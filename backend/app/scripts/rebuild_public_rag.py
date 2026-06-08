"""Rebuild the public RAG collection from local corpus snapshots."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from app.rag.importer import load_corpus_cves
from app.rag.kev_importer import import_kev_public
from app.rag.local_embedding import embed_texts
from app.rag.stage2_importer import (
    DEFAULT_COLLECTION_NAME,
    DEFAULT_STAGE2_ATTACK_RULE_SOURCE_TYPES,
    DEFAULT_STAGE2_FINGERPRINT_SOURCE_TYPES,
    DEFAULT_STAGE2_THREAT_INTEL_SOURCE_TYPES,
    import_stage2_public,
)
from app.rag.vector_store import VectorStore


STAGE2_PROFILES: dict[str, tuple[str, ...]] = {
    "attack_rules": DEFAULT_STAGE2_ATTACK_RULE_SOURCE_TYPES,
    "threat_intel": DEFAULT_STAGE2_THREAT_INTEL_SOURCE_TYPES,
    "fingerprints": DEFAULT_STAGE2_FINGERPRINT_SOURCE_TYPES,
    "all_public": DEFAULT_STAGE2_ATTACK_RULE_SOURCE_TYPES + DEFAULT_STAGE2_THREAT_INTEL_SOURCE_TYPES + DEFAULT_STAGE2_FINGERPRINT_SOURCE_TYPES,
}


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Rebuild the public RAG collection.")
    parser.add_argument("--collection", default=DEFAULT_COLLECTION_NAME)
    parser.add_argument("--skip-cves", action="store_true")
    parser.add_argument("--skip-kev", action="store_true")
    parser.add_argument("--skip-stage2", action="store_true")
    parser.add_argument("--stage2-profile", choices=sorted(STAGE2_PROFILES), default="all_public")
    parser.add_argument("--cve-limit", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=300)
    return parser.parse_args(argv)


def _index_cves(store: VectorStore, limit: int | None = None, batch_size: int = 300) -> dict[str, int]:
    cves = load_corpus_cves(max_items=limit or 200000)
    unique: dict[str, dict[str, object]] = {}
    for cve in cves:
        unique[str(cve.get("cve_id", "")).strip()] = cve

    existing_ids: set[str] = set()
    count = store.count()
    for offset in range(0, count, 1000):
        results = store._collection.get(limit=1000, offset=offset)  # noqa: SLF001
        existing_ids.update(results.get("ids", []))

    stats = {"seen": len(cves), "selected": len(unique), "indexed": 0}
    batch: list[dict[str, object]] = []
    seen_in_run: set[str] = set()

    def flush() -> None:
        if not batch:
            return
        ids = [str(item["cve_id"]) for item in batch]
        documents = [
            "\n\n".join(
                part
                for part in [
                    str(item["cve_id"]),
                    f"Severity: {item.get('severity', 'UNKNOWN')}",
                    f"Score: {item.get('cvss_score', 0)}",
                    str(item.get("description", "")),
                    f"Published: {item.get('published', '')}",
                ]
                if part
            )
            for item in batch
        ]
        metadatas = [
            {
                "doc_id": str(item["cve_id"]),
                "title": str(item["cve_id"]),
                "category": "cve",
                "source_type": "cve",
                "source_path": "corpus/nvd_full",
                "embedding_version": "local-hash-v1",
                "cve_id": str(item["cve_id"]),
                "cvss_score": item.get("cvss_score", 0),
                "severity": item.get("severity", "UNKNOWN"),
                "published": item.get("published", ""),
            }
            for item in batch
        ]
        embeddings = embed_texts(documents)
        store.add_documents(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)
        stats["indexed"] += len(ids)
        batch.clear()

    for cve_id, item in unique.items():
        if not cve_id:
            continue
        if cve_id in existing_ids or cve_id in seen_in_run:
            continue
        seen_in_run.add(cve_id)
        batch.append(item)
        if len(batch) >= batch_size:
            flush()

    flush()
    return stats


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    store = VectorStore(collection_name=args.collection)
    if not store.is_available:
        raise RuntimeError(f"Vector store unavailable for collection {args.collection}")

    print(f"Rebuilding public RAG into collection={args.collection}")
    if not args.skip_cves:
        cve_stats = _index_cves(store, limit=args.cve_limit, batch_size=args.batch_size)
        print(
            "CVE import complete: "
            f"seen={cve_stats['seen']} selected={cve_stats['selected']} indexed={cve_stats['indexed']}"
        )

    if not args.skip_kev:
        kev_stats = import_kev_public(
            collection_name=args.collection,
            batch_size=args.batch_size,
        )
        print(
            "KEV import complete: "
            f"seen={kev_stats['seen']} selected={kev_stats['selected']} indexed={kev_stats['indexed']}"
        )

    if not args.skip_stage2:
        stage2_stats = import_stage2_public(
            collection_name=args.collection,
            source_types=STAGE2_PROFILES[args.stage2_profile],
            path=Path("corpus/processed/normalized_docs.jsonl"),
            batch_size=args.batch_size,
        )
        print(
            "Stage 2 import complete: "
            f"seen={stage2_stats['seen']} selected={stage2_stats['selected']} indexed={stage2_stats['indexed']}"
        )

    print(f"Public RAG rebuild complete: collection={args.collection} count={store.count()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
  