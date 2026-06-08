"""Stage 2 corpus importer for ATT&CK and Sigma public knowledge."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from app.rag.local_embedding import embed_texts
from app.rag.vector_store import VectorStore

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_NORMALIZED_DOCS = PROJECT_ROOT / "corpus" / "processed" / "normalized_docs.jsonl"
DEFAULT_STAGE2_ATTACK_RULE_SOURCE_TYPES = ("mitre_attack", "ids_rule")
DEFAULT_STAGE2_THREAT_INTEL_SOURCE_TYPES = (
    "cve_attack_mapping",
    "exploit_status",
    "vendor_advisory",
    "vuln_decision",
    "vuln_facts",
    "json_record",
)
DEFAULT_STAGE2_FINGERPRINT_SOURCE_TYPES = ("ja3",)
DEFAULT_STAGE2_SOURCE_TYPES = DEFAULT_STAGE2_ATTACK_RULE_SOURCE_TYPES
DEFAULT_COLLECTION_NAME = "kb_public_all_v1"
EMBEDDING_VERSION = "local-hash-v1"


def iter_normalized_docs(
    path: Path = DEFAULT_NORMALIZED_DOCS,
    source_types: Sequence[str] | None = None,
    categories: Sequence[str] | None = None,
    limit: int | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield normalized docs from the processed corpus snapshot."""
    source_filter = set(source_types) if source_types else None
    category_filter = set(categories) if categories else None
    emitted = 0

    with open(path, encoding="utf-8") as handle:
        for raw_line in handle:
            if limit is not None and emitted >= limit:
                break
            line = raw_line.strip()
            if not line:
                continue
            record = json.loads(line)
            if source_filter and record.get("source_type") not in source_filter:
                continue
            if category_filter and record.get("category") not in category_filter:
                continue
            emitted += 1
            yield record


def build_index_payload(records: Iterable[dict[str, Any]]) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    """Convert normalized records into ids, documents and Chroma metadata."""
    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for record in records:
        doc_id = str(record.get("doc_id", "")).strip()
        if not doc_id or doc_id in seen_ids:
            continue

        title = str(record.get("title", "")).strip()
        content = str(record.get("content", "")).strip()
        document = "\n\n".join(part for part in [title, content] if part)
        metadata = _build_metadata(record)

        seen_ids.add(doc_id)
        ids.append(doc_id)
        documents.append(document)
        metadatas.append(metadata)

    return ids, documents, metadatas


def _build_metadata(record: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "doc_id": record.get("doc_id", ""),
        "title": record.get("title", ""),
        "category": record.get("category", ""),
        "source_type": record.get("source_type", ""),
        "source_path": record.get("source_path", ""),
        "tags": ",".join(str(tag) for tag in record.get("tags", [])[:10]) if record.get("tags") else "",
        "embedding_version": EMBEDDING_VERSION,
    }

    extra = record.get("extra", {})
    if isinstance(extra, dict):
        for key, value in extra.items():
            if value is None:
                continue
            if isinstance(value, (str, int, float, bool)):
                metadata[key] = value

    return metadata


def _fetch_existing_ids(store: VectorStore, page_size: int = 1000) -> set[str]:
    if not store.is_available:
        return set()

    existing_ids: set[str] = set()
    count = store.count()
    for offset in range(0, count, page_size):
        results = store._collection.get(limit=page_size, offset=offset)  # noqa: SLF001
        existing_ids.update(results.get("ids", []))
    return existing_ids


def import_stage2_public(
    collection_name: str = DEFAULT_COLLECTION_NAME,
    source_types: Sequence[str] = DEFAULT_STAGE2_SOURCE_TYPES,
    categories: Sequence[str] | None = None,
    path: Path = DEFAULT_NORMALIZED_DOCS,
    limit: int | None = None,
    dry_run: bool = False,
    batch_size: int = 500,
) -> dict[str, int]:
    """Import Stage 2 public docs into the shared vector collection."""
    store = VectorStore(collection_name=collection_name)
    if not store.is_available:
        raise RuntimeError(f"Vector store unavailable for collection {collection_name}")

    existing_ids = _fetch_existing_ids(store)
    stats = {
        "seen": 0,
        "selected": 0,
        "skipped_existing": 0,
        "indexed": 0,
    }
    batch: list[dict[str, Any]] = []
    seen_in_run: set[str] = set()

    def flush() -> None:
        if not batch or dry_run:
            batch.clear()
            return
        ids, documents, metadatas = build_index_payload(batch)
        embeddings = embed_texts(documents)
        store.add_documents(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)
        stats["indexed"] += len(ids)
        batch.clear()

    for record in iter_normalized_docs(path=path, source_types=source_types, categories=categories, limit=limit):
        stats["seen"] += 1
        doc_id = str(record.get("doc_id", "")).strip()
        if not doc_id:
            continue
        if doc_id in existing_ids or doc_id in seen_in_run:
            stats["skipped_existing"] += 1
            continue

        seen_in_run.add(doc_id)
        stats["selected"] += 1
        batch.append(record)

        if len(batch) >= batch_size:
            flush()

    flush()
    logger.info(
        "Stage 2 public import complete: seen=%d selected=%d indexed=%d skipped_existing=%d",
        stats["seen"],
        stats["selected"],
        stats["indexed"],
        stats["skipped_existing"],
    )
    return stats
