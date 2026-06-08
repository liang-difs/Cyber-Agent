"""Importer for CISA Known Exploited Vulnerabilities (KEV) data."""

from __future__ import annotations

import csv
import hashlib
import logging
from pathlib import Path
from typing import Any, Iterable, Iterator

from app.rag.local_embedding import embed_texts
from app.rag.vector_store import VectorStore

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_KEV_CSV = PROJECT_ROOT / "corpus" / "attack" / "intel_raw" / "kev.csv"
EMBEDDING_VERSION = "local-hash-v1"


def iter_kev_rows(path: Path = DEFAULT_KEV_CSV) -> Iterator[dict[str, str]]:
    """Yield KEV rows from the raw CISA CSV export."""
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield row


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _doc_id(row: dict[str, str]) -> str:
    cve_id = _clean(row.get("cveID"))
    if cve_id:
        return f"kev-{cve_id}"

    seed = "|".join(
        _clean(row.get(field))
        for field in ("vendorProject", "product", "vulnerabilityName", "dateAdded")
    )
    return "kev-" + hashlib.sha1(seed.encode("utf-8")).hexdigest()


def build_kev_index_payload(rows: Iterable[dict[str, str]]) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    """Convert KEV rows into ids, documents and Chroma metadata."""
    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for row in rows:
        doc_id = _doc_id(row)
        if not doc_id or doc_id in seen_ids:
            continue

        cve_id = _clean(row.get("cveID"))
        vendor = _clean(row.get("vendorProject"))
        product = _clean(row.get("product"))
        title = _clean(row.get("vulnerabilityName")) or f"KEV-{cve_id or doc_id}"
        kev_date = _clean(row.get("dateAdded"))
        due_date = _clean(row.get("dueDate"))
        required_action = _clean(row.get("requiredAction"))
        description = _clean(row.get("shortDescription"))
        notes = _clean(row.get("notes"))
        ransomware = _clean(row.get("knownRansomwareCampaignUse"))
        cwes = _clean(row.get("cwes"))

        document = "\n".join(
            part
            for part in [
                f"KEV: {cve_id}",
                f"Vendor: {vendor}",
                f"Product: {product}",
                f"Title: {title}",
                f"DateAdded: {kev_date}",
                f"DueDate: {due_date}",
                f"KnownRansomwareCampaignUse: {ransomware}",
                f"RequiredAction: {required_action}",
                f"Description: {description}",
                f"Notes: {notes}",
                f"CWEs: {cwes}",
            ]
            if part and not part.endswith(": ")
        )

        metadata: dict[str, Any] = {
            "doc_id": doc_id,
            "title": title,
            "category": "attack",
            "source_type": "kev",
            "source_path": "attack/intel_raw/kev.csv",
            "tags": "vuln_intel,kev",
            "embedding_version": EMBEDDING_VERSION,
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "kev_date": kev_date,
            "due_date": due_date,
            "required_action": required_action,
            "known_ransomware_campaign_use": ransomware,
            "cwes": cwes,
        }

        seen_ids.add(doc_id)
        ids.append(doc_id)
        documents.append(document)
        metadatas.append(metadata)

    return ids, documents, metadatas


def import_kev_public(
    collection_name: str,
    path: Path = DEFAULT_KEV_CSV,
    dry_run: bool = False,
    batch_size: int = 500,
) -> dict[str, int]:
    """Import KEV entries into the public vector collection."""
    store = VectorStore(collection_name=collection_name)
    if not store.is_available:
        raise RuntimeError(f"Vector store unavailable for collection {collection_name}")

    existing_ids: set[str] = set()
    kev_existing = store._collection.get(where={"source_type": "kev"})  # noqa: SLF001
    existing_ids.update(kev_existing.get("ids", []))
    stats = {"seen": 0, "selected": 0, "skipped_existing": 0, "indexed": 0}
    batch: list[dict[str, str]] = []
    seen_in_run: set[str] = set()

    def flush() -> None:
        if not batch or dry_run:
            batch.clear()
            return
        ids, documents, metadatas = build_kev_index_payload(batch)
        embeddings = embed_texts(documents)
        store.add_documents(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)
        stats["indexed"] += len(ids)
        batch.clear()

    for row in iter_kev_rows(path=path):
        stats["seen"] += 1
        doc_id = _doc_id(row)
        if not doc_id:
            continue
        if doc_id in existing_ids or doc_id in seen_in_run:
            stats["skipped_existing"] += 1
            continue

        seen_in_run.add(doc_id)
        stats["selected"] += 1
        batch.append(row)

        if len(batch) >= batch_size:
            flush()

    flush()
    logger.info(
        "KEV import complete: seen=%d selected=%d indexed=%d skipped_existing=%d",
        stats["seen"],
        stats["selected"],
        stats["indexed"],
        stats["skipped_existing"],
    )
    return stats