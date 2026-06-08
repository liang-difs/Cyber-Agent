"""Structured CVE catalog queries over the public RAG collection."""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from app.rag.stage2_importer import DEFAULT_COLLECTION_NAME
from app.rag.vector_store import VectorStore


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_float(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except Exception:
        return None


def _coerce_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _unwrap_rows(values: Any) -> list[Any]:
    if not isinstance(values, list):
        return []
    if values and isinstance(values[0], list):
        return list(values[0])
    return list(values)


def _flatten_collection_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    ids = _unwrap_rows(raw.get("ids", []))
    documents = _unwrap_rows(raw.get("documents", []))
    metadatas = _unwrap_rows(raw.get("metadatas", []))

    rows: list[dict[str, Any]] = []
    for index, doc_id in enumerate(ids):
        metadata = metadatas[index] if index < len(metadatas) and isinstance(metadatas[index], dict) else {}
        document = documents[index] if index < len(documents) and isinstance(documents[index], str) else ""
        row = {"id": doc_id, "document": document}
        row.update(metadata)
        rows.append(row)
    return rows


def parse_catalog_filters(
    query: Optional[str] = None,
    year: Optional[int] = None,
    cvss_score: Optional[float] = None,
    kev_only: bool = False,
    severity: Optional[str] = None,
    keyword: Optional[str] = None,
) -> dict[str, Any]:
    text = _safe_text(query)
    lowered = text.lower()

    if year is None:
        year_match = re.search(r"(19|20)\d{2}", text)
        if year_match:
            year = int(year_match.group(0))

    if cvss_score is None:
        score_match = re.search(r"cvss(?:\s*评分|\s*score)?\s*[:=]?\s*([0-9]+(?:\.[0-9]+)?)", lowered, re.IGNORECASE)
        if score_match:
            cvss_score = float(score_match.group(1))

    if not kev_only and ("kev" in lowered or "known exploited vulnerabilities" in lowered):
        kev_only = True

    if severity is not None:
        severity = severity.strip().upper() or None

    return {
        "query": text,
        "year": year,
        "cvss_score": cvss_score,
        "kev_only": kev_only,
        "severity": severity,
        "keyword": _safe_text(keyword) or None,
    }


def _load_source_rows(store: VectorStore, source_type: str) -> list[dict[str, Any]]:
    """Load all rows of a given source_type with pagination to avoid SQL limits."""
    rows: list[dict[str, Any]] = []
    page_size = 500
    offset = 0
    while True:
        raw = store.fetch(where={"source_type": source_type}, limit=page_size, offset=offset)
        page_rows = _flatten_collection_rows(raw)
        if not page_rows:
            break
        rows.extend(page_rows)
        if len(page_rows) < page_size:
            break
        offset += page_size
    return rows


def _extract_year(published: str) -> Optional[int]:
    if not published:
        return None
    match = re.match(r"^(19|20)\d{2}", published)
    if not match:
        return None
    return int(published[:4])


def _build_key_dates(*, published: str = "", kev_date: str = "", first_seen: str = "") -> dict[str, str]:
    key_dates: dict[str, str] = {}
    if published:
        key_dates["published"] = published
    if kev_date:
        key_dates["kev_date"] = kev_date
    if first_seen:
        key_dates["first_seen"] = first_seen
    return key_dates


def _build_evidence_entry(
    *,
    cve_id: str,
    source_type: str,
    source_path: str,
    doc_id: str,
    key_dates: dict[str, str],
    note: str = "",
) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "source_type": source_type,
        "source_path": source_path,
        "doc_id": doc_id,
        "key_dates": key_dates,
        "note": note,
    }


def _dedupe_evidence(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for entry in entries:
        key = (
            _safe_text(entry.get("cve_id")),
            _safe_text(entry.get("source_type")),
            _safe_text(entry.get("source_path")),
            _safe_text(entry.get("doc_id")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


def build_catalog_stats(items: list[dict[str, Any]], total_cve_docs: int, total_kev_docs: int) -> dict[str, Any]:
    """Build aggregate stats for the current filtered CVE catalog view."""
    by_year: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    kev_by_year: dict[str, int] = {}
    kev_by_severity: dict[str, int] = {}

    kev_count = 0
    for item in items:
        year = _extract_year(_safe_text(item.get("published")))
        year_key = str(year) if year is not None else "UNKNOWN"
        severity_key = _safe_text(item.get("severity")).upper() or "UNKNOWN"

        by_year[year_key] = by_year.get(year_key, 0) + 1
        by_severity[severity_key] = by_severity.get(severity_key, 0) + 1

        if item.get("is_kev"):
            kev_count += 1
            kev_by_year[year_key] = kev_by_year.get(year_key, 0) + 1
            kev_by_severity[severity_key] = kev_by_severity.get(severity_key, 0) + 1

    kev_hit_rate = round(kev_count / len(items), 4) if items else 0.0

    return {
        "matched_count": len(items),
        "kev_count": kev_count,
        "kev_hit_rate": kev_hit_rate,
        "by_year": dict(sorted(by_year.items(), key=lambda pair: pair[0], reverse=True)),
        "by_severity": dict(sorted(by_severity.items(), key=lambda pair: pair[0])),
        "kev_by_year": dict(sorted(kev_by_year.items(), key=lambda pair: pair[0], reverse=True)),
        "kev_by_severity": dict(sorted(kev_by_severity.items(), key=lambda pair: pair[0])),
        "coverage": {
            "total_cve_docs": total_cve_docs,
            "total_kev_docs": total_kev_docs,
            "kev_doc_coverage": round(total_kev_docs / total_cve_docs, 4) if total_cve_docs else 0.0,
        },
    }


def _item_evidence_from_rows(cve_row: dict[str, Any], kev_row: dict[str, Any] | None) -> list[dict[str, Any]]:
    cve_id = _safe_text(cve_row.get("cve_id") or cve_row.get("id"))
    cve_doc_id = _safe_text(cve_row.get("id") or cve_id)
    cve_source_path = _safe_text(cve_row.get("source_path")) or "corpus/nvd_full"
    cve_key_dates = _build_key_dates(
        published=_safe_text(cve_row.get("published")),
        first_seen=_safe_text(cve_row.get("first_seen")),
    )

    evidence = [
        _build_evidence_entry(
            cve_id=cve_id,
            source_type=_safe_text(cve_row.get("source_type")) or "cve",
            source_path=cve_source_path,
            doc_id=cve_doc_id,
            key_dates=cve_key_dates,
            note=_safe_text(cve_row.get("title")) or "NVD 记录",
        )
    ]

    if kev_row:
        kev_doc_id = _safe_text(kev_row.get("id") or f"kev-{cve_id}")
        kev_source_path = _safe_text(kev_row.get("source_path")) or "attack/intel_raw/kev.csv"
        kev_key_dates = _build_key_dates(
            kev_date=_safe_text(kev_row.get("kev_date")),
            first_seen=_safe_text(kev_row.get("first_seen")),
        )
        evidence.append(
            _build_evidence_entry(
                cve_id=cve_id,
                source_type=_safe_text(kev_row.get("source_type")) or "kev",
                source_path=kev_source_path,
                doc_id=kev_doc_id,
                key_dates=kev_key_dates,
                note=_safe_text(kev_row.get("vendor")) or "CISA KEV 记录",
            )
        )

    return evidence


def query_cve_catalog(
    query: Optional[str] = None,
    year: Optional[int] = None,
    cvss_score: Optional[float] = None,
    kev_only: bool = False,
    severity: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = 20,
    collection_name: str = DEFAULT_COLLECTION_NAME,
    store: Optional[VectorStore] = None,
) -> dict[str, Any]:
    """Query the public CVE + KEV catalog with structured filters."""
    filters = parse_catalog_filters(
        query=query,
        year=year,
        cvss_score=cvss_score,
        kev_only=kev_only,
        severity=severity,
        keyword=keyword,
    )

    active_store = store or VectorStore(collection_name=collection_name)
    if not active_store.is_available:
        raise RuntimeError(f"Vector store unavailable for collection {collection_name}")

    cve_rows = _load_source_rows(active_store, "cve")
    kev_rows = _load_source_rows(active_store, "kev")
    kev_map = {_safe_text(row.get("cve_id")): row for row in kev_rows if _safe_text(row.get("cve_id"))}

    items: list[dict[str, Any]] = []
    evidence_entries: list[dict[str, Any]] = []
    for row in cve_rows:
        cve_id = _safe_text(row.get("cve_id") or row.get("id"))
        if not cve_id:
            continue

        published = _safe_text(row.get("published"))
        if filters["year"] is not None and not published.startswith(str(filters["year"])):
            continue

        score = _safe_float(row.get("cvss_score"))
        if filters["cvss_score"] is not None and score is not None and abs(score - float(filters["cvss_score"])) > 1e-6:
            continue
        if filters["cvss_score"] is not None and score is None:
            continue

        sev = _safe_text(row.get("severity"))
        if filters["severity"] is not None and sev.upper() != filters["severity"]:
            continue

        if filters["keyword"]:
            haystack = " ".join([
                cve_id,
                _safe_text(row.get("title")),
                _safe_text(row.get("document")),
            ]).lower()
            if filters["keyword"].lower() not in haystack:
                continue

        kev_row = kev_map.get(cve_id)
        is_kev = kev_row is not None
        if filters["kev_only"] and not is_kev:
            continue

        row_evidence = _item_evidence_from_rows(row, kev_row)
        evidence_entries.extend(row_evidence)

        items.append({
            "cve_id": cve_id,
            "doc_id": _safe_text(row.get("id") or cve_id),
            "title": _safe_text(row.get("title")) or cve_id,
            "published": published,
            "cvss_score": score if score is not None else 0.0,
            "severity": sev or "UNKNOWN",
            "is_kev": is_kev,
            "kev_date": _safe_text(kev_row.get("kev_date")) if kev_row else "",
            "vendor": _safe_text(kev_row.get("vendor")) if kev_row else "",
            "product": _safe_text(kev_row.get("product")) if kev_row else "",
            "source_type": "cve",
            "source_path": _safe_text(row.get("source_path")) or "corpus/nvd_full",
            "first_seen": _safe_text(row.get("first_seen")),
            "evidence": row_evidence,
        })

    items.sort(key=lambda item: (item.get("published", ""), item.get("cve_id", "")), reverse=True)
    selected_items = items[: max(1, limit)]
    stats = build_catalog_stats(items, len(cve_rows), len(kev_rows))
    returned_kev_count = sum(1 for item in selected_items if item.get("is_kev"))
    selected_evidence = _dedupe_evidence([entry for item in selected_items for entry in _coerce_dict(item).get("evidence", []) if isinstance(entry, dict)])

    filter_bits: list[str] = []
    if filters["year"] is not None:
        filter_bits.append(f"year={filters['year']}")
    if filters["cvss_score"] is not None:
        filter_bits.append(f"cvss={filters['cvss_score']}")
    if filters["kev_only"]:
        filter_bits.append("kev_only=True")
    if filters["severity"] is not None:
        filter_bits.append(f"severity={filters['severity']}")
    if filters["keyword"]:
        filter_bits.append(f"keyword={filters['keyword']}")

    summary_text = (
        f"筛选条件: {', '.join(filter_bits) if filter_bits else 'none'}；"
        f"CVE 总数 {len(cve_rows)}，KEV 总数 {len(kev_rows)}，命中 {len(items)} 条。"
    )
    if filters["kev_only"] or stats["kev_count"]:
        summary_text += f" 其中 KEV 命中 {stats['kev_count']} 条。"

    return {
        "query": filters["query"],
        "filters": filters,
        "total_cve_docs": len(cve_rows),
        "total_kev_docs": len(kev_rows),
        "matched_count": len(items),
        "kev_count": stats["kev_count"],
        "stats": stats,
        "evidence": selected_evidence,
        "returned_count": len(selected_items),
        "returned_kev_count": returned_kev_count,
        "summary_text": summary_text,
        "items": selected_items,
    }