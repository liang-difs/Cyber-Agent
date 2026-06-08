"""CVE Data Importer — fetches from NVD API and indexes into BM25 + ChromaDB."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.rag.bm25_search import BM25Search
from app.rag.vector_store import VectorStore

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CORPUS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "corpus" / "nvd_full"


async def fetch_recent_cves(
    api_key: str = "",
    results_per_page: int = 100,
    max_results: int = 1000,
) -> list[dict[str, Any]]:
    """Fetch recent CVEs from NVD API."""
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    all_cves = []
    start_index = 0

    async with httpx.AsyncClient(timeout=30) as client:
        while start_index < max_results:
            params = {
                "resultsPerPage": min(results_per_page, max_results - start_index),
                "startIndex": start_index,
            }
            try:
                resp = await client.get(NVD_API_URL, params=params, headers=headers)
                if resp.status_code == 404 and api_key:
                    # Invalid API key — retry without
                    resp = await client.get(NVD_API_URL, params=params)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.error("NVD API fetch failed at index %d: %s", start_index, e)
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for v in vulns:
                cve = v.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc_en = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    "",
                )

                # CVSS score
                cvss_score = 0.0
                severity = "UNKNOWN"
                metrics = cve.get("metrics", {})
                for vkey in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if vkey in metrics and metrics[vkey]:
                        cvss_data = metrics[vkey][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        break

                all_cves.append({
                    "cve_id": cve_id,
                    "description": desc_en,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "published": cve.get("published", ""),
                })

            total = data.get("totalResults", 0)
            start_index += len(vulns)
            if start_index >= total:
                break

            # Rate limit: 5 requests per 30 seconds without key
            await asyncio.sleep(6 if not api_key else 1)

    logger.info("Fetched %d CVEs from NVD", len(all_cves))
    return all_cves


def index_cves_to_bm25(cves: list[dict[str, Any]], bm25: BM25Search) -> None:
    """Index CVEs into BM25 search."""
    ids = [c["cve_id"] for c in cves]
    documents = [
        f"{c['cve_id']} {c['description']} severity:{c['severity']} score:{c['cvss_score']}"
        for c in cves
    ]
    metadatas = [
        {
            "cve_id": c["cve_id"],
            "cvss_score": c["cvss_score"],
            "severity": c["severity"],
            "published": c.get("published", ""),
        }
        for c in cves
    ]
    bm25.index(ids, documents, metadatas)
    logger.info("Indexed %d CVEs into BM25", len(cves))


def index_cves_to_chromadb(cves: list[dict[str, Any]], store: VectorStore) -> None:
    """Index CVEs into ChromaDB (without embeddings — text only)."""
    if not store.is_available:
        logger.warning("ChromaDB not available, skipping vector indexing")
        return

    ids = [c["cve_id"] for c in cves]
    documents = [c["description"] for c in cves]
    metadatas = [
        {"cve_id": c["cve_id"], "cvss_score": c["cvss_score"], "severity": c["severity"]}
        for c in cves
    ]

    # ChromaDB can handle up to ~5000 documents per batch
    batch_size = 500
    for i in range(0, len(ids), batch_size):
        store.add_documents(
            ids=ids[i : i + batch_size],
            documents=documents[i : i + batch_size],
            metadatas=metadatas[i : i + batch_size],
        )

    logger.info("Indexed %d CVEs into ChromaDB", len(cves))


async def fetch_cves_since(
    api_key: str = "",
    since_date: str = "",
    max_results: int = 1000,
) -> list[dict[str, Any]]:
    """Fetch CVEs modified since a given date from NVD API.

    Args:
        api_key: NVD API key (optional, higher rate limits).
        since_date: ISO date string like "2026-05-01T00:00:00.000".
        max_results: Maximum number of results to fetch.
    """
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    params: dict[str, Any] = {
        "resultsPerPage": min(100, max_results),
        "startIndex": 0,
    }
    if since_date:
        params["lastModStartDate"] = since_date
        params["lastModEndDate"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    all_cves: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=30) as client:
        while len(all_cves) < max_results:
            try:
                resp = await client.get(NVD_API_URL, params=params, headers=headers)
                if resp.status_code == 404 and api_key:
                    resp = await client.get(NVD_API_URL, params=params)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.error("NVD API fetch failed: %s", e)
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for v in vulns:
                cve = v.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc_en = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    "",
                )
                cvss_score = 0.0
                severity = "UNKNOWN"
                metrics = cve.get("metrics", {})
                for vkey in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if vkey in metrics and metrics[vkey]:
                        cvss_data = metrics[vkey][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        break

                all_cves.append({
                    "cve_id": cve_id,
                    "description": desc_en,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "published": cve.get("published", ""),
                })

            total = data.get("totalResults", 0)
            params["startIndex"] += len(vulns)
            if params["startIndex"] >= total:
                break

            await asyncio.sleep(6 if not api_key else 1)

    logger.info("Fetched %d CVEs since %s", len(all_cves), since_date or "beginning")
    return all_cves


async def sync_cves(bm25: BM25Search, api_key: str = "", since_hours: int = 24) -> int:
    """Incremental CVE sync: fetch recent changes and merge into BM25."""
    from datetime import datetime, timedelta, timezone

    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000")

    new_cves = await fetch_cves_since(api_key=api_key, since_date=since_str)
    if not new_cves:
        logger.info("No new CVEs to sync")
        return 0

    # Get existing data
    existing_ids, existing_docs, existing_metas = bm25.get_all()
    existing_map = {cid: i for i, cid in enumerate(existing_ids)}

    # Merge: new CVEs overwrite existing ones with same ID
    merged_ids = list(existing_ids)
    merged_docs = list(existing_docs)
    merged_metas = list(existing_metas)

    added = 0
    updated = 0
    for cve in new_cves:
        doc_text = f"{cve['cve_id']} {cve['description']} severity:{cve['severity']} score:{cve['cvss_score']}"
        meta = {
            "cve_id": cve["cve_id"],
            "cvss_score": cve["cvss_score"],
            "severity": cve["severity"],
            "published": cve.get("published", ""),
        }
        if cve["cve_id"] in existing_map:
            idx = existing_map[cve["cve_id"]]
            merged_docs[idx] = doc_text
            merged_metas[idx] = meta
            updated += 1
        else:
            merged_ids.append(cve["cve_id"])
            merged_docs.append(doc_text)
            merged_metas.append(meta)
            added += 1

    if added or updated:
        bm25.index(merged_ids, merged_docs, merged_metas)
        logger.info("CVE sync: %d added, %d updated, %d total", added, updated, len(merged_ids))

        # Persist to corpus JSONL
        try:
            corpus_file = CORPUS_DIR / "nvd_sync.jsonl"
            with open(corpus_file, "a", encoding="utf-8") as f:
                for cve in new_cves:
                    f.write(json.dumps(cve, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning("Failed to persist CVE sync data: %s", e)

    return added + updated


async def on_demand_cve_lookup(cve_id: str, bm25: BM25Search) -> dict[str, Any] | None:
    """Look up a CVE: check BM25 first, then fetch from NVD if missing."""
    # Check BM25
    existing = bm25.get_by_id(cve_id)
    if existing:
        return existing

    # Fetch from NVD API
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(NVD_API_URL, params={"cveId": cve_id})
            resp.raise_for_status()
            data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve = vulns[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        desc_en = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "",
        )
        cvss_score = 0.0
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})
        for vkey in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if vkey in metrics and metrics[vkey]:
                cvss_data = metrics[vkey][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        result = {
            "cve_id": cve_id,
            "description": desc_en,
            "cvss_score": cvss_score,
            "severity": severity,
            "published": cve.get("published", ""),
        }

        # Append to BM25 index
        existing_ids, existing_docs, existing_metas = bm25.get_all()
        existing_ids.append(cve_id)
        existing_docs.append(f"{cve_id} {desc_en} severity:{severity} score:{cvss_score}")
        existing_metas.append({
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "published": cve.get("published", ""),
        })
        bm25.index(existing_ids, existing_docs, existing_metas)
        logger.info("On-demand CVE lookup: %s fetched and indexed", cve_id)

        return result
    except Exception as e:
        logger.error("On-demand CVE lookup failed for %s: %s", cve_id, e)
        return None


def load_corpus_cves(max_items: int = 5000) -> list[dict[str, Any]]:
    """Load CVEs from local corpus files (corpus/nvd_full/)."""
    all_cves: list[dict[str, Any]] = []
    if not CORPUS_DIR.is_dir():
        logger.warning("Corpus directory not found: %s", CORPUS_DIR)
        return all_cves

    for jsonl_file in sorted(CORPUS_DIR.glob("*.jsonl")):
        logger.info("Loading corpus file: %s", jsonl_file.name)
        try:
            with open(jsonl_file, encoding="utf-8") as f:
                for line in f:
                    if len(all_cves) >= max_items:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    all_cves.append({
                        "cve_id": entry.get("cve_id", ""),
                        "description": entry.get("description", ""),
                        "cvss_score": entry.get("cvss_base", entry.get("cvss_score", 0)),
                        "severity": entry.get("severity", "UNKNOWN").upper(),
                        "published": entry.get("published", ""),
                    })
        except Exception as e:
            logger.error("Failed to load %s: %s", jsonl_file.name, e)
        if len(all_cves) >= max_items:
            break

    logger.info("Loaded %d CVEs from corpus", len(all_cves))
    return all_cves


async def import_cves(
    api_key: str = "",
    max_results: int = 1000,
    bm25: BM25Search | None = None,
    store: VectorStore | None = None,
) -> int:
    """Import CVEs from NVD into BM25 and ChromaDB."""
    cves = await fetch_recent_cves(api_key=api_key, max_results=max_results)
    if not cves:
        logger.warning("No CVEs fetched")
        return 0

    if bm25:
        index_cves_to_bm25(cves, bm25)

    if store:
        index_cves_to_chromadb(cves, store)

    return len(cves)
