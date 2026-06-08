"""BM25 Keyword Search."""

from __future__ import annotations

import re
from typing import Any

try:
    from rank_bm25 import BM25Okapi
except ImportError:
    BM25Okapi = None  # type: ignore[assignment,misc]


class BM25Search:
    """BM25-based keyword search over documents."""

    def __init__(self):
        self._ids: list[str] = []
        self._documents: list[str] = []
        self._metadatas: list[dict[str, Any]] = []
        self._bm25 = None

    @property
    def count(self) -> int:
        return len(self._ids)

    def index(self, ids: list[str], documents: list[str], metadatas: list[dict[str, Any]] | None = None) -> None:
        self._ids = ids
        self._documents = documents
        self._metadatas = metadatas or [{} for _ in ids]
        self._bm25 = None
        if documents and BM25Okapi is not None:
            tokenized = [self._tokenize(doc) for doc in documents]
            self._bm25 = BM25Okapi(tokenized)

    def search(self, query: str, n_results: int = 8) -> list[dict[str, Any]]:
        if not self._bm25 or not self._ids:
            return []
        scores = self._bm25.get_scores(self._tokenize(query))
        ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
        results = []
        for idx, score in ranked[:n_results]:
            if score > 0:
                results.append({
                    "id": self._ids[idx],
                    "document": self._documents[idx],
                    "metadata": self._metadatas[idx],
                    "score": float(score),
                })
        return results

    def list_all(self, page: int = 1, page_size: int = 20, severity: str | None = None, keyword: str | None = None) -> dict[str, Any]:
        """List all indexed documents with optional filtering and pagination."""
        page = max(1, page)
        page_size = max(1, min(100, page_size))
        items = []
        for i in range(len(self._ids)):
            meta = self._metadatas[i] if i < len(self._metadatas) else {}
            item = {
                "id": self._ids[i],
                "document": self._documents[i],
                "description": self._documents[i],
                **meta,
            }
            if severity and meta.get("severity", "").upper() != severity.upper():
                continue
            if keyword:
                kw = keyword.lower()
                if kw not in self._documents[i].lower() and kw not in self._ids[i].lower():
                    continue
            items.append(item)

        total = len(items)
        start = (page - 1) * page_size
        end = start + page_size
        return {
            "items": items[start:end],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def get_by_id(self, doc_id: str) -> dict[str, Any] | None:
        """Get a single document by its ID."""
        for i, id_ in enumerate(self._ids):
            if id_ == doc_id:
                meta = self._metadatas[i] if i < len(self._metadatas) else {}
                return {"id": id_, "document": self._documents[i], "description": self._documents[i], **meta}
        return None

    def get_all(self) -> tuple[list[str], list[str], list[dict[str, Any]]]:
        """Return all indexed data as (ids, documents, metadatas)."""
        return list(self._ids), list(self._documents), list(self._metadatas)

    def stats(self) -> dict[str, Any]:
        """Return severity distribution and recent items."""
        by_severity: dict[str, int] = {}
        for meta in self._metadatas:
            sev = meta.get("severity", "UNKNOWN").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1

        recent = []
        for i in range(len(self._ids)):
            meta = self._metadatas[i] if i < len(self._metadatas) else {}
            recent.append({
                "id": self._ids[i],
                "severity": meta.get("severity", "UNKNOWN"),
                "cvss_score": meta.get("cvss_score", 0),
                "published": meta.get("published", ""),
            })
        recent.sort(key=lambda x: x.get("published", ""), reverse=True)

        return {
            "total": self.count,
            "by_severity": by_severity,
            "recent": recent[:10],
        }

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        return re.findall(r"[a-z0-9]+", text.lower())


# Module-level singleton instance shared across the app
bm25_instance = BM25Search()
