"""RAG Pipeline — hybrid retrieval with RRF fusion."""

from __future__ import annotations

import logging
from typing import Any, Optional

from app.rag.bm25_search import BM25Search, bm25_instance
from app.rag.embedder import EmbeddingService
from app.rag.local_embedding import embed_texts
from app.rag.vector_store import VectorStore

logger = logging.getLogger(__name__)


class RAGPipeline:
    """Hybrid RAG: vector search + BM25 + RRF fusion."""

    def __init__(
        self,
        embedder: Optional[EmbeddingService] = None,
        vector_store: Optional[VectorStore] = None,
        bm25: Optional[BM25Search] = None,
    ):
        self.embedder = embedder or EmbeddingService()
        self.vector_store = vector_store or VectorStore()
        self.bm25 = bm25 or bm25_instance

    def retrieve(self, query: str, top_k: int = 4) -> list[dict[str, Any]]:
        vector_results: list[dict[str, Any]] = []
        bm25_results: list[dict[str, Any]] = []

        if self.vector_store.is_available:
            embedding = self.embedder.encode([query])
            if not embedding:
                embedding = embed_texts([query])
            if embedding:
                vector_results = self.vector_store.query(
                    query_embedding=embedding[0],
                    n_results=8,
                )

        if self.bm25.count > 0:
            bm25_results = self.bm25.search(query, n_results=8)

        if not vector_results and not bm25_results:
            logger.warning("No RAG results — both vector and BM25 empty")
            return []

        fused = self._rrf_fusion(vector_results, bm25_results, k=60)
        return fused[:top_k]

    @staticmethod
    def _rrf_fusion(
        vector_results: list[dict[str, Any]],
        bm25_results: list[dict[str, Any]],
        k: int = 60,
    ) -> list[dict[str, Any]]:
        scores: dict[str, float] = {}
        doc_map: dict[str, dict[str, Any]] = {}

        for rank, doc in enumerate(vector_results):
            doc_id = doc["id"]
            scores[doc_id] = scores.get(doc_id, 0) + 1.0 / (k + rank + 1)
            doc_map[doc_id] = doc

        for rank, doc in enumerate(bm25_results):
            doc_id = doc["id"]
            scores[doc_id] = scores.get(doc_id, 0) + 1.0 / (k + rank + 1)
            if doc_id not in doc_map:
                doc_map[doc_id] = {"id": doc_id, "document": doc.get("document", ""), "metadata": {}}

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        results = []
        for doc_id, score in ranked:
            entry = doc_map[doc_id].copy()
            entry["rrf_score"] = score
            results.append(entry)

        return results
