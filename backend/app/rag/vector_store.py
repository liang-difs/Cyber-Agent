"""ChromaDB Vector Store."""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    import chromadb
except ImportError:
    chromadb = None  # type: ignore[assignment]


class VectorStore:
    """ChromaDB persistent vector store."""

    def __init__(self, persist_dir: str = "/home/liang/.cache/chromadb_public", collection_name: str = "kb_public_all_v1"):
        self.collection_name = collection_name
        self._client = None
        self._collection = None
        try:
            if chromadb is None:
                raise ImportError("chromadb not installed")
            from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
            self._client = chromadb.PersistentClient(path=persist_dir)
            self._collection = self._client.get_or_create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"},
                embedding_function=None,  # Disable auto-embedding; we provide our own
            )
            logger.info("ChromaDB collection '%s' ready (%d docs)", collection_name, self._collection.count())
        except Exception as e:
            logger.error("ChromaDB init failed: %s", e)
            self._client = None
            self._collection = None

    @property
    def is_available(self) -> bool:
        return self._collection is not None

    def add_documents(
        self,
        ids: list[str],
        documents: list[str],
        metadatas: Optional[list[dict[str, Any]]] = None,
        embeddings: Optional[list[list[float]]] = None,
    ) -> None:
        if not self.is_available:
            return
        kwargs: dict[str, Any] = {"ids": ids, "documents": documents}
        if metadatas:
            kwargs["metadatas"] = metadatas
        if embeddings:
            kwargs["embeddings"] = embeddings
        self._collection.add(**kwargs)

    def query(
        self,
        query_text: Optional[str] = None,
        query_embedding: Optional[list[float]] = None,
        n_results: int = 8,
    ) -> list[dict[str, Any]]:
        if not self.is_available:
            return []
        kwargs: dict[str, Any] = {"n_results": n_results}
        if query_embedding:
            kwargs["query_embeddings"] = [query_embedding]
        elif query_text:
            kwargs["query_texts"] = [query_text]
        else:
            return []

        results = self._collection.query(**kwargs)

        docs = []
        for i in range(len(results["ids"][0])):
            docs.append({
                "id": results["ids"][0][i],
                "document": results["documents"][0][i] if results.get("documents") else "",
                "metadata": results["metadatas"][0][i] if results.get("metadatas") else {},
                "distance": results["distances"][0][i] if results.get("distances") else 0,
            })
        return docs

    def count(self) -> int:
        if not self.is_available:
            return 0
        return self._collection.count()

    def fetch(self, where: Optional[dict[str, Any]] = None, limit: Optional[int] = None, offset: int = 0) -> dict[str, Any]:
        """Fetch stored rows with an optional metadata filter."""
        if not self.is_available:
            return {"ids": [], "documents": [], "metadatas": []}

        kwargs: dict[str, Any] = {}
        if where:
            kwargs["where"] = where
        if limit is not None:
            kwargs["limit"] = limit
        if offset:
            kwargs["offset"] = offset
        return self._collection.get(**kwargs)

    def iter_ids(self, page_size: int = 1000):
        """Yield all stored ids in pages."""
        if not self.is_available:
            return

        count = self.count()
        for offset in range(0, count, page_size):
            results = self._collection.get(limit=page_size, offset=offset)
            for doc_id in results.get("ids", []):
                yield doc_id
