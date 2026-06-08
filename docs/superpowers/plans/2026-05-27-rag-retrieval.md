# RAG Retrieval Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement RAG retrieval with ChromaDB vector store, BGE-M3 embedding, BM25 keyword search, and RRF fusion for the CyberSec Agent.

**Architecture:** The RAG module provides hybrid retrieval: BGE-M3 embedding for semantic search via ChromaDB, BM25 for keyword search, fused with RRF (k=60). BGE-M3 degradation: when model unavailable, fall back to pure BM25. The RAG tool returns retrieved context — Agent layer handles LLM interpretation.

**Tech Stack:** ChromaDB (vector store), sentence-transformers/BGE-M3 (embedding), rank-bm25 (BM25), RRF fusion

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `backend/app/rag/__init__.py` | Create | Package init |
| `backend/app/rag/embedder.py` | Create | BGE-M3 embedding with degradation |
| `backend/app/rag/vector_store.py` | Create | ChromaDB client |
| `backend/app/rag/bm25_search.py` | Create | BM25 keyword search |
| `backend/app/rag/pipeline.py` | Create | RAG pipeline with RRF |
| `backend/app/rag/importer.py` | Create | CVE data import |
| `backend/app/tools/rag_tool.py` | Create | RAG tool for Agent |
| `backend/app/agent/tool_executor.py` | Modify | Register rag_tool |
| `tests/test_rag.py` | Create | Unit tests |

---

### Task 1: Create Embedding Service with Degradation

**Files:**
- Create: `backend/app/rag/__init__.py`
- Create: `backend/app/rag/embedder.py`
- Test: `tests/test_rag.py`

- [ ] **Step 1: Write tests**

Create `tests/test_rag.py`:

```python
"""Tests for RAG module."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.rag.embedder import EmbeddingService


def test_embedder_init_available():
    """Test embedder when model is available."""
    with patch("sentence_transformers.SentenceTransformer") as mock_st:
        mock_model = MagicMock()
        mock_model.encode.return_value = [[0.1] * 1024]
        mock_st.return_value = mock_model

        service = EmbeddingService(model_name="BAAI/bge-m3")
        assert service.is_available is True


def test_embedder_init_unavailable():
    """Test embedder when model fails to load."""
    with patch("sentence_transformers.SentenceTransformer", side_effect=Exception("Model not found")):
        service = EmbeddingService(model_name="nonexistent-model")
        assert service.is_available is False


def test_embedder_encode():
    """Test encoding text to vectors."""
    with patch("sentence_transformers.SentenceTransformer") as mock_st:
        mock_model = MagicMock()
        mock_model.encode.return_value = [[0.1] * 1024]
        mock_st.return_value = mock_model

        service = EmbeddingService()
        result = service.encode(["test query"])
        assert len(result) == 1
        assert len(result[0]) == 1024


def test_embedder_encode_unavailable():
    """Test encoding when model unavailable."""
    with patch("sentence_transformers.SentenceTransformer", side_effect=Exception("fail")):
        service = EmbeddingService()
        result = service.encode(["test"])
        assert result is None


def test_embedder_encode_batch():
    """Test batch encoding."""
    with patch("sentence_transformers.SentenceTransformer") as mock_st:
        mock_model = MagicMock()
        mock_model.encode.return_value = [[0.1] * 1024, [0.2] * 1024]
        mock_st.return_value = mock_model

        service = EmbeddingService()
        result = service.encode(["query 1", "query 2"])
        assert len(result) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_rag.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Implement**

Create `backend/app/rag/__init__.py`:

```python
"""RAG retrieval module."""
```

Create `backend/app/rag/embedder.py`:

```python
"""BGE-M3 Embedding Service with degradation protection."""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class EmbeddingService:
    """BGE-M3 embedding with graceful degradation."""

    def __init__(self, model_name: str = "BAAI/bge-m3"):
        self._model = None
        self._is_available = False
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(model_name)
            self._is_available = True
            logger.info("Embedding model loaded: %s", model_name)
        except Exception as e:
            logger.warning("Embedding model unavailable: %s — RAG will degrade to BM25", e)

    @property
    def is_available(self) -> bool:
        return self._is_available

    def encode(self, texts: list[str]) -> Optional[list[list[float]]]:
        """Encode texts to vectors. Returns None if model unavailable."""
        if not self._is_available or self._model is None:
            return None
        try:
            embeddings = self._model.encode(texts, normalize_embeddings=True)
            return embeddings.tolist()
        except Exception as e:
            logger.error("Embedding encode failed: %s", e)
            return None
```

- [ ] **Step 4: Run tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_rag.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/rag/ tests/test_rag.py
git commit -m "feat: add RAG embedding service with BGE-M3 degradation"
```

---

### Task 2: Create ChromaDB Vector Store

**Files:**
- Create: `backend/app/rag/vector_store.py`
- Test: `tests/test_rag.py`

- [ ] **Step 1: Write tests**

Add to `tests/test_rag.py`:

```python
from app.rag.vector_store import VectorStore


def test_vector_store_init():
    """Test vector store initialization."""
    with patch("chromadb.PersistentClient") as mock_client:
        mock_collection = MagicMock()
        mock_client.return_value.get_or_create_collection.return_value = mock_collection

        store = VectorStore(persist_dir="/tmp/test_chroma", collection_name="test")
        assert store.collection_name == "test"


def test_vector_store_add_documents():
    """Test adding documents."""
    with patch("chromadb.PersistentClient") as mock_client:
        mock_collection = MagicMock()
        mock_client.return_value.get_or_create_collection.return_value = mock_collection

        store = VectorStore(persist_dir="/tmp/test_chroma")
        store.add_documents(
            ids=["cve-1", "cve-2"],
            documents=["desc 1", "desc 2"],
            metadatas=[{"cve_id": "CVE-2024-0001"}, {"cve_id": "CVE-2024-0002"}],
        )
        mock_collection.add.assert_called_once()


def test_vector_store_query():
    """Test querying."""
    with patch("chromadb.PersistentClient") as mock_client:
        mock_collection = MagicMock()
        mock_collection.query.return_value = {
            "ids": [["cve-1"]],
            "documents": [["desc 1"]],
            "metadatas": [[{"cve_id": "CVE-2024-0001"}]],
            "distances": [[0.5]],
        }
        mock_client.return_value.get_or_create_collection.return_value = mock_collection

        store = VectorStore(persist_dir="/tmp/test_chroma")
        results = store.query(query_text="test query", n_results=5)
        assert len(results) == 1
        assert results[0]["id"] == "cve-1"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_rag.py -v -k "vector_store"`
Expected: FAIL

- [ ] **Step 3: Implement**

Create `backend/app/rag/vector_store.py`:

```python
"""ChromaDB Vector Store."""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class VectorStore:
    """ChromaDB persistent vector store."""

    def __init__(self, persist_dir: str = "data/chromadb", collection_name: str = "cve_knowledge"):
        self.collection_name = collection_name
        try:
            import chromadb
            self._client = chromadb.PersistentClient(path=persist_dir)
            self._collection = self._client.get_or_create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"},
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
        """Add documents to the collection."""
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
        """Query the collection."""
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
```

- [ ] **Step 4: Run tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_rag.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/rag/vector_store.py tests/test_rag.py
git commit -m "feat: add ChromaDB vector store"
```

---

### Task 3: Create BM25 Search and RRF Pipeline

**Files:**
- Create: `backend/app/rag/bm25_search.py`
- Create: `backend/app/rag/pipeline.py`
- Test: `tests/test_rag.py`

- [ ] **Step 1: Write tests**

Add to `tests/test_rag.py`:

```python
from app.rag.bm25_search import BM25Search
from app.rag.pipeline import RAGPipeline


def test_bm25_search_index():
    """Test BM25 indexing."""
    search = BM25Search()
    search.index(
        ids=["cve-1", "cve-2"],
        documents=["Palo Alto command injection", "Apache log4j remote code execution"],
    )
    assert search.count == 2


def test_bm25_search_query():
    """Test BM25 query."""
    search = BM25Search()
    search.index(
        ids=["cve-1", "cve-2"],
        documents=["Palo Alto command injection vulnerability", "Apache log4j remote code execution"],
    )
    results = search.search("command injection", n_results=2)
    assert len(results) > 0
    assert results[0]["id"] == "cve-1"


def test_bm25_search_empty():
    """Test BM25 with no documents."""
    search = BM25Search()
    results = search.search("test", n_results=5)
    assert results == []


def test_pipeline_rrf_fusion():
    """Test RRF fusion of vector and BM25 results."""
    pipeline = RAGPipeline.__new__(RAGPipeline)

    vector_results = [
        {"id": "cve-1", "document": "desc1", "metadata": {}, "distance": 0.3},
        {"id": "cve-2", "document": "desc2", "metadata": {}, "distance": 0.5},
    ]
    bm25_results = [
        {"id": "cve-2", "document": "desc2", "score": 2.5},
        {"id": "cve-3", "document": "desc3", "score": 1.0},
    ]

    fused = pipeline._rrf_fusion(vector_results, bm25_results, k=60)
    assert len(fused) == 3
    # cve-2 appears in both, should rank highest
    assert fused[0]["id"] == "cve-2"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_rag.py -v -k "bm25 or pipeline"`
Expected: FAIL

- [ ] **Step 3: Implement**

Create `backend/app/rag/bm25_search.py`:

```python
"""BM25 Keyword Search."""

from __future__ import annotations

import re
from typing import Any


class BM25Search:
    """BM25-based keyword search over documents."""

    def __init__(self):
        self._ids: list[str] = []
        self._documents: list[str] = []
        self._bm25 = None

    @property
    def count(self) -> int:
        return len(self._ids)

    def index(self, ids: list[str], documents: list[str]) -> None:
        """Index documents for BM25 search."""
        self._ids = ids
        self._documents = documents
        if documents:
            from rank_bm25 import BM25Okapi
            tokenized = [self._tokenize(doc) for doc in documents]
            self._bm25 = BM25Okapi(tokenized)

    def search(self, query: str, n_results: int = 8) -> list[dict[str, Any]]:
        """Search documents by keyword relevance."""
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
                    "score": float(score),
                })
        return results

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Simple tokenization: lowercase, split on non-alphanumeric."""
        return re.findall(r"[a-z0-9]+", text.lower())
```

Create `backend/app/rag/pipeline.py`:

```python
"""RAG Pipeline — hybrid retrieval with RRF fusion."""

from __future__ import annotations

import logging
from typing import Any, Optional

from app.rag.bm25_search import BM25Search
from app.rag.embedder import EmbeddingService
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
        self.bm25 = bm25 or BM25Search()

    def retrieve(self, query: str, top_k: int = 4) -> list[dict[str, Any]]:
        """Retrieve relevant documents using hybrid search."""
        vector_results: list[dict[str, Any]] = []
        bm25_results: list[dict[str, Any]] = []

        # Vector search (if embedding available)
        if self.embedder.is_available and self.vector_store.is_available:
            embedding = self.embedder.encode([query])
            if embedding:
                vector_results = self.vector_store.query(
                    query_embedding=embedding[0],
                    n_results=8,
                )

        # BM25 search
        if self.bm25.count > 0:
            bm25_results = self.bm25.search(query, n_results=8)

        # If neither available, return empty
        if not vector_results and not bm25_results:
            logger.warning("No RAG results — both vector and BM25 empty")
            return []

        # RRF fusion
        fused = self._rrf_fusion(vector_results, bm25_results, k=60)
        return fused[:top_k]

    @staticmethod
    def _rrf_fusion(
        vector_results: list[dict[str, Any]],
        bm25_results: list[dict[str, Any]],
        k: int = 60,
    ) -> list[dict[str, Any]]:
        """Reciprocal Rank Fusion of vector and BM25 results."""
        scores: dict[str, float] = {}
        doc_map: dict[str, dict[str, Any]] = {}

        # Vector results
        for rank, doc in enumerate(vector_results):
            doc_id = doc["id"]
            scores[doc_id] = scores.get(doc_id, 0) + 1.0 / (k + rank + 1)
            doc_map[doc_id] = doc

        # BM25 results
        for rank, doc in enumerate(bm25_results):
            doc_id = doc["id"]
            scores[doc_id] = scores.get(doc_id, 0) + 1.0 / (k + rank + 1)
            if doc_id not in doc_map:
                doc_map[doc_id] = {"id": doc_id, "document": doc.get("document", ""), "metadata": {}}

        # Sort by fused score
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        results = []
        for doc_id, score in ranked:
            entry = doc_map[doc_id].copy()
            entry["rrf_score"] = score
            results.append(entry)

        return results
```

- [ ] **Step 4: Run tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_rag.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/rag/bm25_search.py backend/app/rag/pipeline.py tests/test_rag.py
git commit -m "feat: add BM25 search and RRF fusion pipeline"
```

---

### Task 4: Create RAG Tool for Agent

**Files:**
- Create: `backend/app/tools/rag_tool.py`
- Modify: `backend/app/agent/tool_executor.py`
- Test: `tests/test_rag.py`

- [ ] **Step 1: Write tests**

Add to `tests/test_rag.py`:

```python
from app.tools.rag_tool import RAGTool, RAGInput


def test_rag_tool_properties():
    tool = RAGTool()
    assert tool.name == "rag_search"
    assert tool.version == "v1"


def test_rag_tool_schema():
    tool = RAGTool()
    schema = tool.get_schema()
    assert schema["function"]["name"] == "rag_search"
    assert "query" in schema["function"]["parameters"]["properties"]


@pytest.mark.anyio
async def test_rag_tool_execute():
    """Test RAG tool with mocked pipeline."""
    mock_results = [
        {"id": "CVE-2024-3400", "document": "Palo Alto command injection", "metadata": {"cve_id": "CVE-2024-3400"}, "rrf_score": 0.05},
    ]

    with patch("app.tools.rag_tool.RAGPipeline") as mock_pipeline_cls:
        mock_pipeline = MagicMock()
        mock_pipeline.retrieve.return_value = mock_results
        mock_pipeline_cls.return_value = mock_pipeline

        tool = RAGTool()
        result = await tool.execute(RAGInput(
            query="Palo Alto vulnerability",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert len(result.data["results"]) == 1
    assert result.data["results"][0]["id"] == "CVE-2024-3400"


@pytest.mark.anyio
async def test_rag_tool_no_results():
    """Test RAG tool with no results."""
    with patch("app.tools.rag_tool.RAGPipeline") as mock_pipeline_cls:
        mock_pipeline = MagicMock()
        mock_pipeline.retrieve.return_value = []
        mock_pipeline_cls.return_value = mock_pipeline

        tool = RAGTool()
        result = await tool.execute(RAGInput(
            query="nonexistent topic",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["found"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_rag.py -v -k "rag_tool"`
Expected: FAIL

- [ ] **Step 3: Implement**

Create `backend/app/tools/rag_tool.py`:

```python
"""RAG Search Tool — retrieves relevant knowledge for the Agent.

Follows tool_protocol.md. Returns retrieved context.
No LLM interpretation — Agent layer handles that.
"""

from __future__ import annotations

import time
from typing import Any

from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult
from app.rag.pipeline import RAGPipeline


class RAGInput(ToolInput):
    """RAG Tool input."""

    query: str = Field(..., description="检索查询，如 CVE 编号、漏洞描述、攻击类型")


class RAGTool:
    """RAG 知识检索工具。"""

    name = "rag_search"
    version = "v1"
    input_class = RAGInput

    def __init__(self):
        self._pipeline: RAGPipeline | None = None

    def _get_pipeline(self) -> RAGPipeline:
        if self._pipeline is None:
            self._pipeline = RAGPipeline()
        return self._pipeline

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "rag_search",
                "description": "从安全知识库中检索相关信息，用于补充 CVE、ATT&CK 等背景知识。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "检索查询，如 CVE 编号、漏洞描述、攻击类型",
                        }
                    },
                    "required": ["query"],
                },
            },
        }

    async def execute(self, input_data: RAGInput) -> ToolResult:
        start = time.time()
        pipeline = self._get_pipeline()

        results = pipeline.retrieve(input_data.query, top_k=4)

        if not results:
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data={"query": input_data.query, "results": [], "found": False},
                confidence=0.0,
                evidence_source=["rag_pipeline"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data={
                "query": input_data.query,
                "results": results,
                "found": True,
            },
            confidence=0.8,
            evidence_source=["rag_pipeline"],
            trace_id=input_data.trace_id,
            execution_time_ms=int((time.time() - start) * 1000),
        )


rag_tool = RAGTool()
```

- [ ] **Step 4: Register in tool_executor.py**

Add to `backend/app/agent/tool_executor.py`:

```python
from app.tools.rag_tool import rag_tool
```

And `tool_registry.register(rag_tool)`.

- [ ] **Step 5: Run all tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/ -v --tb=short`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/tools/rag_tool.py backend/app/agent/tool_executor.py tests/test_rag.py
git commit -m "feat: add RAG search tool with hybrid retrieval"
```
