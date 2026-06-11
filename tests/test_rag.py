"""Tests for RAG module — Embedding, VectorStore, BM25, Pipeline, and RAGTool.

All tests use mocks so they pass without chromadb or sentence-transformers installed.
"""

import json

import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Task 1: EmbeddingService
# ---------------------------------------------------------------------------

class TestEmbeddingService:
    """Tests for app.rag.embedder.EmbeddingService."""

    def test_init_success(self):
        """Model loads successfully."""
        mock_st = MagicMock()
        mock_model = MagicMock()
        mock_st.return_value = mock_model

        with patch("app.rag.embedder.SentenceTransformer", mock_st):
            from app.rag.embedder import EmbeddingService
            svc = EmbeddingService(model_name="BAAI/bge-m3")

            assert svc.is_available is True
            mock_st.assert_called_once_with("BAAI/bge-m3")

    def test_init_failure_degrades(self):
        """Unavailable model sets is_available=False."""
        mock_st = MagicMock(side_effect=RuntimeError("no gpu"))

        with patch("app.rag.embedder.SentenceTransformer", mock_st):
            from app.rag.embedder import EmbeddingService
            svc = EmbeddingService()

            assert svc.is_available is False

    def test_encode_returns_vectors(self):
        """encode() returns list[list[float]]."""
        import numpy as np

        mock_st = MagicMock()
        mock_model = MagicMock()
        mock_model.encode.return_value = np.array([[0.1, 0.2], [0.3, 0.4]])
        mock_st.return_value = mock_model

        with patch("app.rag.embedder.SentenceTransformer", mock_st):
            from app.rag.embedder import EmbeddingService
            svc = EmbeddingService()
            result = svc.encode(["hello", "world"])

            assert result is not None
            assert len(result) == 2
            assert len(result[0]) == 2
            mock_model.encode.assert_called_once_with(["hello", "world"], normalize_embeddings=True)

    def test_encode_returns_none_when_unavailable(self):
        """encode() returns None when model not loaded."""
        mock_st = MagicMock(side_effect=RuntimeError("fail"))

        with patch("app.rag.embedder.SentenceTransformer", mock_st):
            from app.rag.embedder import EmbeddingService
            svc = EmbeddingService()

            assert svc.encode(["text"]) is None

    def test_encode_returns_none_on_runtime_error(self):
        """encode() returns None when encode() raises at runtime."""
        mock_st = MagicMock()
        mock_model = MagicMock()
        mock_model.encode.side_effect = RuntimeError("OOM")
        mock_st.return_value = mock_model

        with patch("app.rag.embedder.SentenceTransformer", mock_st):
            from app.rag.embedder import EmbeddingService
            svc = EmbeddingService()
            assert svc.encode(["boom"]) is None


# ---------------------------------------------------------------------------
# Task 2: VectorStore
# ---------------------------------------------------------------------------

class TestVectorStore:
    """Tests for app.rag.vector_store.VectorStore."""

    def _make_mock_chromadb(self):
        """Create a mock chromadb module with PersistentClient."""
        mock_chroma = MagicMock()
        mock_client = MagicMock()
        mock_col = MagicMock()
        mock_col.count.return_value = 0
        mock_col.query.return_value = {
            "ids": [["doc1", "doc2"]],
            "documents": [["Document 1 text", "Document 2 text"]],
            "metadatas": [[{"source": "nvd"}, {"source": "mitre"}]],
            "distances": [[0.1, 0.3]],
        }
        mock_client.get_or_create_collection.return_value = mock_col
        mock_chroma.PersistentClient.return_value = mock_client
        return mock_chroma, mock_client, mock_col

    def test_init_success(self):
        """ChromaDB client and collection created."""
        mock_chroma, mock_client, mock_col = self._make_mock_chromadb()

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore(persist_dir="/tmp/test_chroma", collection_name="test_col")

            assert store.is_available is True
            mock_client.get_or_create_collection.assert_called_once_with(
                name="test_col", metadata={"hnsw:space": "cosine"}, embedding_function=None,
            )

    def test_init_failure(self):
        """Unavailable when chromadb init fails."""
        mock_chroma = MagicMock()
        mock_chroma.PersistentClient.side_effect = RuntimeError("no chroma")

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()

            assert store.is_available is False

    def test_add_documents(self):
        """add_documents delegates to collection."""
        mock_chroma, mock_client, mock_col = self._make_mock_chromadb()

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()
            store.add_documents(
                ids=["a", "b"],
                documents=["doc a", "doc b"],
                metadatas=[{"k": "v1"}, {"k": "v2"}],
                embeddings=[[0.1], [0.2]],
            )

            mock_col.add.assert_called_once_with(
                ids=["a", "b"],
                documents=["doc a", "doc b"],
                metadatas=[{"k": "v1"}, {"k": "v2"}],
                embeddings=[[0.1], [0.2]],
            )

    def test_add_documents_noop_when_unavailable(self):
        """add_documents is a no-op when collection is None."""
        mock_chroma = MagicMock()
        mock_chroma.PersistentClient.side_effect = RuntimeError("fail")

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()
            # Should not raise
            store.add_documents(ids=["a"], documents=["d"])

    def test_query_by_embedding(self):
        """query() with embedding returns structured results."""
        mock_chroma, mock_client, mock_col = self._make_mock_chromadb()

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()
            results = store.query(query_embedding=[0.1, 0.2], n_results=2)

            assert len(results) == 2
            assert results[0]["id"] == "doc1"
            assert results[0]["document"] == "Document 1 text"
            assert results[0]["metadata"] == {"source": "nvd"}
            assert results[0]["distance"] == 0.1

    def test_query_by_text(self):
        """query() with text fallback."""
        mock_chroma, mock_client, mock_col = self._make_mock_chromadb()

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()
            store.query(query_text="CVE-2024-3400")

            mock_col.query.assert_called_once_with(
                n_results=8, query_texts=["CVE-2024-3400"],
            )

    def test_query_empty_when_unavailable(self):
        """query() returns [] when unavailable."""
        mock_chroma = MagicMock()
        mock_chroma.PersistentClient.side_effect = RuntimeError("fail")

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()
            assert store.query(query_text="hello") == []

    def test_query_empty_when_no_args(self):
        """query() returns [] with neither text nor embedding."""
        mock_chroma, mock_client, mock_col = self._make_mock_chromadb()

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()
            assert store.query() == []

    def test_count(self):
        """count() delegates to collection."""
        mock_chroma, mock_client, mock_col = self._make_mock_chromadb()
        mock_col.count.return_value = 42

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()
            assert store.count() == 42

    def test_count_zero_when_unavailable(self):
        """count() returns 0 when unavailable."""
        mock_chroma = MagicMock()
        mock_chroma.PersistentClient.side_effect = RuntimeError("fail")

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()
            assert store.count() == 0

    def test_fetch(self):
        """fetch() delegates to collection.get with metadata filters."""
        mock_chroma = MagicMock()
        mock_client = MagicMock()
        mock_col = MagicMock()
        mock_col.get.return_value = {
            "ids": ["doc1"],
            "documents": ["Document 1 text"],
            "metadatas": [{"source_type": "cve", "cve_id": "CVE-2024-0001"}],
        }
        mock_client.get_or_create_collection.return_value = mock_col
        mock_chroma.PersistentClient.return_value = mock_client

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()
            result = store.fetch(where={"source_type": "cve"})

            assert result["ids"] == ["doc1"]
            mock_col.get.assert_called_once_with(where={"source_type": "cve"})

    def test_iter_ids(self):
        """iter_ids() yields ids in pages."""
        mock_chroma = MagicMock()
        mock_client = MagicMock()
        mock_col = MagicMock()
        mock_col.count.return_value = 3
        mock_col.get.side_effect = [
            {"ids": ["a", "b"]},
            {"ids": ["c"]},
        ]
        mock_client.get_or_create_collection.return_value = mock_col
        mock_chroma.PersistentClient.return_value = mock_client

        with patch("app.rag.vector_store.chromadb", mock_chroma):
            from app.rag.vector_store import VectorStore
            store = VectorStore()
            assert list(store.iter_ids(page_size=2)) == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# Task 3: BM25Search
# ---------------------------------------------------------------------------

class TestBM25Search:
    """Tests for app.rag.bm25_search.BM25Search."""

    def test_empty_index(self):
        """Empty BM25 has count=0 and returns []."""
        from app.rag.bm25_search import BM25Search
        bm = BM25Search()
        assert bm.count == 0
        assert bm.search("anything") == []

    def test_index_and_search(self):
        """Indexing then searching returns ranked results."""
        mock_bm25_cls = MagicMock()
        mock_bm25 = MagicMock()
        mock_bm25.get_scores.return_value = [0.9, 0.1, 0.5]
        mock_bm25_cls.return_value = mock_bm25

        with patch("app.rag.bm25_search.BM25Okapi", mock_bm25_cls):
            from app.rag.bm25_search import BM25Search
            bm = BM25Search()
            bm.index(
                ids=["doc1", "doc2", "doc3"],
                documents=["SQL injection attack", "XSS cross-site scripting", "SQL database"],
            )

            assert bm.count == 3
            results = bm.search("SQL injection", n_results=2)

            assert len(results) == 2
            assert results[0]["id"] == "doc1"  # highest score 0.9
            assert results[0]["score"] == 0.9
            assert results[1]["id"] == "doc3"  # second highest 0.5

    def test_search_filters_zero_scores(self):
        """Documents with score 0 are excluded."""
        mock_bm25_cls = MagicMock()
        mock_bm25 = MagicMock()
        mock_bm25.get_scores.return_value = [2.0, 0.0, 0.0]
        mock_bm25_cls.return_value = mock_bm25

        with patch("app.rag.bm25_search.BM25Okapi", mock_bm25_cls):
            from app.rag.bm25_search import BM25Search
            bm = BM25Search()
            bm.index(ids=["a", "b", "c"], documents=["x", "y", "z"])
            results = bm.search("x")

            assert len(results) == 1
            assert results[0]["id"] == "a"

    def test_tokenize(self):
        """Tokenization preserves hyphenated identifiers and extracts sub-tokens."""
        from app.rag.bm25_search import BM25Search
        tokens = BM25Search._tokenize("CVE-2024-3400: SQL Injection!")
        # Hyphenated token preserved + sub-parts added
        assert "cve-2024-3400" in tokens
        assert "cve" in tokens
        assert "2024" in tokens
        assert "3400" in tokens
        assert "sql" in tokens
        assert "injection" in tokens


# ---------------------------------------------------------------------------
# Task 3b: BM25Search metadata, list, stats
# ---------------------------------------------------------------------------

class TestBM25Metadata:
    def test_index_with_metadata(self):
        from app.rag.bm25_search import BM25Search
        bm25 = BM25Search()
        bm25.index(
            ids=["CVE-2024-0001", "CVE-2024-0002"],
            documents=["Remote code execution vulnerability", "SQL injection flaw"],
            metadatas=[
                {"cve_id": "CVE-2024-0001", "cvss_score": 9.8, "severity": "CRITICAL"},
                {"cve_id": "CVE-2024-0002", "cvss_score": 7.5, "severity": "HIGH"},
            ],
        )
        assert bm25.count == 2

    def test_list_all(self):
        from app.rag.bm25_search import BM25Search
        bm25 = BM25Search()
        bm25.index(
            ids=["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
            documents=["RCE vuln", "SQL injection", "XSS flaw"],
            metadatas=[
                {"severity": "CRITICAL", "cvss_score": 9.8},
                {"severity": "HIGH", "cvss_score": 7.5},
                {"severity": "MEDIUM", "cvss_score": 5.0},
            ],
        )
        result = bm25.list_all(page=1, page_size=2)
        assert result["total"] == 3
        assert len(result["items"]) == 2
        assert result["page"] == 1

    def test_list_all_severity_filter(self):
        from app.rag.bm25_search import BM25Search
        bm25 = BM25Search()
        bm25.index(
            ids=["CVE-2024-0001", "CVE-2024-0002"],
            documents=["RCE vuln", "SQL injection"],
            metadatas=[
                {"severity": "CRITICAL", "cvss_score": 9.8},
                {"severity": "HIGH", "cvss_score": 7.5},
            ],
        )
        result = bm25.list_all(severity="CRITICAL")
        assert result["total"] == 1
        assert result["items"][0]["id"] == "CVE-2024-0001"

    def test_get_by_id(self):
        from app.rag.bm25_search import BM25Search
        bm25 = BM25Search()
        bm25.index(
            ids=["CVE-2024-0001"],
            documents=["RCE vuln"],
            metadatas=[{"severity": "CRITICAL", "cvss_score": 9.8}],
        )
        item = bm25.get_by_id("CVE-2024-0001")
        assert item is not None
        assert item["severity"] == "CRITICAL"
        assert bm25.get_by_id("CVE-9999-9999") is None

    def test_stats(self):
        from app.rag.bm25_search import BM25Search
        bm25 = BM25Search()
        bm25.index(
            ids=["CVE-2024-0001", "CVE-2024-0002"],
            documents=["RCE vuln", "SQL injection"],
            metadatas=[
                {"severity": "CRITICAL", "cvss_score": 9.8, "published": "2024-01-01"},
                {"severity": "HIGH", "cvss_score": 7.5, "published": "2024-02-01"},
            ],
        )
        stats = bm25.stats()
        assert stats["total"] == 2
        assert stats["by_severity"]["CRITICAL"] == 1
        assert stats["by_severity"]["HIGH"] == 1
        assert len(stats["recent"]) == 2

    def test_list_all_keyword_filter(self):
        from app.rag.bm25_search import BM25Search
        bm25 = BM25Search()
        bm25.index(
            ids=["CVE-2024-0001", "CVE-2024-0002"],
            documents=["Remote code execution vulnerability", "SQL injection flaw"],
            metadatas=[{"severity": "CRITICAL"}, {"severity": "HIGH"}],
        )
        result = bm25.list_all(keyword="remote")
        assert result["total"] == 1
        assert result["items"][0]["id"] == "CVE-2024-0001"

    def test_empty_index(self):
        from app.rag.bm25_search import BM25Search
        bm25 = BM25Search()
        assert bm25.count == 0
        assert bm25.list_all()["total"] == 0
        assert bm25.get_by_id("any") is None
        stats = bm25.stats()
        assert stats["total"] == 0
        assert stats["by_severity"] == {}


# ---------------------------------------------------------------------------
# Task 3: RAGPipeline
# ---------------------------------------------------------------------------

class TestRAGPipeline:
    """Tests for app.rag.pipeline.RAGPipeline."""

    def _make_pipeline(self, vector_results=None, bm25_results=None, embed_available=True):
        """Helper to build a pipeline with mocked dependencies."""
        from app.rag.pipeline import RAGPipeline

        embedder = MagicMock()
        embedder.is_available = embed_available
        embedder.encode.return_value = [[0.1, 0.2]] if embed_available else None

        vector_store = MagicMock()
        vector_store.is_available = embed_available
        vector_store.query.return_value = vector_results or []

        bm25 = MagicMock()
        bm25.count = len(bm25_results) if bm25_results else 0
        bm25.search.return_value = bm25_results or []

        return RAGPipeline(embedder=embedder, vector_store=vector_store, bm25=bm25)

    def test_retrieve_vector_only(self):
        """Uses vector search when BM25 is empty."""
        vec_docs = [
            {"id": "doc1", "document": "vec result 1", "metadata": {}, "distance": 0.1},
            {"id": "doc2", "document": "vec result 2", "metadata": {}, "distance": 0.3},
        ]
        pipe = self._make_pipeline(vector_results=vec_docs)
        results = pipe.retrieve("test query", top_k=2)

        assert len(results) == 2
        assert results[0]["id"] == "doc1"
        assert "rrf_score" in results[0]

    def test_retrieve_bm25_only(self):
        """Uses BM25 when vector is unavailable."""
        bm25_docs = [
            {"id": "doc1", "document": "bm25 result 1", "score": 5.0},
        ]
        pipe = self._make_pipeline(bm25_results=bm25_docs, embed_available=False)
        results = pipe.retrieve("test query", top_k=1)

        assert len(results) == 1
        assert results[0]["id"] == "doc1"
        assert "rrf_score" in results[0]

    def test_retrieve_uses_local_fallback_when_embedder_fails(self):
        """Fallback hashing still enables vector retrieval."""
        vec_docs = [
            {"id": "doc1", "document": "vec result 1", "metadata": {}, "distance": 0.1},
        ]
        pipe = self._make_pipeline(vector_results=vec_docs, embed_available=False)
        pipe.vector_store.is_available = True
        pipe.embedder.encode.return_value = None
        results = pipe.retrieve("attack technique", top_k=1)

        assert len(results) == 1
        assert results[0]["id"] == "doc1"

    def test_retrieve_hybrid_rrf(self):
        """RRF fusion ranks documents appearing in both lists higher."""
        vec_docs = [
            {"id": "docA", "document": "shared", "metadata": {}, "distance": 0.1},
            {"id": "docB", "document": "vec only", "metadata": {}, "distance": 0.2},
        ]
        bm25_docs = [
            {"id": "docA", "document": "shared", "score": 10.0},
            {"id": "docC", "document": "bm25 only", "score": 8.0},
        ]
        pipe = self._make_pipeline(vector_results=vec_docs, bm25_results=bm25_docs)
        results = pipe.retrieve("test query", top_k=3)

        ids = [r["id"] for r in results]
        assert "docA" in ids  # appears in both, should rank first
        assert "docB" in ids
        assert "docC" in ids
        # docA should be first since it appears in both lists
        assert results[0]["id"] == "docA"

    def test_retrieve_empty(self):
        """Returns [] when both sources are empty."""
        pipe = self._make_pipeline()
        results = pipe.retrieve("nothing found")
        assert results == []

    def test_rrf_fusion_scoring(self):
        """Verify RRF formula: 1/(k+rank+1)."""
        from app.rag.pipeline import RAGPipeline

        vec = [
            {"id": "x", "document": "x", "metadata": {}},
            {"id": "y", "document": "y", "metadata": {}},
        ]
        bm = [
            {"id": "x", "document": "x", "score": 1.0},
        ]
        fused = RAGPipeline._rrf_fusion(vec, bm, k=60)

        # x: 1/(60+0+1) + 1/(60+0+1) = 2/61
        # y: 1/(60+1+1) = 1/62
        assert fused[0]["id"] == "x"
        assert abs(fused[0]["rrf_score"] - 2.0 / 61) < 1e-9
        assert abs(fused[1]["rrf_score"] - 1.0 / 62) < 1e-9


# ---------------------------------------------------------------------------
# Task 4: RAGTool
# ---------------------------------------------------------------------------

class TestRAGTool:
    """Tests for app.tools.rag_tool.RAGTool."""

    def test_tool_properties(self):
        from app.tools.rag_tool import RAGTool
        tool = RAGTool()
        assert tool.name == "rag_search"
        assert tool.version == "v1"

    def test_tool_schema(self):
        from app.tools.rag_tool import RAGTool
        tool = RAGTool()
        schema = tool.get_schema()

        assert schema["type"] == "function"
        assert schema["function"]["name"] == "rag_search"
        params = schema["function"]["parameters"]
        assert "query" in params["properties"]
        assert "query" in params["required"]

    def test_input_class(self):
        from app.tools.rag_tool import RAGTool, RAGInput
        tool = RAGTool()
        assert tool.input_class == RAGInput

    @pytest.mark.anyio
    async def test_execute_found(self):
        """execute() returns results when pipeline finds matches."""
        from app.tools.rag_tool import RAGTool, RAGInput

        mock_results = [
            {"id": "doc1", "document": "CVE-2024-3400 info", "metadata": {}, "rrf_score": 0.05},
        ]

        with patch("app.tools.rag_tool.RAGPipeline") as MockPipeline:
            mock_pipe = MagicMock()
            mock_pipe.retrieve.return_value = mock_results
            MockPipeline.return_value = mock_pipe

            tool = RAGTool()
            result = await tool.execute(RAGInput(
                query="CVE-2024-3400",
                tenant_id="test",
                trace_id="test-trace",
            ))

        assert result.success is True
        assert result.data["found"] is True
        assert len(result.data["results"]) == 1
        assert result.confidence == 0.8
        assert "rag_pipeline" in result.evidence_source

    @pytest.mark.anyio
    async def test_execute_no_results(self):
        """execute() returns found=False when pipeline returns empty."""
        from app.tools.rag_tool import RAGTool, RAGInput

        with patch("app.tools.rag_tool.RAGPipeline") as MockPipeline:
            mock_pipe = MagicMock()
            mock_pipe.retrieve.return_value = []
            MockPipeline.return_value = mock_pipe

            tool = RAGTool()
            result = await tool.execute(RAGInput(
                query="nonexistent",
                tenant_id="test",
                trace_id="test-trace",
            ))

        assert result.success is True
        assert result.data["found"] is False
        assert result.data["results"] == []
        assert result.confidence == 0.0


class TestCVECatalogTool:
    """Tests for structured CVE catalog queries."""

    def test_parse_filters_from_query(self):
        from app.rag.cve_catalog import parse_catalog_filters

        filters = parse_catalog_filters(query="2024 CVSS 10.0 已被 CISA 加入 KEV 列表")

        assert filters["year"] == 2024
        assert filters["cvss_score"] == 10.0
        assert filters["kev_only"] is True

    def test_query_cve_catalog_filters_year_cvss_and_kev(self):
        from app.rag.cve_catalog import query_cve_catalog

        cve_rows = {
            "ids": ["cve-1", "cve-2", "cve-3"],
            "documents": ["doc1", "doc2", "doc3"],
            "metadatas": [
                {
                    "cve_id": "CVE-2024-0001",
                    "title": "CVE one",
                    "published": "2024-01-10T00:00:00Z",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "source_type": "cve",
                    "source_path": "corpus/nvd_full/nvd_high.jsonl",
                },
                {
                    "cve_id": "CVE-2024-0002",
                    "title": "CVE two",
                    "published": "2024-02-10T00:00:00Z",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "source_type": "cve",
                    "source_path": "corpus/nvd_full/nvd_high.jsonl",
                },
                {
                    "cve_id": "CVE-2023-0003",
                    "title": "CVE three",
                    "published": "2023-03-10T00:00:00Z",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "source_type": "cve",
                    "source_path": "corpus/nvd_full/nvd_high.jsonl",
                },
            ],
        }
        kev_rows = {
            "ids": ["kev-1", "kev-2"],
            "documents": ["kev doc 1", "kev doc 2"],
            "metadatas": [
                {
                    "cve_id": "CVE-2024-0001",
                    "kev_date": "2024-04-01",
                    "vendor": "Vendor A",
                    "product": "Product A",
                    "source_type": "kev",
                },
                {
                    "cve_id": "CVE-2024-0002",
                    "kev_date": "2024-04-02",
                    "vendor": "Vendor B",
                    "product": "Product B",
                    "source_type": "kev",
                },
            ],
        }
        store = MagicMock()
        store.is_available = True
        store.fetch.side_effect = [cve_rows, kev_rows]

        result = query_cve_catalog(year=2024, cvss_score=10.0, kev_only=True, store=store, limit=20)

        assert result["matched_count"] == 2
        assert [item["cve_id"] for item in result["items"]] == ["CVE-2024-0002", "CVE-2024-0001"]
        assert all(item["is_kev"] for item in result["items"])
        assert result["stats"]["kev_hit_rate"] == 1.0
        assert result["stats"]["by_year"]["2024"] == 2
        assert result["stats"]["by_severity"]["CRITICAL"] == 2
        assert result["evidence"]
        assert all(entry["source_type"] in {"cve", "kev"} for entry in result["evidence"])
        assert any("published" in entry["key_dates"] for entry in result["evidence"])
        assert any("kev_date" in entry["key_dates"] for entry in result["evidence"])
        assert "year=2024" in result["summary_text"]

    def test_query_cve_catalog_kev_filter_excludes_non_kev(self):
        from app.rag.cve_catalog import query_cve_catalog

        cve_rows = {
            "ids": ["cve-1", "cve-2"],
            "documents": ["doc1", "doc2"],
            "metadatas": [
                {
                    "cve_id": "CVE-2024-1001",
                    "title": "Shared Title",
                    "published": "2024-01-10T00:00:00Z",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "source_type": "cve",
                    "source_path": "corpus/nvd_full/nvd_high.jsonl",
                },
                {
                    "cve_id": "CVE-2024-1002",
                    "title": "Shared Title",
                    "published": "2024-02-10T00:00:00Z",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "source_type": "cve",
                    "source_path": "corpus/nvd_full/nvd_high.jsonl",
                },
            ],
        }
        kev_rows = {
            "ids": ["kev-1"],
            "documents": ["kev doc 1"],
            "metadatas": [
                {
                    "cve_id": "CVE-2024-1001",
                    "kev_date": "2024-04-01",
                    "vendor": "Vendor A",
                    "product": "Product A",
                    "source_type": "kev",
                    "source_path": "attack/intel_raw/kev.csv",
                }
            ],
        }

        store = MagicMock()
        store.is_available = True
        store.fetch.side_effect = [cve_rows, kev_rows]

        non_kev_result = query_cve_catalog(year=2024, kev_only=False, store=store, limit=20)

        assert non_kev_result["matched_count"] == 2
        assert {item["cve_id"] for item in non_kev_result["items"]} == {"CVE-2024-1001", "CVE-2024-1002"}
        assert any(item["is_kev"] is False for item in non_kev_result["items"])
        assert any(item["is_kev"] is True for item in non_kev_result["items"])

        store_kevy = MagicMock()
        store_kevy.is_available = True
        store_kevy.fetch.side_effect = [cve_rows, kev_rows]
        kev_only_result = query_cve_catalog(year=2024, kev_only=True, store=store_kevy, limit=20)

        assert kev_only_result["matched_count"] == 1
        assert [item["cve_id"] for item in kev_only_result["items"]] == ["CVE-2024-1001"]
        assert kev_only_result["items"][0]["evidence"][0]["doc_id"] == "cve-1"

    def test_query_cve_catalog_same_title_different_vulns_are_distinct(self):
        from app.rag.cve_catalog import query_cve_catalog

        cve_rows = {
            "ids": ["cve-a", "cve-b"],
            "documents": ["doc a", "doc b"],
            "metadatas": [
                {
                    "cve_id": "CVE-2024-2001",
                    "title": "Shared Title",
                    "published": "2024-03-10T00:00:00Z",
                    "cvss_score": 7.5,
                    "severity": "HIGH",
                    "source_type": "cve",
                    "source_path": "corpus/nvd_full/nvd_high.jsonl",
                },
                {
                    "cve_id": "CVE-2024-2002",
                    "title": "Shared Title",
                    "published": "2024-04-10T00:00:00Z",
                    "cvss_score": 8.8,
                    "severity": "HIGH",
                    "source_type": "cve",
                    "source_path": "corpus/nvd_full/nvd_high.jsonl",
                },
            ],
        }
        kev_rows = {"ids": [], "documents": [], "metadatas": []}

        store = MagicMock()
        store.is_available = True
        store.fetch.side_effect = [cve_rows, kev_rows]

        result = query_cve_catalog(keyword="Shared Title", store=store, limit=20)

        assert [item["cve_id"] for item in result["items"]] == ["CVE-2024-2002", "CVE-2024-2001"]
        assert {item["doc_id"] for item in result["items"]} == {"cve-a", "cve-b"}

    def test_query_cve_catalog_preserves_conflicting_dates(self):
        from app.rag.cve_catalog import query_cve_catalog

        cve_rows = {
            "ids": ["cve-date-1"],
            "documents": ["doc date"],
            "metadatas": [
                {
                    "cve_id": "CVE-2024-3001",
                    "title": "Date Conflict",
                    "published": "2024-01-10T00:00:00Z",
                    "first_seen": "2024-01-12T08:30:00Z",
                    "cvss_score": 9.1,
                    "severity": "CRITICAL",
                    "source_type": "cve",
                    "source_path": "corpus/nvd_full/nvd_high.jsonl",
                },
            ],
        }
        kev_rows = {
            "ids": ["kev-date-1"],
            "documents": ["kev date doc"],
            "metadatas": [
                {
                    "cve_id": "CVE-2024-3001",
                    "kev_date": "2024-02-20",
                    "source_type": "kev",
                    "source_path": "attack/intel_raw/kev.csv",
                }
            ],
        }

        store = MagicMock()
        store.is_available = True
        store.fetch.side_effect = [cve_rows, kev_rows]

        result = query_cve_catalog(keyword="Date Conflict", store=store, limit=20)

        item = result["items"][0]
        assert item["published"] == "2024-01-10T00:00:00Z"
        assert item["first_seen"] == "2024-01-12T08:30:00Z"
        assert item["kev_date"] == "2024-02-20"
        assert item["evidence"][0]["key_dates"]["published"] == "2024-01-10T00:00:00Z"
        assert item["evidence"][1]["key_dates"]["kev_date"] == "2024-02-20"

    def test_build_catalog_stats(self):
        from app.rag.cve_catalog import build_catalog_stats

        items = [
            {"published": "2024-01-10T00:00:00Z", "severity": "CRITICAL", "is_kev": True},
            {"published": "2024-02-10T00:00:00Z", "severity": "HIGH", "is_kev": False},
            {"published": "2023-03-10T00:00:00Z", "severity": "HIGH", "is_kev": True},
        ]

        stats = build_catalog_stats(items, total_cve_docs=10, total_kev_docs=3)

        assert stats["matched_count"] == 3
        assert stats["kev_count"] == 2
        assert stats["kev_hit_rate"] == pytest.approx(2 / 3, rel=1e-4)
        assert stats["by_year"]["2024"] == 2
        assert stats["by_year"]["2023"] == 1
        assert stats["by_severity"]["HIGH"] == 2
        assert stats["kev_by_year"]["2024"] == 1
        assert stats["coverage"]["total_cve_docs"] == 10
        assert stats["coverage"]["kev_doc_coverage"] == 0.3

    @pytest.mark.anyio
    async def test_execute_returns_structured_result(self):
        from app.tools.cve_catalog_tool import CVECatalogInput, CVECatalogTool

        mock_data = {
            "query": "2024 CVSS 10.0 KEV",
            "filters": {"query": "2024 CVSS 10.0 KEV", "year": 2024, "cvss_score": 10.0, "kev_only": True, "severity": None, "keyword": None},
            "total_cve_docs": 3,
            "total_kev_docs": 2,
            "matched_count": 1,
            "kev_count": 1,
            "stats": {
                "matched_count": 1,
                "kev_count": 1,
                "kev_hit_rate": 1.0,
                "by_year": {"2024": 1},
                "by_severity": {"CRITICAL": 1},
                "kev_by_year": {"2024": 1},
                "kev_by_severity": {"CRITICAL": 1},
                "coverage": {"total_cve_docs": 3, "total_kev_docs": 2, "kev_doc_coverage": 0.6667},
            },
            "summary_text": "筛选条件: year=2024, cvss=10.0, kev_only=True；CVE 总数 3，KEV 总数 2，命中 1 条。",
            "items": [
                {
                    "cve_id": "CVE-2024-0001",
                    "title": "CVE one",
                    "published": "2024-01-10T00:00:00Z",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "is_kev": True,
                    "kev_date": "2024-04-01",
                    "vendor": "Vendor A",
                    "product": "Product A",
                    "source_type": "cve",
                    "source_path": "corpus/nvd_full/nvd_high.jsonl",
                }
            ],
        }

        with patch("app.tools.cve_catalog_tool.query_cve_catalog", return_value=mock_data):
            tool = CVECatalogTool()
            result = await tool.execute(CVECatalogInput(
                query="2024 CVSS 10.0 KEV",
                tenant_id="test",
                trace_id="test-trace",
            ))

        assert result.success is True
        assert result.data["matched_count"] == 1
        assert result.evidence_source == ["kb_public_all_v1", "source_type:cve", "source_type:kev"]

    def test_tool_registration(self):
        from app.agent.tool_executor import tool_registry

        assert "cve_catalog" in tool_registry.list_names()


class TestAgentReactFallback:
    def test_build_web_search_fallback_handles_string_results(self):
        from app.agent.react import _build_web_search_fallback

        text = _build_web_search_fallback(
            "CVE-2024-3400",
            {"data": {"results": ["CVE-2024-3400 is KEV-listed", {"title": "Palo Alto advisory", "snippet": "official"}]}}
        )

        assert "CVE-2024-3400 is KEV-listed" in text
        assert "Palo Alto advisory" in text


# ---------------------------------------------------------------------------
# Task 5: Stage 2 Importer
# ---------------------------------------------------------------------------

class TestStage2Importer:
    """Tests for the Stage 2 normalized corpus importer."""

    def test_iter_normalized_docs_filters_source_types(self, tmp_path):
        from app.rag.stage2_importer import iter_normalized_docs

        path = tmp_path / "normalized_docs.jsonl"
        records = [
            {"doc_id": "1", "title": "CVE-1", "content": "a", "source_type": "cve", "category": "attack"},
            {"doc_id": "2", "title": "ATT&CK", "content": "b", "source_type": "mitre_attack", "category": "attack"},
            {"doc_id": "3", "title": "Sigma", "content": "c", "source_type": "ids_rule", "category": "rules"},
        ]
        with open(path, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")

        selected = list(iter_normalized_docs(path=path, source_types=["mitre_attack", "ids_rule"]))
        assert [item["doc_id"] for item in selected] == ["2", "3"]

    def test_build_index_payload(self):
        from app.rag.stage2_importer import build_index_payload

        records = [
            {
                "doc_id": "attack-1",
                "title": "Technique X",
                "content": "Describe technique",
                "category": "attack",
                "source_type": "mitre_attack",
                "source_path": "attack/mitre_attack.json",
                "tags": ["attack", "technique"],
                "extra": {"platform": "Windows", "rank": 1},
            }
        ]
        ids, documents, metadatas = build_index_payload(records)
        assert ids == ["attack-1"]
        assert documents[0].startswith("Technique X")
        assert metadatas[0]["source_type"] == "mitre_attack"
        assert metadatas[0]["embedding_version"] == "local-hash-v1"
        assert metadatas[0]["platform"] == "Windows"

    def test_build_index_payload_skips_none_metadata(self):
        from app.rag.stage2_importer import build_index_payload

        records = [
            {
                "doc_id": "intel-1",
                "title": "Threat Intel",
                "content": "Example",
                "category": "attack",
                "source_type": "exploit_status",
                "source_path": "attack/intel_norm/exploit_status.jsonl",
                "tags": ["vuln_intel"],
                "extra": {"epss_score": None, "epss_percentile": None, "kev_flag": False},
            }
        ]
        ids, documents, metadatas = build_index_payload(records)

        assert ids == ["intel-1"]
        assert metadatas[0]["kev_flag"] is False
        assert "epss_score" not in metadatas[0]
        assert "epss_percentile" not in metadatas[0]

    def test_stage2_threat_intel_source_types(self):
        from app.rag.stage2_importer import DEFAULT_STAGE2_THREAT_INTEL_SOURCE_TYPES
        from app.scripts.reindex_rag import STAGE2_PROFILES

        assert DEFAULT_STAGE2_THREAT_INTEL_SOURCE_TYPES == (
            "cve_attack_mapping",
            "exploit_status",
            "vendor_advisory",
            "vuln_decision",
            "vuln_facts",
            "json_record",
        )
        assert STAGE2_PROFILES["threat_intel"] == DEFAULT_STAGE2_THREAT_INTEL_SOURCE_TYPES

    def test_iter_normalized_docs_filters_threat_intel(self, tmp_path):
        from app.rag.stage2_importer import iter_normalized_docs

        path = tmp_path / "normalized_docs.jsonl"
        records = [
            {"doc_id": "1", "title": "CVE", "content": "a", "source_type": "mitre_attack", "category": "attack"},
            {"doc_id": "2", "title": "Threat Intel", "content": "b", "source_type": "exploit_status", "category": "attack"},
            {"doc_id": "3", "title": "Vendor Advisory", "content": "c", "source_type": "vendor_advisory", "category": "attack"},
        ]
        with open(path, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")

        selected = list(iter_normalized_docs(path=path, source_types=["exploit_status", "vendor_advisory"]))
        assert [item["doc_id"] for item in selected] == ["2", "3"]

    def test_reindex_rag_profile_selects_threat_intel(self):
        from app.scripts import reindex_rag

        with patch("app.scripts.reindex_rag.import_stage2_public") as mock_import:
            mock_import.return_value = {"seen": 1, "selected": 1, "indexed": 1, "skipped_existing": 0}

            reindex_rag.main(["--profile", "threat_intel", "--collection", "test_col", "--dry-run"])

        mock_import.assert_called_once()
        kwargs = mock_import.call_args.kwargs
        assert kwargs["collection_name"] == "test_col"
        assert kwargs["source_types"] == list(reindex_rag.STAGE2_PROFILES["threat_intel"])

    def test_reindex_rag_profile_includes_fingerprints(self):
        from app.scripts import reindex_rag

        assert reindex_rag.STAGE2_PROFILES["fingerprints"] == ("ja3",)
        assert "ja3" in reindex_rag.STAGE2_PROFILES["all_public"]

    def test_build_kev_index_payload(self, tmp_path):
        from app.rag.kev_importer import build_kev_index_payload

        records = [
            {
                "cveID": "CVE-2025-29635",
                "vendorProject": "D-Link",
                "product": "DIR-823X",
                "vulnerabilityName": "D-Link DIR-823X Command Injection Vulnerability",
                "dateAdded": "2026-04-24",
                "shortDescription": "Example KEV description",
                "requiredAction": "Apply mitigations",
                "dueDate": "2026-05-08",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "https://example.invalid",
                "cwes": "CWE-77",
            }
        ]

        ids, documents, metadatas = build_kev_index_payload(records)

        assert ids == ["kev-CVE-2025-29635"]
        assert "D-Link" in documents[0]
        assert metadatas[0]["source_type"] == "kev"
        assert metadatas[0]["cve_id"] == "CVE-2025-29635"
        assert metadatas[0]["vendor"] == "D-Link"

