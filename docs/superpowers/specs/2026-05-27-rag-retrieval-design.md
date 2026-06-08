# RAG Retrieval Module — Design Spec

## Overview

RAG (Retrieval-Augmented Generation) 模块为 CyberSec Agent 提供知识检索能力。使用 ChromaDB 向量存储 + BGE-M3 Embedding + BM25 全文检索 + RRF 融合重排序。

## Components

### 1. Embedding Service (`backend/app/rag/embedder.py`)
- BGE-M3 模型本地推理（sentence-transformers）
- 降级保护：模型不可用时返回 None，RAG 降级为纯 BM25
- 批量编码支持

### 2. Vector Store (`backend/app/rag/vector_store.py`)
- ChromaDB 本地持久化存储
- Collection 管理（CVE 知识库、ATT&CK 等）
- 向量检索 Top-K

### 3. BM25 Search (`backend/app/rag/bm25_search.py`)
- rank_bm25 库
- 基于关键词的全文检索
- 对 CVE 编号、IP 等精确词至关重要

### 4. RAG Pipeline (`backend/app/rag/pipeline.py`)
- 混合检索：向量 + BM25
- RRF 融合：`score = Σ 1/(k + rank_i)`，k=60
- Top-K 结果返回给 Agent

### 5. Data Import (`backend/app/rag/importer.py`)
- 从 NVD API 批量拉取 CVE 数据
- 导入 ChromaDB

## Data Flow

```
User Query
    ↓
Embedding (BGE-M3) → Vector Search (ChromaDB Top-8)
    ↓                                              ↓
BM25 Search (Top-8)                          Cosine Scores
    ↓                                              ↓
         RRF Fusion (k=60) ←──────────────────────┘
                ↓
         Top-4 Results → Inject into Agent Prompt
```

## Degradation

- BGE-M3 不可用 → 纯 BM25 检索
- ChromaDB 不可用 → 纯 BM25 检索
- 两者都不可用 → RAG 返回空结果，Agent 仅依赖工具数据

## File Structure

| File | Responsibility |
|------|---------------|
| `backend/app/rag/__init__.py` | Package init |
| `backend/app/rag/embedder.py` | BGE-M3 embedding with degradation |
| `backend/app/rag/vector_store.py` | ChromaDB client and collection management |
| `backend/app/rag/bm25_search.py` | BM25 keyword search |
| `backend/app/rag/pipeline.py` | RAG pipeline with RRF fusion |
| `backend/app/rag/importer.py` | CVE data import from NVD |
| `backend/app/tools/rag_tool.py` | RAG tool for ReAct Agent |
| `tests/test_rag.py` | Unit tests |

## Constraints

- Python 3.9 compatible
- BGE-M3 model: BAAI/bge-m3 (~2GB download)
- ChromaDB persistent storage: `data/chromadb/`
- No LLM in RAG tool — returns retrieved context only
- Agent layer decides how to use retrieved context
