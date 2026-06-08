# Phase 2 Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the CyberSec Agent web frontend — login, chat with tool progress, CVE database search with stats — using React 18 + Vite + Ant Design 5.

**Architecture:** Vite SPA with proxy to FastAPI backend. Zustand for state, axios for HTTP, native WebSocket for chat. Ant Design 5 ConfigProvider for theme switching. Backend gains 3 new CVE REST endpoints backed by BM25 in-memory data.

**Tech Stack:** React 18, TypeScript, Vite 5, Ant Design 5, Zustand 4, axios, ECharts 5, React Router 6, dayjs

---

## File Structure

### Frontend (new)

```
frontend/
├── index.html
├── package.json
├── tsconfig.json
├── tsconfig.node.json
├── vite.config.ts
├── .env.development
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── vite-env.d.ts
│   ├── types/
│   │   └── api.ts                  # All API/WebSocket type definitions
│   ├── api/
│   │   ├── client.ts               # axios instance + JWT interceptor
│   │   ├── auth.ts                 # login API
│   │   └── cve.ts                  # CVE list/detail/stats APIs
│   ├── stores/
│   │   ├── auth.ts                 # JWT + user info + login/logout
│   │   ├── chat.ts                 # sessions, messages, tool calls
│   │   └── theme.ts                # dark/light theme state
│   ├── hooks/
│   │   └── useWebSocket.ts         # WebSocket connection + event parsing
│   ├── components/
│   │   ├── AppLayout/
│   │   │   └── index.tsx           # Layout + Sider + menu + outlet
│   │   ├── ProtectedRoute/
│   │   │   └── index.tsx           # Auth guard
│   │   ├── ChatMessage/
│   │   │   └── index.tsx           # Message bubble
│   │   └── ToolProgress/
│   │       └── index.tsx           # Tool call status cards
│   └── pages/
│       ├── Login/
│       │   └── index.tsx
│       ├── Chat/
│       │   ├── index.tsx           # Main chat page
│       │   ├── SessionList.tsx
│       │   ├── MessageList.tsx
│       │   └── MessageInput.tsx
│       └── CveSearch/
│           ├── index.tsx           # Main CVE page
│           ├── CveTable.tsx
│           ├── CveDetail.tsx
│           └── StatsPanel.tsx
```

### Backend (modify)

```
backend/app/
├── rag/bm25_search.py              # Add metadata storage + list method
├── rag/importer.py                 # Pass metadata when indexing
├── api/cve.py                      # NEW: CVE list/detail/stats endpoints
└── main.py                         # Include cve router
```

---

## Task 1: Backend — BM25 Metadata Storage + CVE REST API

The BM25 index currently stores only `_ids` and `_documents`. The frontend needs list/detail/stats endpoints. We add metadata storage to BM25 and create a new API router.

### Task 1.1: Add metadata to BM25Search

**Files:**
- Modify: `backend/app/rag/bm25_search.py`
- Test: `tests/test_rag.py`

- [ ] **Step 1: Add `_metadatas` field and `list` method to BM25Search**

In `backend/app/rag/bm25_search.py`, add metadata support:

```python
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
        items = []
        for i in range(len(self._ids)):
            meta = self._metadatas[i] if i < len(self._metadatas) else {}
            item = {
                "id": self._ids[i],
                "document": self._documents[i],
                **meta,
            }
            # Filter by severity
            if severity and meta.get("severity", "").upper() != severity.upper():
                continue
            # Filter by keyword
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
                return {"id": id_, "document": self._documents[i], **meta}
        return None

    def stats(self) -> dict[str, Any]:
        """Return severity distribution and recent items."""
        by_severity: dict[str, int] = {}
        for meta in self._metadatas:
            sev = meta.get("severity", "UNKNOWN").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1

        # Recent items (by published date if available)
        recent = []
        for i in range(len(self._ids)):
            meta = self._metadatas[i] if i < len(self._metadatas) else {}
            recent.append({
                "cve_id": self._ids[i],
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
```

- [ ] **Step 2: Add test for list_all and stats**

In `tests/test_rag.py`, add tests for the new methods:

```python
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
```

- [ ] **Step 3: Run tests**

Run: `cd /data/data6T/liang/project/Agent && /data/data6T/liang/Anaconda/bin/python -m pytest tests/test_rag.py -v -k "BM25Metadata" --tb=short`

Expected: All 5 new tests PASS.

- [ ] **Step 4: Run all tests to verify no regressions**

Run: `cd /data/data6T/liang/project/Agent && /data/data6T/liang/Anaconda/bin/python -m pytest tests/ -q --tb=short`

Expected: 114 passed (109 existing + 5 new).

- [ ] **Step 5: Commit**

```bash
git add backend/app/rag/bm25_search.py tests/test_rag.py
git commit -m "feat: add metadata storage and list/stats methods to BM25Search"
```

### Task 1.2: Update importer to pass metadata

**Files:**
- Modify: `backend/app/rag/importer.py`

- [ ] **Step 1: Update index_cves_to_bm25 to pass metadata**

In `backend/app/rag/importer.py`, modify `index_cves_to_bm25`:

```python
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
```

- [ ] **Step: Run all tests**

Run: `cd /data/data6T/liang/project/Agent && /data/data6T/liang/Anaconda/bin/python -m pytest tests/ -q --tb=short`

Expected: All pass.

- [ ] **Step: Commit**

```bash
git add backend/app/rag/importer.py
git commit -m "feat: pass metadata when indexing CVEs into BM25"
```

### Task 1.3: Create CVE REST API endpoints

**Files:**
- Create: `backend/app/api/cve.py`
- Modify: `backend/app/main.py`
- Test: `tests/test_cve_api.py`

- [ ] **Step 1: Create CVE API router**

Create `backend/app/api/cve.py`:

```python
"""CVE REST API endpoints."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Query

router = APIRouter(prefix="/api/v1/cve", tags=["cve"])


def _get_bm25():
    """Get BM25 instance (lazy import to avoid circular deps)."""
    from app.rag.bm25_search import BM25Search
    return BM25Search()


@router.get("/list")
async def list_cves(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    keyword: Optional[str] = None,
) -> dict[str, Any]:
    """List CVEs with pagination and filtering."""
    bm25 = _get_bm25()
    return bm25.list_all(page=page, page_size=page_size, severity=severity, keyword=keyword)


@router.get("/stats")
async def cve_stats() -> dict[str, Any]:
    """CVE severity distribution and recent items."""
    bm25 = _get_bm25()
    return bm25.stats()


@router.get("/{cve_id}")
async def get_cve(cve_id: str) -> dict[str, Any]:
    """Get a single CVE by ID."""
    bm25 = _get_bm25()
    item = bm25.get_by_id(cve_id)
    if not item:
        return {"error": "not_found", "cve_id": cve_id}
    return item
```

- [ ] **Step 2: Register CVE router in main.py**

In `backend/app/main.py`, add import and include:

```python
from app.api.cve import router as cve_router
```

And add after the other router includes:

```python
app.include_router(cve_router)
```

- [ ] **Step 3: Write tests for CVE API**

Create `tests/test_cve_api.py`:

```python
"""Tests for CVE REST API."""

from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def mock_bm25():
    """Mock BM25Search with sample data."""
    mock = MagicMock()
    mock.count = 2
    mock.list_all.return_value = {
        "items": [
            {"id": "CVE-2024-0001", "cve_id": "CVE-2024-0001", "severity": "CRITICAL", "cvss_score": 9.8, "document": "RCE vuln"},
            {"id": "CVE-2024-0002", "cve_id": "CVE-2024-0002", "severity": "HIGH", "cvss_score": 7.5, "document": "SQL injection"},
        ],
        "total": 2,
        "page": 1,
        "page_size": 20,
    }
    mock.get_by_id.return_value = {
        "id": "CVE-2024-0001",
        "cve_id": "CVE-2024-0001",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "document": "Remote code execution vulnerability",
    }
    mock.stats.return_value = {
        "total": 2,
        "by_severity": {"CRITICAL": 1, "HIGH": 1},
        "recent": [
            {"cve_id": "CVE-2024-0001", "severity": "CRITICAL", "cvss_score": 9.8, "published": "2024-01-01"},
        ],
    }
    return mock


@pytest.fixture
def client(mock_bm25):
    """Test client with mocked BM25."""
    with patch("app.api.cve._get_bm25", return_value=mock_bm25):
        from app.main import app
        return TestClient(app)


class TestCveListAPI:
    def test_list_default(self, client):
        resp = client.get("/api/v1/cve/list")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert data["page"] == 1

    def test_list_with_severity_filter(self, client, mock_bm25):
        resp = client.get("/api/v1/cve/list?severity=CRITICAL")
        assert resp.status_code == 200
        mock_bm25.list_all.assert_called_once_with(page=1, page_size=20, severity="CRITICAL", keyword=None)

    def test_list_with_pagination(self, client, mock_bm25):
        resp = client.get("/api/v1/cve/list?page=2&page_size=10")
        assert resp.status_code == 200
        mock_bm25.list_all.assert_called_once_with(page=2, page_size=10, severity=None, keyword=None)


class TestCveDetailAPI:
    def test_get_existing_cve(self, client):
        resp = client.get("/api/v1/cve/CVE-2024-0001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2024-0001"
        assert data["severity"] == "CRITICAL"

    def test_get_nonexistent_cve(self, client, mock_bm25):
        mock_bm25.get_by_id.return_value = None
        resp = client.get("/api/v1/cve/CVE-9999-9999")
        assert resp.status_code == 200
        data = resp.json()
        assert data["error"] == "not_found"


class TestCveStatsAPI:
    def test_stats(self, client):
        resp = client.get("/api/v1/cve/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "by_severity" in data
        assert "recent" in data
```

- [ ] **Step 4: Run tests**

Run: `cd /data/data6T/liang/project/Agent && /data/data6T/liang/Anaconda/bin/python -m pytest tests/test_cve_api.py -v --tb=short`

Expected: All 6 tests PASS.

- [ ] **Step 5: Run all tests**

Run: `cd /data/data6T/liang/project/Agent && /data/data6T/liang/Anaconda/bin/python -m pytest tests/ -q --tb=short`

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add backend/app/api/cve.py backend/app/main.py tests/test_cve_api.py
git commit -m "feat: add CVE list/detail/stats REST API endpoints"
```

---

## Task 2: Frontend Scaffolding

Set up Vite + React 18 + TypeScript project with all dependencies.

**Files:**
- Create: `frontend/` directory with all scaffolding files

- [ ] **Step 1: Create frontend directory and initialize**

```bash
cd /data/data6T/liang/project/Agent
mkdir -p frontend/src/{api,stores,hooks,components/{AppLayout,ProtectedRoute,ChatMessage,ToolProgress},pages/{Login,Chat,CveSearch},types}
mkdir -p frontend/public
```

- [ ] **Step 2: Create package.json**

Create `frontend/package.json`:

```json
{
  "name": "cybersec-agent-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.26.2",
    "antd": "^5.21.0",
    "@ant-design/icons": "^5.5.1",
    "axios": "^1.7.7",
    "zustand": "^4.5.5",
    "echarts": "^5.5.1",
    "echarts-for-react": "^3.0.2",
    "dayjs": "^1.11.13"
  },
  "devDependencies": {
    "typescript": "^5.6.2",
    "vite": "^5.4.8",
    "@vitejs/plugin-react": "^4.3.2",
    "@types/react": "^18.3.11",
    "@types/react-dom": "^18.3.0"
  }
}
```

- [ ] **Step 3: Create tsconfig.json**

Create `frontend/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": false,
    "noUnusedParameters": false,
    "noFallthroughCasesInSwitch": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "esModuleInterop": true
  },
  "include": ["src"]
}
```

Create `frontend/tsconfig.node.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2023"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "strict": true
  },
  "include": ["vite.config.ts"]
}
```

- [ ] **Step 4: Create vite.config.ts**

Create `frontend/vite.config.ts`:

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
});
```

- [ ] **Step 5: Create .env.development**

Create `frontend/.env.development`:

```
VITE_API_BASE_URL=http://localhost:8000
```

- [ ] **Step 6: Create index.html**

Create `frontend/index.html`:

```html
<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CyberSec Agent</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 7: Create vite-env.d.ts**

Create `frontend/src/vite-env.d.ts`:

```typescript
/// <reference types="vite/client" />
```

- [ ] **Step 8: Install dependencies**

```bash
cd /data/data6T/liang/project/Agent/frontend && npm install
```

- [ ] **Step 9: Verify build works**

```bash
cd /data/data6T/liang/project/Agent/frontend && npx tsc --noEmit
```

Expected: No errors (src is empty, so just type-check passes).

- [ ] **Step 10: Commit**

```bash
git add frontend/
git commit -m "feat: scaffold Vite + React 18 + TypeScript frontend project"
```

---

## Task 3: Type Definitions + API Client

Define all TypeScript types for the backend API, create axios client with JWT interceptor, and implement auth/CVE API functions.

**Files:**
- Create: `frontend/src/types/api.ts`
- Create: `frontend/src/api/client.ts`
- Create: `frontend/src/api/auth.ts`
- Create: `frontend/src/api/cve.ts`

- [ ] **Step 1: Create API type definitions**

Create `frontend/src/types/api.ts`:

```typescript
// Auth
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user_id: string;
  role: string;
  tenant_id: string;
}

export interface JwtPayload {
  sub: string;
  role: string;
  tenant_id: string;
  exp: number;
}

// CVE
export interface CveItem {
  id: string;
  cve_id: string;
  description: string;
  cvss_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  published: string;
}

export interface CveListResponse {
  items: CveItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface CveStatsResponse {
  total: number;
  by_severity: Record<string, number>;
  recent: Array<{
    cve_id: string;
    severity: string;
    cvss_score: number;
    published: string;
  }>;
}

// WebSocket events
export type WSEvent =
  | { type: 'llm_backend'; provider: string; model: string }
  | { type: 'tool_call'; tool: string; status: 'running' }
  | { type: 'tool_result'; tool: string; success: boolean }
  | { type: 'token'; content: string }
  | { type: 'done'; session_id: string; total_tokens: number }
  | { type: 'error'; code: string; message: string };

// Chat
export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  toolCalls?: ToolCallInfo[];
  tokenCount?: number;
}

export interface ToolCallInfo {
  tool: string;
  status: 'running' | 'success' | 'failed';
  startTime: number;
  endTime?: number;
}

export interface Session {
  id: string;
  title: string;
  lastMessage: string;
  updatedAt: number;
}
```

- [ ] **Step 2: Create axios client**

Create `frontend/src/api/client.ts`:

```typescript
import axios from 'axios';

const client = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
});

// Request interceptor: attach JWT
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor: handle 401
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  },
);

export default client;
```

- [ ] **Step 3: Create auth API**

Create `frontend/src/api/auth.ts`:

```typescript
import client from './client';
import type { LoginRequest, LoginResponse } from '../types/api';

export async function login(req: LoginRequest): Promise<LoginResponse> {
  const { data } = await client.post<LoginResponse>('/auth/login', req);
  return data;
}
```

- [ ] **Step 4: Create CVE API**

Create `frontend/src/api/cve.ts`:

```typescript
import client from './client';
import type { CveListResponse, CveStatsResponse, CveItem } from '../types/api';

export async function listCves(params: {
  page?: number;
  page_size?: number;
  severity?: string;
  keyword?: string;
}): Promise<CveListResponse> {
  const { data } = await client.get<CveListResponse>('/cve/list', { params });
  return data;
}

export async function getCve(cveId: string): Promise<CveItem> {
  const { data } = await client.get<CveItem>(`/cve/${cveId}`);
  return data;
}

export async function getCveStats(): Promise<CveStatsResponse> {
  const { data } = await client.get<CveStatsResponse>('/cve/stats');
  return data;
}
```

- [ ] **Step 5: Verify TypeScript compiles**

```bash
cd /data/data6T/liang/project/Agent/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/types/ frontend/src/api/
git commit -m "feat: add API types, axios client, auth and CVE API functions"
```

---

## Task 4: Zustand Stores + Theme Hook

Create auth store (JWT persistence), chat store (messages/sessions), and theme store (light/dark).

**Files:**
- Create: `frontend/src/stores/auth.ts`
- Create: `frontend/src/stores/chat.ts`
- Create: `frontend/src/stores/theme.ts`

- [ ] **Step 1: Create auth store**

Create `frontend/src/stores/auth.ts`:

```typescript
import { create } from 'zustand';
import type { JwtPayload } from '../types/api';
import { login as loginApi } from '../api/auth';

function parseJwt(token: string): JwtPayload | null {
  try {
    const base64 = token.split('.')[1];
    const json = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

interface AuthState {
  token: string | null;
  user: JwtPayload | null;
  isAuthenticated: boolean;
  loading: boolean;
  error: string | null;

  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  loadFromStorage: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: null,
  user: null,
  isAuthenticated: false,
  loading: false,
  error: null,

  login: async (username, password) => {
    set({ loading: true, error: null });
    try {
      const resp = await loginApi({ username, password });
      localStorage.setItem('token', resp.access_token);
      const payload = parseJwt(resp.access_token);
      set({
        token: resp.access_token,
        user: payload,
        isAuthenticated: true,
        loading: false,
      });
    } catch (err: any) {
      const msg = err.response?.data?.detail || '登录失败';
      set({ error: msg, loading: false });
      throw err;
    }
  },

  logout: () => {
    localStorage.removeItem('token');
    set({ token: null, user: null, isAuthenticated: false });
  },

  loadFromStorage: () => {
    const token = localStorage.getItem('token');
    if (!token) return;
    const payload = parseJwt(token);
    if (!payload || payload.exp * 1000 < Date.now()) {
      localStorage.removeItem('token');
      return;
    }
    set({ token, user: payload, isAuthenticated: true });
  },
}));
```

- [ ] **Step 2: Create chat store**

Create `frontend/src/stores/chat.ts`:

```typescript
import { create } from 'zustand';
import type { ChatMessage, ToolCallInfo, Session } from '../types/api';

interface ChatState {
  sessions: Session[];
  currentSessionId: string | null;
  messages: ChatMessage[];

  addMessage: (msg: ChatMessage) => void;
  updateLastAssistantMessage: (content: string) => void;
  addToolCall: (toolCall: ToolCallInfo) => void;
  updateToolCall: (tool: string, status: 'success' | 'failed') => void;
  setCurrentSession: (id: string) => void;
  createSession: () => string;
  setMessages: (messages: ChatMessage[]) => void;
}

let nextId = 1;

export const useChatStore = create<ChatState>((set, get) => ({
  sessions: [],
  currentSessionId: null,
  messages: [],

  addMessage: (msg) => {
    set((state) => ({ messages: [...state.messages, msg] }));
  },

  updateLastAssistantMessage: (content) => {
    set((state) => {
      const msgs = [...state.messages];
      const last = msgs[msgs.length - 1];
      if (last && last.role === 'assistant') {
        msgs[msgs.length - 1] = { ...last, content: last.content + content };
      }
      return { messages: msgs };
    });
  },

  addToolCall: (toolCall) => {
    set((state) => {
      const msgs = [...state.messages];
      const last = msgs[msgs.length - 1];
      if (last && last.role === 'assistant') {
        msgs[msgs.length - 1] = {
          ...last,
          toolCalls: [...(last.toolCalls || []), toolCall],
        };
      }
      return { messages: msgs };
    });
  },

  updateToolCall: (tool, status) => {
    set((state) => {
      const msgs = [...state.messages];
      const last = msgs[msgs.length - 1];
      if (last && last.toolCalls) {
        const updated = last.toolCalls.map((tc) =>
          tc.tool === tool && tc.status === 'running'
            ? { ...tc, status, endTime: Date.now() }
            : tc,
        );
        msgs[msgs.length - 1] = { ...last, toolCalls: updated };
      }
      return { messages: msgs };
    });
  },

  setCurrentSession: (id) => {
    set({ currentSessionId: id, messages: [] });
  },

  createSession: () => {
    const id = `session-${nextId++}`;
    const session: Session = {
      id,
      title: '新会话',
      lastMessage: '',
      updatedAt: Date.now(),
    };
    set((state) => ({
      sessions: [session, ...state.sessions],
      currentSessionId: id,
      messages: [],
    }));
    return id;
  },

  setMessages: (messages) => set({ messages }),
}));
```

- [ ] **Step 3: Create theme store**

Create `frontend/src/stores/theme.ts`:

```typescript
import { create } from 'zustand';
import { theme } from 'antd';

interface ThemeState {
  isDark: boolean;
  toggleTheme: () => void;
}

export const useThemeStore = create<ThemeState>((set) => ({
  isDark: localStorage.getItem('theme') === 'dark',
  toggleTheme: () =>
    set((state) => {
      const next = !state.isDark;
      localStorage.setItem('theme', next ? 'dark' : 'light');
      return { isDark: next };
    }),
}));

export function getAntdTheme(isDark: boolean) {
  return {
    algorithm: isDark ? theme.darkAlgorithm : theme.defaultAlgorithm,
    token: {
      colorPrimary: '#1677ff',
    },
  };
}
```

- [ ] **Step 4: Verify TypeScript compiles**

```bash
cd /data/data6T/liang/project/Agent/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/stores/
git commit -m "feat: add Zustand stores for auth, chat, and theme"
```

---

## Task 5: Layout, Routing, and Login Page

Build the app shell: ConfigProvider with theme, React Router with protected routes, AppLayout with sidebar, and the login page.

**Files:**
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/App.tsx`
- Create: `frontend/src/components/AppLayout/index.tsx`
- Create: `frontend/src/components/ProtectedRoute/index.tsx`
- Create: `frontend/src/pages/Login/index.tsx`

- [ ] **Step 1: Create main.tsx**

Create `frontend/src/main.tsx`:

```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import App from './App';
import { useThemeStore, getAntdTheme } from './stores/theme';

function Root() {
  const isDark = useThemeStore((s) => s.isDark);
  return (
    <ConfigProvider locale={zhCN} theme={getAntdTheme(isDark)}>
      <App />
    </ConfigProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
```

- [ ] **Step 2: Create App.tsx with routing**

Create `frontend/src/App.tsx`:

```tsx
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useEffect } from 'react';
import { useAuthStore } from './stores/auth';
import ProtectedRoute from './components/ProtectedRoute';
import AppLayout from './components/AppLayout';
import Login from './pages/Login';
import Chat from './pages/Chat';
import CveSearch from './pages/CveSearch';

export default function App() {
  const loadFromStorage = useAuthStore((s) => s.loadFromStorage);

  useEffect(() => {
    loadFromStorage();
  }, [loadFromStorage]);

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<AppLayout />}>
            <Route path="/chat" element={<Chat />} />
            <Route path="/cve" element={<CveSearch />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/chat" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
```

- [ ] **Step 3: Create ProtectedRoute**

Create `frontend/src/components/ProtectedRoute/index.tsx`:

```tsx
import { Navigate, Outlet } from 'react-router-dom';
import { useAuthStore } from '../../stores/auth';

export default function ProtectedRoute() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <Outlet />;
}
```

- [ ] **Step 4: Create AppLayout**

Create `frontend/src/components/AppLayout/index.tsx`:

```tsx
import { Layout, Menu, Button, Space, Tag, theme as antTheme } from 'antd';
import {
  MessageOutlined,
  BugOutlined,
  BulbOutlined,
  BulbFilled,
  LogoutOutlined,
} from '@ant-design/icons';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useThemeStore } from '../../stores/theme';
import { useAuthStore } from '../../stores/auth';

const { Sider, Content, Header } = Layout;

const menuItems = [
  { key: '/chat', icon: <MessageOutlined />, label: '智能对话' },
  { key: '/cve', icon: <BugOutlined />, label: 'CVE 数据库' },
];

export default function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const { isDark, toggleTheme } = useThemeStore();
  const { user, logout } = useAuthStore();
  const { token: antToken } = antTheme.useToken();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        width={220}
        style={{
          background: isDark ? '#1f1f1f' : '#fff',
          borderRight: `1px solid ${antToken.colorBorderSecondary}`,
        }}
      >
        <div style={{ padding: '16px 24px', fontWeight: 700, fontSize: 18 }}>
          CyberSec Agent
        </div>
        <Menu
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
          style={{ borderRight: 'none', background: 'transparent' }}
        />
        <div style={{ position: 'absolute', bottom: 16, left: 0, right: 0, padding: '0 16px' }}>
          <Space direction="vertical" style={{ width: '100%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Tag color="blue">{user?.role || 'user'}</Tag>
              <Space>
                <Button
                  type="text"
                  icon={isDark ? <BulbFilled /> : <BulbOutlined />}
                  onClick={toggleTheme}
                  size="small"
                />
                <Button
                  type="text"
                  icon={<LogoutOutlined />}
                  onClick={handleLogout}
                  size="small"
                  danger
                />
              </Space>
            </div>
          </Space>
        </div>
      </Sider>
      <Layout>
        <Content style={{ padding: 24 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  );
}
```

- [ ] **Step 5: Create Login page**

Create `frontend/src/pages/Login/index.tsx`:

```tsx
import { Form, Input, Button, Card, Typography, message, Space } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../stores/auth';

const { Title, Text } = Typography;

export default function Login() {
  const navigate = useNavigate();
  const { login, loading, error } = useAuthStore();

  const onFinish = async (values: { username: string; password: string }) => {
    try {
      await login(values.username, values.password);
      message.success('登录成功');
      navigate('/chat');
    } catch {
      message.error(error || '登录失败');
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        background: '#f0f2f5',
      }}
    >
      <Card style={{ width: 400 }}>
        <Space direction="vertical" style={{ width: '100%', textAlign: 'center', marginBottom: 24 }}>
          <Title level={3} style={{ marginBottom: 0 }}>CyberSec Agent</Title>
          <Text type="secondary">网络安全智能分析平台</Text>
        </Space>
        <Form name="login" onFinish={onFinish} autoComplete="off" size="large">
          <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              登录
            </Button>
          </Form.Item>
        </Form>
        <Text type="secondary" style={{ fontSize: 12 }}>
          默认账号: admin / admin123
        </Text>
      </Card>
    </div>
  );
}
```

- [ ] **Step 6: Create placeholder pages**

Create `frontend/src/pages/Chat/index.tsx`:

```tsx
export default function Chat() {
  return <div>Chat page - coming in Task 6</div>;
}
```

Create `frontend/src/pages/CveSearch/index.tsx`:

```tsx
export default function CveSearch() {
  return <div>CVE Search page - coming in Task 7</div>;
}
```

- [ ] **Step 7: Verify TypeScript compiles**

```bash
cd /data/data6T/liang/project/Agent/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 8: Commit**

```bash
git add frontend/src/
git commit -m "feat: add layout, routing, protected routes, and login page"
```

---

## Task 6: Chat Page — WebSocket + Messages

Implement the full chat page with WebSocket connection, message display, and tool progress.

**Files:**
- Create: `frontend/src/hooks/useWebSocket.ts`
- Create: `frontend/src/components/ChatMessage/index.tsx`
- Create: `frontend/src/components/ToolProgress/index.tsx`
- Modify: `frontend/src/pages/Chat/index.tsx` (replace placeholder)
- Create: `frontend/src/pages/Chat/SessionList.tsx`
- Create: `frontend/src/pages/Chat/MessageList.tsx`
- Create: `frontend/src/pages/Chat/MessageInput.tsx`

- [ ] **Step 1: Create useWebSocket hook**

Create `frontend/src/hooks/useWebSocket.ts`:

```typescript
import { useRef, useState, useCallback, useEffect } from 'react';
import type { WSEvent } from '../types/api';

interface UseWebSocketReturn {
  connected: boolean;
  sendMessage: (content: string, sessionId?: string) => void;
  events: WSEvent[];
  clearEvents: () => void;
}

export function useWebSocket(token: string | null): UseWebSocketReturn {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<WSEvent[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();

  const connect = useCallback(() => {
    if (!token || wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(`ws://${window.location.hostname}:8000/api/v1/agent/chat?token=${token}`);

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      // Auto-reconnect after 3s
      reconnectTimer.current = setTimeout(() => connect(), 3000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as WSEvent;
        setEvents((prev) => [...prev, data]);
      } catch {
        // ignore parse errors
      }
    };

    wsRef.current = ws;
  }, [token]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const sendMessage = useCallback((content: string, sessionId?: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'chat', content, session_id: sessionId }));
    }
  }, []);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { connected, sendMessage, events, clearEvents };
}
```

- [ ] **Step 2: Create ChatMessage component**

Create `frontend/src/components/ChatMessage/index.tsx`:

```tsx
import { Avatar, Typography } from 'antd';
import { UserOutlined, RobotOutlined } from '@ant-design/icons';
import type { ChatMessage as ChatMessageType } from '../../types/api';
import ToolProgress from '../ToolProgress';

const { Text } = Typography;

interface Props {
  message: ChatMessageType;
}

export default function ChatMessage({ message }: Props) {
  const isUser = message.role === 'user';

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: isUser ? 'flex-end' : 'flex-start',
        marginBottom: 16,
        gap: 8,
      }}
    >
      {!isUser && <Avatar icon={<RobotOutlined />} style={{ backgroundColor: '#1677ff' }} />}
      <div style={{ maxWidth: '70%' }}>
        {message.toolCalls && message.toolCalls.length > 0 && (
          <ToolProgress toolCalls={message.toolCalls} />
        )}
        <div
          style={{
            padding: '10px 14px',
            borderRadius: 12,
            background: isUser ? '#1677ff' : '#f5f5f5',
            color: isUser ? '#fff' : '#000',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}
        >
          {message.content || '...'}
        </div>
        {message.tokenCount !== undefined && (
          <Text type="secondary" style={{ fontSize: 12, marginTop: 4, display: 'block' }}>
            tokens: {message.tokenCount}
          </Text>
        )}
      </div>
      {isUser && <Avatar icon={<UserOutlined />} style={{ backgroundColor: '#87d068' }} />}
    </div>
  );
}
```

- [ ] **Step 3: Create ToolProgress component**

Create `frontend/src/components/ToolProgress/index.tsx`:

```tsx
import { Tag, Space, Spin } from 'antd';
import { CheckCircleFilled, CloseCircleFilled, LoadingOutlined } from '@ant-design/icons';
import type { ToolCallInfo } from '../../types/api';

interface Props {
  toolCalls: ToolCallInfo[];
}

const statusConfig = {
  running: { color: 'processing', icon: <Spin indicator={<LoadingOutlined spin />} size="small" /> },
  success: { color: 'success', icon: <CheckCircleFilled /> },
  failed: { color: 'error', icon: <CloseCircleFilled /> },
};

export default function ToolProgress({ toolCalls }: Props) {
  return (
    <div style={{ marginBottom: 8 }}>
      <Space direction="vertical" size={4} style={{ width: '100%' }}>
        {toolCalls.map((tc, i) => {
          const config = statusConfig[tc.status];
          const elapsed = tc.endTime ? ((tc.endTime - tc.startTime) / 1000).toFixed(1) : null;
          return (
            <div
              key={`${tc.tool}-${i}`}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '4px 8px',
                borderRadius: 6,
                background: '#fafafa',
                fontSize: 13,
              }}
            >
              {config.icon}
              <Tag color={config.color}>{tc.tool}</Tag>
              <span style={{ color: '#999' }}>
                {tc.status === 'running' ? '执行中...' : elapsed ? `${elapsed}s` : ''}
              </span>
            </div>
          );
        })}
      </Space>
    </div>
  );
}
```

- [ ] **Step 4: Create SessionList component**

Create `frontend/src/pages/Chat/SessionList.tsx`:

```tsx
import { Button, List, Typography } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useChatStore } from '../../stores/chat';
import dayjs from 'dayjs';

const { Text } = Typography;

export default function SessionList() {
  const { sessions, currentSessionId, setCurrentSession, createSession } = useChatStore();

  return (
    <div style={{ width: 240, borderRight: '1px solid #f0f0f0', height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} block onClick={createSession}>
          新会话
        </Button>
      </div>
      <List
        style={{ flex: 1, overflow: 'auto' }}
        dataSource={sessions}
        renderItem={(session) => (
          <List.Item
            onClick={() => setCurrentSession(session.id)}
            style={{
              padding: '10px 16px',
              cursor: 'pointer',
              background: session.id === currentSessionId ? '#e6f4ff' : 'transparent',
            }}
          >
            <List.Item.Meta
              title={<Text ellipsis style={{ fontSize: 14 }}>{session.title}</Text>}
              description={
                <Text type="secondary" ellipsis style={{ fontSize: 12 }}>
                  {dayjs(session.updatedAt).format('MM-DD HH:mm')}
                </Text>
              }
            />
          </List.Item>
        )}
      />
    </div>
  );
}
```

- [ ] **Step 5: Create MessageList component**

Create `frontend/src/pages/Chat/MessageList.tsx`:

```tsx
import { useEffect, useRef } from 'react';
import { Empty } from 'antd';
import ChatMessage from '../../components/ChatMessage';
import { useChatStore } from '../../stores/chat';

export default function MessageList() {
  const messages = useChatStore((s) => s.messages);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  if (messages.length === 0) {
    return (
      <div style={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
        <Empty description="发送消息开始对话" />
      </div>
    );
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '16px 0' }}>
      {messages.map((msg) => (
        <ChatMessage key={msg.id} message={msg} />
      ))}
      <div ref={bottomRef} />
    </div>
  );
}
```

- [ ] **Step 6: Create MessageInput component**

Create `frontend/src/pages/Chat/MessageInput.tsx`:

```tsx
import { useState, useRef, useEffect } from 'react';
import { Input, Button, Space } from 'antd';
import { SendOutlined } from '@ant-design/icons';

const { TextArea } = Input;

interface Props {
  onSend: (content: string) => void;
  disabled: boolean;
}

export default function MessageInput({ onSend, disabled }: Props) {
  const [value, setValue] = useState('');
  const ref = useRef<any>(null);

  useEffect(() => {
    if (!disabled) ref.current?.focus();
  }, [disabled]);

  const handleSend = () => {
    const trimmed = value.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    setValue('');
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div style={{ padding: '12px 0', borderTop: '1px solid #f0f0f0' }}>
      <Space.Compact style={{ width: '100%' }}>
        <TextArea
          ref={ref}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="输入消息... (Enter 发送, Shift+Enter 换行)"
          autoSize={{ minRows: 1, maxRows: 4 }}
          disabled={disabled}
          style={{ resize: 'none' }}
        />
        <Button
          type="primary"
          icon={<SendOutlined />}
          onClick={handleSend}
          disabled={disabled || !value.trim()}
          style={{ height: 'auto' }}
        />
      </Space.Compact>
    </div>
  );
}
```

- [ ] **Step 7: Assemble Chat page**

Replace `frontend/src/pages/Chat/index.tsx`:

```tsx
import { useEffect, useRef } from 'react';
import { Tag, Space, Typography } from 'antd';
import { LinkOutlined, DisconnectOutlined } from '@ant-design/icons';
import { useAuthStore } from '../../stores/auth';
import { useChatStore } from '../../stores/chat';
import { useWebSocket } from '../../hooks/useWebSocket';
import SessionList from './SessionList';
import MessageList from './MessageList';
import MessageInput from './MessageInput';
import type { WSEvent } from '../../types/api';

const { Text } = Typography;

export default function Chat() {
  const token = useAuthStore((s) => s.token);
  const { connected, sendMessage, events, clearEvents } = useWebSocket(token);
  const { currentSessionId, addMessage, updateLastAssistantMessage, addToolCall, updateToolCall, createSession } = useChatStore();
  const waitingRef = useRef(false);

  // Process WebSocket events
  useEffect(() => {
    if (events.length === 0) return;

    const latest = events[events.length - 1] as WSEvent;

    switch (latest.type) {
      case 'tool_call':
        addToolCall({ tool: latest.tool, status: 'running', startTime: Date.now() });
        break;
      case 'tool_result':
        updateToolCall(latest.tool, latest.success ? 'success' : 'failed');
        break;
      case 'token':
        updateLastAssistantMessage(latest.content);
        break;
      case 'done':
        waitingRef.current = false;
        break;
      case 'error':
        addMessage({
          id: `error-${Date.now()}`,
          role: 'assistant',
          content: `错误: ${latest.message}`,
          timestamp: Date.now(),
        });
        waitingRef.current = false;
        break;
    }
  }, [events]);

  const handleSend = (content: string) => {
    let sid = currentSessionId;
    if (!sid) {
      sid = createSession();
    }

    // Add user message
    addMessage({
      id: `user-${Date.now()}`,
      role: 'user',
      content,
      timestamp: Date.now(),
    });

    // Add placeholder assistant message
    addMessage({
      id: `assistant-${Date.now()}`,
      role: 'assistant',
      content: '',
      timestamp: Date.now(),
      toolCalls: [],
    });

    clearEvents();
    waitingRef.current = true;
    sendMessage(content, sid);
  };

  const isWaiting = waitingRef.current;

  return (
    <div style={{ display: 'flex', height: 'calc(100vh - 48px)', background: '#fff', borderRadius: 8 }}>
      <SessionList />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '0 16px' }}>
        <div style={{ padding: '12px 0', borderBottom: '1px solid #f0f0f0', display: 'flex', justifyContent: 'space-between' }}>
          <Text strong>智能对话</Text>
          <Space>
            {connected ? (
              <Tag icon={<LinkOutlined />} color="success">已连接</Tag>
            ) : (
              <Tag icon={<DisconnectOutlined />} color="error">未连接</Tag>
            )}
          </Space>
        </div>
        <MessageList />
        <MessageInput onSend={handleSend} disabled={isWaiting || !connected} />
      </div>
    </div>
  );
}
```

- [ ] **Step 8: Verify TypeScript compiles**

```bash
cd /data/data6T/liang/project/Agent/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 9: Commit**

```bash
git add frontend/src/
git commit -m "feat: implement chat page with WebSocket, messages, and tool progress"
```

---

## Task 7: CVE Search Page

Implement the CVE database search page with table, detail drawer, and statistics charts.

**Files:**
- Modify: `frontend/src/pages/CveSearch/index.tsx` (replace placeholder)
- Create: `frontend/src/pages/CveSearch/CveTable.tsx`
- Create: `frontend/src/pages/CveSearch/CveDetail.tsx`
- Create: `frontend/src/pages/CveSearch/StatsPanel.tsx`

- [ ] **Step 1: Create StatsPanel component**

Create `frontend/src/pages/CveSearch/StatsPanel.tsx`:

```tsx
import { Card, Statistic, Row, Col } from 'antd';
import ReactECharts from 'echarts-for-react';
import type { CveStatsResponse } from '../../types/api';

interface Props {
  stats: CveStatsResponse | null;
  loading: boolean;
}

const severityColors: Record<string, string> = {
  CRITICAL: '#ff4d4f',
  HIGH: '#fa8c16',
  MEDIUM: '#fadb14',
  LOW: '#1677ff',
  UNKNOWN: '#d9d9d9',
};

export default function StatsPanel({ stats, loading }: Props) {
  if (!stats) return null;

  const pieData = Object.entries(stats.by_severity).map(([name, value]) => ({
    name,
    value,
    itemStyle: { color: severityColors[name] || '#d9d9d9' },
  }));

  const option = {
    tooltip: { trigger: 'item' as const },
    legend: { bottom: 0 },
    series: [
      {
        type: 'pie',
        radius: ['40%', '70%'],
        avoidLabelOverlap: false,
        label: { show: false },
        data: pieData,
      },
    ],
  };

  return (
    <Card title="CVE 统计" loading={loading} style={{ marginBottom: 16 }}>
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={8}>
          <Statistic title="总计" value={stats.total} />
        </Col>
        <Col span={8}>
          <Statistic
            title="严重"
            value={stats.by_severity.CRITICAL || 0}
            valueStyle={{ color: '#ff4d4f' }}
          />
        </Col>
        <Col span={8}>
          <Statistic
            title="高危"
            value={stats.by_severity.HIGH || 0}
            valueStyle={{ color: '#fa8c16' }}
          />
        </Col>
      </Row>
      <ReactECharts option={option} style={{ height: 200 }} />
    </Card>
  );
}
```

- [ ] **Step 2: Create CveDetail drawer**

Create `frontend/src/pages/CveSearch/CveDetail.tsx`:

```tsx
import { Drawer, Descriptions, Tag, Typography } from 'antd';
import type { CveItem } from '../../types/api';

const { Paragraph } = Typography;

const severityColors: Record<string, string> = {
  CRITICAL: 'red',
  HIGH: 'orange',
  MEDIUM: 'gold',
  LOW: 'blue',
  UNKNOWN: 'default',
};

interface Props {
  cve: CveItem | null;
  open: boolean;
  onClose: () => void;
}

export default function CveDetail({ cve, open, onClose }: Props) {
  if (!cve) return null;

  return (
    <Drawer
      title={cve.cve_id}
      open={open}
      onClose={onClose}
      width={500}
    >
      <Descriptions column={1} bordered size="small">
        <Descriptions.Item label="CVE ID">{cve.cve_id}</Descriptions.Item>
        <Descriptions.Item label="严重程度">
          <Tag color={severityColors[cve.severity] || 'default'}>{cve.severity}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label="CVSS 分数">{cve.cvss_score}</Descriptions.Item>
        <Descriptions.Item label="发布日期">{cve.published || 'N/A'}</Descriptions.Item>
        <Descriptions.Item label="描述">
          <Paragraph style={{ margin: 0 }}>{cve.description || 'N/A'}</Paragraph>
        </Descriptions.Item>
      </Descriptions>
    </Drawer>
  );
}
```

- [ ] **Step 3: Create CveTable component**

Create `frontend/src/pages/CveSearch/CveTable.tsx`:

```tsx
import { Table, Tag, Progress } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { CveItem } from '../../types/api';

const severityColors: Record<string, string> = {
  CRITICAL: 'red',
  HIGH: 'orange',
  MEDIUM: 'gold',
  LOW: 'blue',
  UNKNOWN: 'default',
};

interface Props {
  data: CveItem[];
  loading: boolean;
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number, pageSize: number) => void;
  onRowClick: (record: CveItem) => void;
}

const columns: ColumnsType<CveItem> = [
  {
    title: 'CVE ID',
    dataIndex: 'cve_id',
    key: 'cve_id',
    render: (text: string) => <a style={{ fontWeight: 600 }}>{text}</a>,
  },
  {
    title: '严重程度',
    dataIndex: 'severity',
    key: 'severity',
    render: (sev: string) => <Tag color={severityColors[sev] || 'default'}>{sev}</Tag>,
  },
  {
    title: 'CVSS',
    dataIndex: 'cvss_score',
    key: 'cvss_score',
    sorter: (a, b) => a.cvss_score - b.cvss_score,
    render: (score: number) => (
      <Progress
        percent={score * 10}
        size="small"
        strokeColor={score >= 9 ? '#ff4d4f' : score >= 7 ? '#fa8c16' : score >= 4 ? '#fadb14' : '#1677ff'}
        format={() => score.toFixed(1)}
      />
    ),
  },
  {
    title: '发布日期',
    dataIndex: 'published',
    key: 'published',
    render: (text: string) => text ? new Date(text).toLocaleDateString() : 'N/A',
  },
  {
    title: '摘要',
    dataIndex: 'description',
    key: 'description',
    ellipsis: true,
  },
];

export default function CveTable({ data, loading, total, page, pageSize, onPageChange, onRowClick }: Props) {
  return (
    <Table
      columns={columns}
      dataSource={data}
      rowKey="id"
      loading={loading}
      pagination={{
        current: page,
        pageSize,
        total,
        onChange: onPageChange,
        showSizeChanger: true,
        showTotal: (t) => `共 ${t} 条`,
      }}
      onRow={(record) => ({
        onClick: () => onRowClick(record),
        style: { cursor: 'pointer' },
      })}
      size="middle"
    />
  );
}
```

- [ ] **Step 4: Assemble CveSearch page**

Replace `frontend/src/pages/CveSearch/index.tsx`:

```tsx
import { useState, useEffect, useCallback } from 'react';
import { Input, Select, Space, Row, Col, message } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import { listCves, getCveStats, getCve } from '../../api/cve';
import type { CveItem, CveStatsResponse, CveListResponse } from '../../types/api';
import CveTable from './CveTable';
import CveDetail from './CveDetail';
import StatsPanel from './StatsPanel';

const { Search } = Input;

const severityOptions = [
  { label: '全部', value: '' },
  { label: 'CRITICAL', value: 'CRITICAL' },
  { label: 'HIGH', value: 'HIGH' },
  { label: 'MEDIUM', value: 'MEDIUM' },
  { label: 'LOW', value: 'LOW' },
];

export default function CveSearch() {
  const [keyword, setKeyword] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [listData, setListData] = useState<CveListResponse | null>(null);
  const [stats, setStats] = useState<CveStatsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [statsLoading, setStatsLoading] = useState(false);
  const [selectedCve, setSelectedCve] = useState<CveItem | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listCves({
        page,
        page_size: pageSize,
        severity: severity || undefined,
        keyword: keyword || undefined,
      });
      setListData(data);
    } catch {
      message.error('查询失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, severity, keyword]);

  const fetchStats = useCallback(async () => {
    setStatsLoading(true);
    try {
      const data = await getCveStats();
      setStats(data);
    } catch {
      // silent
    } finally {
      setStatsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleSearch = (value: string) => {
    setKeyword(value);
    setPage(1);
  };

  const handleRowClick = async (record: CveItem) => {
    try {
      const detail = await getCve(record.cve_id);
      setSelectedCve(detail);
      setDrawerOpen(true);
    } catch {
      message.error('获取详情失败');
    }
  };

  return (
    <div>
      <Row gutter={16}>
        <Col span={16}>
          <Space style={{ marginBottom: 16 }} size="middle">
            <Search
              placeholder="输入 CVE ID 或关键词"
              onSearch={handleSearch}
              style={{ width: 300 }}
              enterButton={<SearchOutlined />}
              allowClear
            />
            <Select
              value={severity}
              onChange={(v) => { setSeverity(v); setPage(1); }}
              options={severityOptions}
              style={{ width: 140 }}
              placeholder="严重程度"
            />
          </Space>
          <CveTable
            data={listData?.items || []}
            loading={loading}
            total={listData?.total || 0}
            page={page}
            pageSize={pageSize}
            onPageChange={(p, ps) => { setPage(p); setPageSize(ps); }}
            onRowClick={handleRowClick}
          />
        </Col>
        <Col span={8}>
          <StatsPanel stats={stats} loading={statsLoading} />
        </Col>
      </Row>
      <CveDetail cve={selectedCve} open={drawerOpen} onClose={() => setDrawerOpen(false)} />
    </div>
  );
}
```

- [ ] **Step 5: Verify TypeScript compiles**

```bash
cd /data/data6T/liang/project/Agent/frontend && npx tsc --noEmit
```

Expected: No errors.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/
git commit -m "feat: implement CVE search page with table, detail drawer, and stats charts"
```

---

## Task 8: Integration Test — Manual Verification

Verify the full stack works end-to-end.

- [ ] **Step 1: Start the backend server**

```bash
cd /data/data6T/liang/project/Agent/backend
lsof -ti:8000 | xargs kill 2>/dev/null
nohup /data/data6T/liang/Anaconda/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > /tmp/agent_server.log 2>&1 &
```

Wait for "RAG index empty, importing CVEs from NVD..." and "Imported 200 CVEs into RAG BM25 index" in logs.

- [ ] **Step 2: Verify CVE API works**

```bash
curl -s http://localhost:8000/api/v1/cve/stats | python3 -m json.tool
curl -s "http://localhost:8000/api/v1/cve/list?page=1&page_size=3" | python3 -m json.tool
```

Expected: JSON responses with CVE data.

- [ ] **Step 3: Start the frontend dev server**

```bash
cd /data/data6T/liang/project/Agent/frontend && npm run dev
```

Expected: Vite dev server running on http://localhost:3000

- [ ] **Step 4: Open browser and verify**

1. Open http://localhost:3000 → should redirect to /login
2. Login with admin/admin123 → should redirect to /chat
3. Send a message "你好" → should get AI response
4. Send "帮我搜索 CVE-2024-3400" → should see tool call progress
5. Navigate to CVE 数据库 → should see CVE table with stats
6. Click a CVE row → should open detail drawer
7. Toggle theme → should switch light/dark

- [ ] **Step 5: Run all backend tests**

```bash
cd /data/data6T/liang/project/Agent && /data/data6T/liang/Anaconda/bin/python -m pytest tests/ -q --tb=short
```

Expected: All tests pass.

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "feat: Phase 2 frontend complete — chat, CVE search, theme switching"
```

---

## Task Summary

| Task | Description | Files |
|------|-------------|-------|
| 1.1 | BM25 metadata + list/stats methods | `bm25_search.py`, `test_rag.py` |
| 1.2 | Importer passes metadata | `importer.py` |
| 1.3 | CVE REST API endpoints | `api/cve.py`, `main.py`, `test_cve_api.py` |
| 2 | Frontend scaffolding | `frontend/` (package.json, vite, tsconfig) |
| 3 | Types + API client | `types/api.ts`, `api/*.ts` |
| 4 | Zustand stores + theme | `stores/*.ts` |
| 5 | Layout + routing + login | `main.tsx`, `App.tsx`, `AppLayout`, `Login` |
| 6 | Chat page + WebSocket | `useWebSocket`, `ChatMessage`, `ToolProgress`, `Chat/*` |
| 7 | CVE search page | `CveSearch/*` |
| 8 | Integration verification | Manual testing |
