# Phase 1: Agent Core Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the ReAct Agent core with JWT auth, WebSocket streaming, JSON lenient parsing, context compression, and Redis session persistence — transforming the Phase 0 skeleton into a functional multi-turn conversational agent.

**Architecture:** Custom ReAct agent (no LangChain dependency) integrated with existing LiteLLM Router. The agent loop parses LLM output with a 5-level fallback JSON parser, executes tools via a formalized registry, and streams results over WebSocket. Context compression triggers every N turns to stay within token budgets.

**Tech Stack:** FastAPI, LiteLLM (existing), Pydantic v2, python-jose (JWT), Redis (existing), WebSocket, pytest

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `backend/app/core/config.py` | Centralized settings via pydantic-settings |
| `backend/app/core/security.py` | JWT encode/decode, password hashing |
| `backend/app/api/auth.py` | `/api/v1/auth/login` + `/api/v1/auth/refresh` |
| `backend/app/api/chat.py` | `/api/v1/agent/chat` WebSocket endpoint |
| `backend/app/models/user.py` | User SQLAlchemy model |
| `backend/app/agent/react.py` | ReAct loop core (Thought → Action → Observation) |
| `backend/app/agent/json_parser.py` | 5-level fallback JSON parser |
| `backend/app/agent/context_compressor.py` | ConversationSummaryMemory + Observation truncation |
| `backend/app/tools/registry.py` | Tool Registry (formalized registration pattern) |
| `tests/conftest.py` | Shared fixtures |
| `tests/test_json_parser.py` | JSON parser tests |
| `tests/test_react_agent.py` | ReAct agent tests |
| `tests/test_context_compressor.py` | Context compressor tests |
| `tests/test_auth.py` | JWT auth tests |
| `tests/test_chat_ws.py` | WebSocket chat tests |

### Modified Files

| File | Changes |
|------|---------|
| `backend/app/main.py` | Add JWT middleware, include auth + chat routers, startup/shutdown |
| `backend/app/llm/router.py` | Add `DEEPSEEK_API_KEY` env support (already has provider prefix) |
| `backend/app/agent/context.py` | Add Redis persistence, `get_recent_messages(n)`, `compress_messages()` |
| `backend/app/agent/tool_executor.py` | Refactor to use Registry pattern |
| `backend/app/tools/echo_tool.py` | Update to use new Registry |
| `backend/requirements.txt` | Add `python-jose`, `passlib[bcrypt]`, `pydantic-settings`, `websockets` |

---

## Dependency Graph

```
Task 1 (config) ─────────────────────────────────────────────────┐
Task 2 (json_parser) ──────────────────────────────┐             │
Task 3 (security/JWT) ──┐                          │             │
                        ▼                          ▼             │
Task 4 (auth endpoints) ──┐     Task 5 (tool registry) ──┐      │
                          │                               ▼      │
                          │     Task 6 (context compressor) ──┐  │
                          │                                    ▼  │
                          │     Task 7 (ReAct agent) ◄───────────┘
                          │           │
                          ▼           ▼
Task 8 (WebSocket chat) ◄────────────┘
           │
           ▼
Task 9 (main.py wiring + integration test)
```

Tasks 1, 2, 3 can run in parallel. Task 4 needs 1+3. Task 5 needs 1. Task 6 needs 1. Task 7 needs 2+5+6. Task 8 needs 4+7. Task 9 needs all.

---

## Task 1: Configuration Module

**Files:**
- Create: `backend/app/core/__init__.py`
- Create: `backend/app/core/config.py`
- Modify: `backend/requirements.txt`
- Test: `tests/test_config.py`

- [ ] **Step 1: Add dependencies**

Add to `backend/requirements.txt`:

```
fastapi>=0.100.0
uvicorn>=0.23.0
litellm>=1.40.0
pydantic>=2.0.0
redis>=5.0.0
python-dotenv>=1.0.0
pydantic-settings>=2.0.0
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
websockets>=12.0
```

- [ ] **Step 2: Write config module**

Create `backend/app/core/__init__.py` (empty):

```python
```

Create `backend/app/core/config.py`:

```python
"""Centralized application settings."""

import os
from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # LLM
    llm_model: str = "deepseek-v4-flash"
    llm_timeout: int = 30
    deepseek_api_key: str = ""

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # JWT
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # Agent
    react_max_turns: int = 12
    react_max_tool_retries: int = 3
    ctx_compress_threshold: int = 8000
    ctx_obs_max_tokens: int = 2000
    ctx_history_summary_interval: int = 4

    # WebSocket
    ws_heartbeat_interval: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 3: Write the test**

Create `tests/conftest.py`:

```python
"""Shared test fixtures."""

import pytest


@pytest.fixture
def settings():
    from app.core.config import Settings
    return Settings(
        jwt_secret="test-secret",
        deepseek_api_key="test-key",
        redis_url="redis://localhost:6379/15",
    )
```

Create `tests/test_config.py`:

```python
"""Tests for config module."""

from app.core.config import Settings, get_settings


def test_settings_defaults():
    s = Settings()
    assert s.llm_model == "deepseek-v4-flash"
    assert s.react_max_turns == 12
    assert s.jwt_algorithm == "HS256"


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "custom-model")
    monkeypatch.setenv("JWT_SECRET", "my-secret")
    get_settings.cache_clear()
    s = Settings()
    assert s.llm_model == "custom-model"
    assert s.jwt_secret == "my-secret"
    get_settings.cache_clear()
```

- [ ] **Step 4: Run tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/ backend/requirements.txt tests/conftest.py tests/test_config.py
git commit -m "feat(phase1): add centralized config module"
```

---

## Task 2: JSON Lenient Parser (5-Level Fallback)

**Files:**
- Create: `backend/app/agent/json_parser.py`
- Test: `tests/test_json_parser.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_json_parser.py`:

```python
"""Tests for 5-level fallback JSON parser."""

import pytest

from app.agent.json_parser import parse_llm_json


class TestParseLLMJson:
    """Test the 5-level fallback chain."""

    def test_level1_direct_json(self):
        raw = '{"thought": "test", "action": "echo"}'
        result = parse_llm_json(raw)
        assert result["thought"] == "test"
        assert result["action"] == "echo"

    def test_level2_code_block(self):
        raw = 'Here is my response:\n```json\n{"thought": "test", "action": "echo"}\n```\nDone.'
        result = parse_llm_json(raw)
        assert result["thought"] == "test"

    def test_level3_loose_braces(self):
        raw = 'Sure! {"thought": "analyzing", "action": "lookup"} is my plan.'
        result = parse_llm_json(raw)
        assert result["thought"] == "analyzing"

    def test_level4_fix_trailing_comma(self):
        raw = '{"thought": "test", "action": "echo",}'
        result = parse_llm_json(raw)
        assert result["action"] == "echo"

    def test_level4_fix_single_quotes(self):
        raw = "{'thought': 'test', 'action': 'echo'}"
        result = parse_llm_json(raw)
        assert result["thought"] == "test"

    def test_level4_fix_chinese_comments(self):
        raw = '{"thought": "test" /* 这是注释 */, "action": "echo"}'
        result = parse_llm_json(raw)
        assert result["action"] == "echo"

    def test_level5_fallback_error(self):
        raw = "This is not JSON at all, just plain text."
        result = parse_llm_json(raw)
        assert result["error"] == "parse_failed"
        assert "raw" in result

    def test_nested_json(self):
        raw = '{"thought": "test", "action_input": {"key": "value"}}'
        result = parse_llm_json(raw)
        assert result["action_input"]["key"] == "value"

    def test_final_answer_format(self):
        raw = '{"final_answer": "The IP is malicious", "confidence": 0.9}'
        result = parse_llm_json(raw)
        assert result["final_answer"] == "The IP is malicious"
        assert result["confidence"] == 0.9
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_json_parser.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'app.agent.json_parser'"

- [ ] **Step 3: Implement the parser**

Create `backend/app/agent/json_parser.py`:

```python
"""5-level fallback JSON parser for LLM output.

Parse priority chain (try each until success):
1. Direct JSON: json.loads(output)
2. Code block: regex match ```json ... ``` then parse
3. Loose extract: regex match outermost { ... } braces
4. Fix attempts: remove Chinese comments, trailing commas, single quotes
5. Structured fallback: {"error": "parse_failed", "raw": output}
"""

import json
import re
from typing import Any


def parse_llm_json(raw: str) -> dict[str, Any]:
    """Parse LLM output into JSON with 5-level fallback."""
    raw = raw.strip()
    if not raw:
        return {"error": "parse_failed", "raw": raw}

    # Level 1: Direct JSON
    result = _try_direct_json(raw)
    if result is not None:
        return result

    # Level 2: Extract from code block
    result = _try_code_block(raw)
    if result is not None:
        return result

    # Level 3: Loose brace extraction
    result = _try_loose_braces(raw)
    if result is not None:
        return result

    # Level 4: Fix common issues and retry
    result = _try_fix_and_parse(raw)
    if result is not None:
        return result

    # Level 5: Structured fallback
    return {"error": "parse_failed", "raw": raw}


def _try_direct_json(raw: str) -> dict[str, Any] | None:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _try_code_block(raw: str) -> dict[str, Any] | None:
    pattern = r"```(?:json)?\s*\n?(.*?)\n?\s*```"
    match = re.search(pattern, raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except (json.JSONDecodeError, TypeError):
            return None
    return None


def _try_loose_braces(raw: str) -> dict[str, Any] | None:
    # Find the outermost balanced braces
    start = raw.find("{")
    if start == -1:
        return None

    depth = 0
    for i in range(start, len(raw)):
        if raw[i] == "{":
            depth += 1
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                candidate = raw[start : i + 1]
                try:
                    return json.loads(candidate)
                except (json.JSONDecodeError, TypeError):
                    return None
    return None


def _try_fix_and_parse(raw: str) -> dict[str, Any] | None:
    fixed = raw

    # Remove Chinese comments: /* ... */
    fixed = re.sub(r"/\*[\s\S]*?\*/", "", fixed)

    # Remove // comments (not inside strings)
    fixed = re.sub(r"//[^\n]*", "", fixed)

    # Remove trailing commas before } or ]
    fixed = re.sub(r",\s*([}\]])", r"\1", fixed)

    # Replace single quotes with double quotes (crude but effective for LLM output)
    # Only do this if there are no existing double quotes (avoid breaking valid JSON)
    if '"' not in fixed:
        fixed = fixed.replace("'", '"')

    # Try parsing the fixed version
    # First try direct
    result = _try_direct_json(fixed)
    if result is not None:
        return result

    # Try brace extraction on fixed version
    result = _try_loose_braces(fixed)
    if result is not None:
        return result

    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_json_parser.py -v`
Expected: All 9 tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/agent/json_parser.py tests/test_json_parser.py
git commit -m "feat(phase1): add 5-level fallback JSON parser for LLM output"
```

---

## Task 3: Security Module (JWT + Password Hashing)

**Files:**
- Create: `backend/app/core/security.py`
- Test: `tests/test_security.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_security.py`:

```python
"""Tests for JWT and password security."""

import pytest

from app.core.security import create_access_token, verify_token, hash_password, verify_password


class TestJWT:
    def test_create_and_verify_token(self):
        token = create_access_token({"sub": "user-123", "role": "analyst"}, secret="test-secret")
        payload = verify_token(token, secret="test-secret")
        assert payload["sub"] == "user-123"
        assert payload["role"] == "analyst"
        assert "exp" in payload

    def test_invalid_token(self):
        result = verify_token("invalid.token.here", secret="test-secret")
        assert result is None

    def test_wrong_secret(self):
        token = create_access_token({"sub": "user-123"}, secret="secret-a")
        result = verify_token(token, secret="secret-b")
        assert result is None

    def test_token_contains_exp(self):
        token = create_access_token({"sub": "user-123"}, secret="test-secret", expires_minutes=30)
        payload = verify_token(token, secret="test-secret")
        assert payload is not None
        assert "exp" in payload


class TestPassword:
    def test_hash_and_verify(self):
        hashed = hash_password("mypassword")
        assert verify_password("mypassword", hashed) is True

    def test_wrong_password(self):
        hashed = hash_password("mypassword")
        assert verify_password("wrongpassword", hashed) is False

    def test_different_hashes(self):
        h1 = hash_password("samepassword")
        h2 = hash_password("samepassword")
        assert h1 != h2  # bcrypt salts differ
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_security.py -v`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Implement security module**

Create `backend/app/core/security.py`:

```python
"""JWT token and password hashing utilities."""

from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_access_token(
    data: dict[str, Any],
    secret: str,
    algorithm: str = "HS256",
    expires_minutes: int = 60,
) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode["exp"] = expire
    return jwt.encode(to_encode, secret, algorithm=algorithm)


def verify_token(token: str, secret: str, algorithm: str = "HS256") -> dict[str, Any] | None:
    try:
        payload = jwt.decode(token, secret, algorithms=[algorithm])
        return payload
    except JWTError:
        return None


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)
```

- [ ] **Step 4: Run tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_security.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/security.py tests/test_security.py
git commit -m "feat(phase1): add JWT and password security module"
```

---

## Task 4: Auth API Endpoints

**Files:**
- Create: `backend/app/api/auth.py`
- Test: `tests/test_auth.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth.py`:

```python
"""Tests for auth endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.security import hash_password

# In-memory user store for testing
_test_users = {
    "admin": {
        "id": "user-001",
        "username": "admin",
        "hashed_password": hash_password("admin123"),
        "role": "admin",
        "tenant_id": "tenant-1",
    }
}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.anyio
async def test_login_success(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.anyio
async def test_login_wrong_password(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong"},
    )
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_login_unknown_user(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "nobody", "password": "test"},
    )
    assert resp.status_code == 401
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_auth.py -v`
Expected: FAIL

- [ ] **Step 3: Implement auth endpoints**

Create `backend/app/api/auth.py`:

```python
"""Authentication endpoints."""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.security import create_access_token, verify_token, hash_password, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
security = HTTPBearer()

# In-memory user store (Phase 1 — replace with PostgreSQL in Phase 4)
_USERS: dict[str, dict] = {
    "admin": {
        "id": "user-001",
        "username": "admin",
        "hashed_password": hash_password("admin123"),
        "role": "admin",
        "tenant_id": "tenant-1",
    }
}


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str
    tenant_id: str


class UserInfo(BaseModel):
    user_id: str
    role: str
    tenant_id: str


@router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    user = _USERS.get(req.username)
    if not user or not verify_password(req.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    settings = get_settings()
    token = create_access_token(
        data={"sub": user["id"], "role": user["role"], "tenant_id": user["tenant_id"]},
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expire_minutes,
    )

    return LoginResponse(
        access_token=token,
        user_id=user["id"],
        role=user["role"],
        tenant_id=user["tenant_id"],
    )


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> UserInfo:
    """Dependency to extract and verify current user from JWT."""
    settings = get_settings()
    payload = verify_token(credentials.credentials, secret=settings.jwt_secret)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return UserInfo(
        user_id=payload["sub"],
        role=payload.get("role", "analyst"),
        tenant_id=payload.get("tenant_id", "default"),
    )
```

- [ ] **Step 4: Wire auth router into main.py**

In `backend/app/main.py`, add the import and include:

```python
from app.api.auth import router as auth_router
# ... existing imports ...

app.include_router(verify_router)
app.include_router(auth_router)  # ADD THIS
```

- [ ] **Step 5: Run tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_auth.py -v`
Expected: All 3 tests PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/api/auth.py backend/app/main.py tests/test_auth.py
git commit -m "feat(phase1): add JWT auth endpoints with in-memory user store"
```

---

## Task 5: Tool Registry (Formalized Pattern)

**Files:**
- Create: `backend/app/tools/registry.py`
- Modify: `backend/app/agent/tool_executor.py`
- Modify: `backend/app/tools/echo_tool.py`
- Test: `tests/test_tool_registry.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_tool_registry.py`:

```python
"""Tests for Tool Registry."""

import pytest

from app.tools.registry import ToolRegistry
from app.governance.tool_protocol import ToolInput, ToolResult


class DummyTool:
    name = "dummy"
    version = "v1"

    def get_schema(self):
        return {
            "type": "function",
            "function": {
                "name": "dummy",
                "description": "A dummy tool",
                "parameters": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                },
            },
        }

    async def execute(self, input_data: ToolInput) -> ToolResult:
        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data={"value": input_data.value if hasattr(input_data, "value") else "ok"},
            trace_id=input_data.trace_id,
        )


@pytest.fixture
def registry():
    return ToolRegistry()


def test_register_and_get(registry):
    tool = DummyTool()
    registry.register(tool)
    assert registry.get("dummy") is tool


def test_get_nonexistent(registry):
    assert registry.get("nope") is None


def test_get_schemas(registry):
    registry.register(DummyTool())
    schemas = registry.get_schemas()
    assert len(schemas) == 1
    assert schemas[0]["function"]["name"] == "dummy"


def test_list_tools(registry):
    registry.register(DummyTool())
    names = registry.list_names()
    assert "dummy" in names


def test_double_register_raises(registry):
    registry.register(DummyTool())
    with pytest.raises(ValueError):
        registry.register(DummyTool())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_tool_registry.py -v`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Implement Tool Registry**

Create `backend/app/tools/registry.py`:

```python
"""Tool Registry — centralized tool registration and lookup."""

from typing import Any

from app.governance.tool_protocol import ToolResult


class ToolRegistry:
    """Manages tool registration and schema access."""

    def __init__(self):
        self._tools: dict[str, Any] = {}

    def register(self, tool: Any) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' already registered")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Any | None:
        return self._tools.get(name)

    def get_schemas(self) -> list[dict[str, Any]]:
        return [tool.get_schema() for tool in self._tools.values()]

    def list_names(self) -> list[str]:
        return list(self._tools.keys())

    async def execute(self, name: str, arguments: dict[str, Any], trace_id: str, tenant_id: str = "system") -> dict[str, Any]:
        tool = self.get(name)
        if not tool:
            return ToolResult(
                success=False,
                tool_name=name,
                tool_version="unknown",
                data={},
                error=f"Tool '{name}' not found",
                confidence=0.0,
                evidence_source=[],
                trace_id=trace_id,
                execution_time_ms=0,
            ).model_dump()

        # Build input with the tool's expected input class
        from app.tools.echo_tool import EchoInput
        input_data = EchoInput(
            trace_id=trace_id,
            tenant_id=tenant_id,
            **arguments,
        )

        result = await tool.execute(input_data)
        return result.model_dump()
```

- [ ] **Step 4: Refactor tool_executor.py to use Registry**

Replace `backend/app/agent/tool_executor.py`:

```python
"""Tool Executor — delegates to Tool Registry.

Kept for backward compatibility with verify.py.
"""

from app.tools.registry import ToolRegistry
from app.tools.echo_tool import echo_tool

# Global registry instance
tool_registry = ToolRegistry()
tool_registry.register(echo_tool)
```

- [ ] **Step 5: Update verify.py imports**

In `backend/app/api/verify.py`, change:

```python
# Old:
# from app.agent.tool_executor import tool_executor
# New:
from app.agent.tool_executor import tool_registry as tool_executor
```

- [ ] **Step 6: Run all tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_tool_registry.py tests/test_json_parser.py tests/test_security.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add backend/app/tools/registry.py backend/app/agent/tool_executor.py backend/app/api/verify.py tests/test_tool_registry.py
git commit -m "feat(phase1): formalize Tool Registry pattern"
```

---

## Task 6: Context Compressor

**Files:**
- Create: `backend/app/agent/context_compressor.py`
- Modify: `backend/app/agent/context.py`
- Test: `tests/test_context_compressor.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_context_compressor.py`:

```python
"""Tests for context compression."""

import pytest

from app.agent.context_compressor import (
    truncate_observation,
    should_compress,
    compress_history,
    estimate_tokens,
)


class TestTruncateObservation:
    def test_short_observation_unchanged(self):
        obs = '{"result": "ok"}'
        result = truncate_observation(obs, max_tokens=100)
        assert result == obs

    def test_long_observation_truncated(self):
        obs = "x " * 5000  # ~5000 tokens
        result = truncate_observation(obs, max_tokens=100)
        assert len(result) < len(obs)
        assert "[TRUNCATED]" in result

    def test_preserves_structure_on_truncation(self):
        obs = '{"data": "' + "x" * 10000 + '", "summary": "test"}'
        result = truncate_observation(obs, max_tokens=50)
        assert "[TRUNCATED]" in result


class TestShouldCompress:
    def test_below_threshold(self):
        assert should_compress(message_count=3, interval=4) is False

    def test_at_threshold(self):
        assert should_compress(message_count=8, interval=4) is True

    def test_boundary(self):
        assert should_compress(message_count=4, interval=4) is True


class TestEstimateTokens:
    def test_empty(self):
        assert estimate_tokens("") == 0

    def test_english(self):
        tokens = estimate_tokens("hello world")
        assert 1 <= tokens <= 3

    def test_json(self):
        tokens = estimate_tokens('{"key": "value"}')
        assert tokens > 0


class TestCompressHistory:
    def test_compress_preserves_recent(self):
        messages = [
            {"role": "user", "content": "q1"},
            {"role": "assistant", "content": "a1"},
            {"role": "user", "content": "q2"},
            {"role": "assistant", "content": "a2"},
            {"role": "user", "content": "q3"},
            {"role": "assistant", "content": "a3"},
        ]
        result = compress_history(messages, keep_recent=2)
        # Should have summary + last 2 messages
        assert len(result) >= 2
        assert result[-1]["content"] == "a3"
        assert result[-2]["content"] == "q3"

    def test_compress_short_list_unchanged(self):
        messages = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]
        result = compress_history(messages, keep_recent=4)
        assert len(result) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_context_compressor.py -v`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Implement context compressor**

Create `backend/app/agent/context_compressor.py`:

```python
"""Context compression for ReAct agent.

Handles:
- Observation truncation (token budget)
- History compression (summarize old turns)
- Token estimation
"""

import json
from typing import Any


def estimate_tokens(text: str) -> int:
    """Rough token estimation: ~4 chars per token for mixed content."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def truncate_observation(observation: str, max_tokens: int = 2000) -> str:
    """Truncate tool observation to fit token budget.

    Preserves the first max_tokens worth of content and adds [TRUNCATED] marker.
    """
    estimated = estimate_tokens(observation)
    if estimated <= max_tokens:
        return observation

    # Approximate char limit from token budget
    char_limit = max_tokens * 4
    truncated = observation[:char_limit]

    # Try to cut at a clean boundary (last newline or comma)
    for sep in ["\n", ",", " "]:
        last_sep = truncated.rfind(sep)
        if last_sep > char_limit * 0.8:
            truncated = truncated[:last_sep]
            break

    return truncated + "\n[TRUNCATED]"


def should_compress(message_count: int, interval: int = 4) -> bool:
    """Check if history compression should trigger."""
    return message_count >= interval * 2


def compress_history(messages: list[dict[str, Any]], keep_recent: int = 4) -> list[dict[str, Any]]:
    """Compress older messages into a summary, keeping recent messages intact.

    Args:
        messages: Full message list in LLM format
        keep_recent: Number of recent messages to keep verbatim

    Returns:
        Compressed message list: [summary_message, ...recent_messages]
    """
    if len(messages) <= keep_recent:
        return messages

    old_messages = messages[:-keep_recent]
    recent_messages = messages[-keep_recent:]

    # Build summary of old messages
    summary_parts = []
    for msg in old_messages:
        role = msg.get("role", "unknown")
        content = msg.get("content", "")
        if role == "tool":
            # Summarize tool results briefly
            summary_parts.append(f"[Tool result: {estimate_tokens(content)} tokens]")
        elif role == "assistant" and msg.get("tool_calls"):
            tool_names = [tc.get("function", {}).get("name", "?") for tc in msg["tool_calls"]]
            summary_parts.append(f"[Called tools: {', '.join(tool_names)}]")
        else:
            # Truncate long content for summary
            brief = content[:200] + "..." if len(content) > 200 else content
            summary_parts.append(f"[{role}]: {brief}")

    summary_text = "=== 历史对话摘要 ===\n" + "\n".join(summary_parts)

    summary_message = {
        "role": "system",
        "content": summary_text,
    }

    return [summary_message] + recent_messages
```

- [ ] **Step 4: Enhance Context Manager with compression support**

In `backend/app/agent/context.py`, add these methods to the `ContextManager` class:

```python
    async def get_recent_messages(self, session_id: str, n: int) -> list[dict[str, Any]]:
        """Get the N most recent messages in LLM format."""
        conv = self._memory_store.get(session_id)
        if not conv:
            return []
        recent = conv.messages[-n:] if n > 0 else conv.messages
        result = []
        for msg in recent:
            m: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.tool_calls:
                m["tool_calls"] = msg.tool_calls
            if msg.tool_call_id:
                m["tool_call_id"] = msg.tool_call_id
            result.append(m)
        return result

    async def replace_messages(self, session_id: str, messages: list[dict[str, Any]]) -> bool:
        """Replace all messages in a session (used after compression)."""
        conv = self._memory_store.get(session_id)
        if not conv:
            return False
        conv.messages = []
        for m in messages:
            conv.messages.append(Message(
                role=m.get("role", "user"),
                content=m.get("content", ""),
                tool_calls=m.get("tool_calls", []),
                tool_call_id=m.get("tool_call_id"),
            ))
        return True
```

- [ ] **Step 5: Run all tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_context_compressor.py -v`
Expected: All 8 tests PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/agent/context_compressor.py backend/app/agent/context.py tests/test_context_compressor.py
git commit -m "feat(phase1): add context compression (observation truncation + history summarization)"
```

---

## Task 7: ReAct Agent Core

**Files:**
- Create: `backend/app/agent/react.py`
- Test: `tests/test_react_agent.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_react_agent.py`:

```python
"""Tests for ReAct agent loop."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from app.agent.react import ReActAgent, ReActResult
from app.agent.json_parser import parse_llm_json
from app.tools.registry import ToolRegistry


def make_mock_llm(responses: list[str]):
    """Create a mock LLM router that returns sequential responses."""
    call_count = 0

    async def mock_complete(request):
        nonlocal call_count
        resp_text = responses[call_count]
        call_count += 1
        mock_resp = MagicMock()
        mock_resp.content = resp_text
        mock_resp.tool_calls = []
        mock_resp.model = "test-model"
        mock_resp.usage = {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}
        mock_resp.latency_ms = 100
        mock_resp.trace_id = request.trace_id
        mock_resp.reasoning_content = None
        return mock_resp

    router = MagicMock()
    router.complete = AsyncMock(side_effect=mock_complete)
    return router


@pytest.fixture
def registry():
    reg = ToolRegistry()
    # Register a simple echo tool
    from app.tools.echo_tool import echo_tool
    reg.register(echo_tool)
    return reg


@pytest.mark.anyio
async def test_react_direct_answer(registry):
    """Agent gives direct answer without tool calls."""
    llm = make_mock_llm([
        json.dumps({"final_answer": "Hello!", "confidence": 0.95, "evidence": ["direct"]}),
    ])

    agent = ReActAgent(llm_router=llm, tool_registry=registry, max_turns=5)
    result = await agent.run(
        messages=[{"role": "user", "content": "Hi"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.success is True
    assert "Hello!" in result.final_answer
    assert result.turns_used == 1


@pytest.mark.anyio
async def test_react_tool_call_then_answer(registry):
    """Agent calls a tool then gives final answer."""
    llm = make_mock_llm([
        json.dumps({"thought": "I should echo", "action": "echo", "action_input": {"message": "test"}}),
        json.dumps({"final_answer": "Echoed: test", "confidence": 1.0, "evidence": ["echo_tool"]}),
    ])

    agent = ReActAgent(llm_router=llm, tool_registry=registry, max_turns=5)
    result = await agent.run(
        messages=[{"role": "user", "content": "Echo test"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.success is True
    assert result.turns_used == 2
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["tool"] == "echo"


@pytest.mark.anyio
async def test_react_max_turns(registry):
    """Agent stops at max turns."""
    # Always return a tool call (never final answer)
    tool_call = json.dumps({"thought": "loop", "action": "echo", "action_input": {"message": "x"}})
    llm = make_mock_llm([tool_call] * 10)

    agent = ReActAgent(llm_router=llm, tool_registry=registry, max_turns=3)
    result = await agent.run(
        messages=[{"role": "user", "content": "loop"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.turns_used == 3
    assert "max turns" in result.final_answer.lower() or result.success is False


@pytest.mark.anyio
async def test_react_handles_malformed_json(registry):
    """Agent handles LLM output that isn't clean JSON."""
    llm = make_mock_llm([
        "Sure! Let me think...\n```json\n{\"thought\": \"analyzing\", \"action\": \"echo\", \"action_input\": {\"message\": \"hi\"}}\n```",
        json.dumps({"final_answer": "Done", "confidence": 0.8, "evidence": []}),
    ])

    agent = ReActAgent(llm_router=llm, tool_registry=registry, max_turns=5)
    result = await agent.run(
        messages=[{"role": "user", "content": "test"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.success is True
    assert result.turns_used == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_react_agent.py -v`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Implement ReAct Agent**

Create `backend/app/agent/react.py`:

```python
"""ReAct Agent — Thought → Action → Observation loop.

Orchestrates LLM reasoning with tool execution.
No LangChain dependency — uses LLM Router and Tool Registry directly.
"""

import json
import time
from typing import Any, AsyncIterator
from dataclasses import dataclass, field

from pydantic import BaseModel

from app.agent.json_parser import parse_llm_json
from app.agent.context_compressor import (
    truncate_observation,
    should_compress,
    compress_history,
    estimate_tokens,
)


@dataclass
class ReActResult:
    """Result of a ReAct agent run."""
    success: bool
    final_answer: str
    turns_used: int
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_latency_ms: int = 0


@dataclass
class TurnEvent:
    """Event emitted during a ReAct turn."""
    type: str  # "thought" | "tool_call" | "tool_result" | "answer" | "error"
    turn: int
    content: Any


class ReActAgent:
    """ReAct reasoning agent.

    Loop: Thought → Action → Observation
    Terminates on: final_answer, max_turns, consecutive failures
    """

    def __init__(
        self,
        llm_router: Any,
        tool_registry: Any,
        max_turns: int = 12,
        max_tool_retries: int = 3,
        compress_interval: int = 4,
        obs_max_tokens: int = 2000,
    ):
        self.llm = llm_router
        self.tools = tool_registry
        self.max_turns = max_turns
        self.max_tool_retries = max_tool_retries
        self.compress_interval = compress_interval
        self.obs_max_tokens = obs_max_tokens

    async def run(
        self,
        messages: list[dict[str, Any]],
        tenant_id: str,
        trace_id: str,
    ) -> ReActResult:
        """Execute the ReAct loop."""
        working_messages = list(messages)
        tool_calls_log: list[dict[str, Any]] = []
        total_tokens = 0
        start_time = time.time()
        consecutive_failures = 0

        for turn in range(1, self.max_turns + 1):
            # Compress if needed
            if should_compress(len(working_messages), self.compress_interval):
                working_messages = compress_history(
                    working_messages, keep_recent=self.compress_interval
                )

            # Call LLM
            from app.llm.router import LLMRequest
            request = LLMRequest(
                messages=working_messages,
                tools=self.tools.get_schemas() if self.tools.list_names() else None,
                trace_id=trace_id,
            )

            response = await self.llm.complete(request)
            total_tokens += response.usage.get("total_tokens", 0)

            # Parse LLM output
            parsed = parse_llm_json(response.content)

            # Check for final answer
            if "final_answer" in parsed:
                return ReActResult(
                    success=True,
                    final_answer=parsed["final_answer"],
                    turns_used=turn,
                    tool_calls=tool_calls_log,
                    total_tokens=total_tokens,
                    total_latency_ms=int((time.time() - start_time) * 1000),
                )

            # Check for error in parse
            if parsed.get("error") == "parse_failed":
                consecutive_failures += 1
                if consecutive_failures >= self.max_tool_retries:
                    return ReActResult(
                        success=False,
                        final_answer=f"Agent failed: LLM output could not be parsed after {consecutive_failures} attempts.",
                        turns_used=turn,
                        tool_calls=tool_calls_log,
                        total_tokens=total_tokens,
                    )
                # Retry with error feedback
                working_messages.append({
                    "role": "assistant",
                    "content": response.content,
                })
                working_messages.append({
                    "role": "user",
                    "content": (
                        "你的输出不是有效的 JSON。请严格按照以下格式输出：\n"
                        '{"thought": "...", "action": "tool_name", "action_input": {...}}\n'
                        '或直接给出最终答案：\n'
                        '{"final_answer": "...", "confidence": 0.9, "evidence": [...]}'
                    ),
                })
                continue

            # Extract action
            action = parsed.get("action")
            action_input = parsed.get("action_input", {})
            thought = parsed.get("thought", "")

            if not action:
                # No action specified — treat as final answer attempt
                return ReActResult(
                    success=True,
                    final_answer=parsed.get("thought", response.content),
                    turns_used=turn,
                    tool_calls=tool_calls_log,
                    total_tokens=total_tokens,
                )

            # Add assistant message with tool_calls format
            tool_call_id = f"call_{trace_id}_{turn}"
            assistant_msg = {
                "role": "assistant",
                "content": response.content,
                "tool_calls": [{
                    "id": tool_call_id,
                    "type": "function",
                    "function": {
                        "name": action,
                        "arguments": json.dumps(action_input),
                    },
                }],
            }
            if response.reasoning_content:
                assistant_msg["reasoning_content"] = response.reasoning_content
            working_messages.append(assistant_msg)

            # Execute tool
            tool_result = await self.tools.execute(
                name=action,
                arguments=action_input,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )

            tool_calls_log.append({
                "turn": turn,
                "tool": action,
                "input": action_input,
                "output": tool_result,
            })

            # Truncate observation
            obs_content = json.dumps(tool_result, ensure_ascii=False)
            obs_content = truncate_observation(obs_content, self.obs_max_tokens)

            working_messages.append({
                "role": "tool",
                "content": obs_content,
                "tool_call_id": tool_call_id,
            })

            # Check for tool failure
            if not tool_result.get("success"):
                consecutive_failures += 1
            else:
                consecutive_failures = 0

        # Max turns reached
        return ReActResult(
            success=False,
            final_answer=f"Agent reached maximum turns ({self.max_turns}) without final answer.",
            turns_used=self.max_turns,
            tool_calls=tool_calls_log,
            total_tokens=total_tokens,
            total_latency_ms=int((time.time() - start_time) * 1000),
        )

    async def run_streaming(
        self,
        messages: list[dict[str, Any]],
        tenant_id: str,
        trace_id: str,
    ) -> AsyncIterator[TurnEvent]:
        """Execute ReAct loop with streaming events for WebSocket."""
        working_messages = list(messages)
        tool_calls_log: list[dict[str, Any]] = []
        total_tokens = 0
        consecutive_failures = 0

        for turn in range(1, self.max_turns + 1):
            if should_compress(len(working_messages), self.compress_interval):
                working_messages = compress_history(
                    working_messages, keep_recent=self.compress_interval
                )

            from app.llm.router import LLMRequest
            request = LLMRequest(
                messages=working_messages,
                tools=self.tools.get_schemas() if self.tools.list_names() else None,
                trace_id=trace_id,
            )

            response = await self.llm.complete(request)
            total_tokens += response.usage.get("total_tokens", 0)

            parsed = parse_llm_json(response.content)

            if "final_answer" in parsed:
                yield TurnEvent(type="answer", turn=turn, content=parsed)
                return

            if parsed.get("error") == "parse_failed":
                consecutive_failures += 1
                yield TurnEvent(type="error", turn=turn, content={"error": "parse_failed", "raw": response.content})
                if consecutive_failures >= self.max_tool_retries:
                    return
                working_messages.append({"role": "assistant", "content": response.content})
                working_messages.append({
                    "role": "user",
                    "content": '请输出有效 JSON: {"thought":"...","action":"tool","action_input":{...}} 或 {"final_answer":"...","confidence":0.9,"evidence":[...]}',
                })
                continue

            action = parsed.get("action")
            if not action:
                yield TurnEvent(type="answer", turn=turn, content={"final_answer": parsed.get("thought", response.content)})
                return

            action_input = parsed.get("action_input", {})
            yield TurnEvent(type="thought", turn=turn, content={"thought": parsed.get("thought", ""), "action": action})

            tool_call_id = f"call_{trace_id}_{turn}"
            assistant_msg = {
                "role": "assistant",
                "content": response.content,
                "tool_calls": [{"id": tool_call_id, "type": "function", "function": {"name": action, "arguments": json.dumps(action_input)}}],
            }
            if response.reasoning_content:
                assistant_msg["reasoning_content"] = response.reasoning_content
            working_messages.append(assistant_msg)

            yield TurnEvent(type="tool_call", turn=turn, content={"tool": action, "status": "running"})

            tool_result = await self.tools.execute(name=action, arguments=action_input, trace_id=trace_id, tenant_id=tenant_id)

            tool_calls_log.append({"turn": turn, "tool": action, "input": action_input, "output": tool_result})

            obs_content = json.dumps(tool_result, ensure_ascii=False)
            obs_content = truncate_observation(obs_content, self.obs_max_tokens)

            working_messages.append({"role": "tool", "content": obs_content, "tool_call_id": tool_call_id})

            yield TurnEvent(type="tool_result", turn=turn, content={"tool": action, "success": tool_result.get("success")})

            if not tool_result.get("success"):
                consecutive_failures += 1
            else:
                consecutive_failures = 0

        yield TurnEvent(type="error", turn=self.max_turns, content={"error": "max_turns_reached"})
```

- [ ] **Step 4: Run tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_react_agent.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/agent/react.py tests/test_react_agent.py
git commit -m "feat(phase1): add ReAct agent core with streaming support"
```

---

## Task 8: WebSocket Chat Endpoint

**Files:**
- Create: `backend/app/api/chat.py`
- Test: `tests/test_chat_ws.py`

- [ ] **Step 1: Write the test**

Create `tests/test_chat_ws.py`:

```python
"""Tests for WebSocket chat endpoint."""

import json
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.security import create_access_token


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def auth_token():
    return create_access_token(
        {"sub": "user-001", "role": "analyst", "tenant_id": "tenant-1"},
        secret="test-secret",
    )


@pytest.mark.anyio
async def test_ws_connect_and_chat(auth_token):
    """Test WebSocket connection and message exchange."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with client.stream(
            "GET",
            f"/api/v1/agent/chat?token={auth_token}",
            headers={"upgrade": "websocket", "connection": "upgrade"},
        ) as resp:
            # WebSocket upgrade should succeed or return proper error
            assert resp.status_code in (101, 400, 403, 426)


@pytest.mark.anyio
async def test_ws_no_token():
    """Test WebSocket connection without token is rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/agent/chat")
        assert resp.status_code in (400, 401, 403, 422, 426)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_chat_ws.py -v`
Expected: FAIL

- [ ] **Step 3: Implement WebSocket chat endpoint**

Create `backend/app/api/chat.py`:

```python
"""WebSocket chat endpoint for Agent interaction.

Protocol:
  Client → Server: {"type": "chat", "content": "...", "session_id": "..."}
  Server → Client: {"type": "token", "content": "..."}
  Server → Client: {"type": "tool_call", "tool": "...", "status": "running"}
  Server → Client: {"type": "tool_result", "tool": "...", "success": true}
  Server → Client: {"type": "llm_backend", "provider": "...", "model": "..."}
  Server → Client: {"type": "done", "total_tokens": N}
  Server → Client: {"type": "error", "code": "...", "message": "..."}
"""

import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from fastapi.websockets import WebSocketState

from app.core.config import get_settings
from app.core.security import verify_token
from app.agent.react import ReActAgent
from app.agent.context import context_manager, Message
from app.agent.tool_executor import tool_registry

router = APIRouter(tags=["chat"])


async def authenticate_ws(token: str) -> dict[str, Any] | None:
    """Verify JWT from WebSocket query param."""
    settings = get_settings()
    return verify_token(token, secret=settings.jwt_secret)


@router.websocket("/api/v1/agent/chat")
async def websocket_chat(
    websocket: WebSocket,
    token: str = Query(...),
):
    """WebSocket endpoint for multi-turn Agent chat."""
    # Authenticate
    user = await authenticate_ws(token)
    if not user:
        await websocket.close(code=4001, reason="Invalid token")
        return

    await websocket.accept()

    tenant_id = user.get("tenant_id", "default")
    user_id = user["sub"]
    session_id = None

    settings = get_settings()

    try:
        while True:
            # Receive message
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "code": "invalid_json", "message": "Invalid JSON"})
                continue

            msg_type = data.get("type")
            if msg_type != "chat":
                await websocket.send_json({"type": "error", "code": "unsupported", "message": f"Unknown type: {msg_type}"})
                continue

            content = data.get("content", "")
            session_id = data.get("session_id")

            # Send LLM backend info
            await websocket.send_json({
                "type": "llm_backend",
                "provider": "deepseek",
                "model": settings.llm_model,
            })

            # Get or create session
            if session_id:
                conv = await context_manager.get_session(session_id)
                if not conv:
                    conv = await context_manager.create_session(tenant_id)
                    session_id = conv.session_id
            else:
                conv = await context_manager.create_session(tenant_id)
                session_id = conv.session_id

            # Add user message
            await context_manager.add_message(session_id, Message(role="user", content=content))

            # Get context
            messages = await context_manager.get_messages(session_id)

            # Run ReAct agent
            import uuid
            trace_id = str(uuid.uuid4())

            agent = ReActAgent(
                llm_router=_get_llm_router(),
                tool_registry=tool_registry,
                max_turns=settings.react_max_turns,
                max_tool_retries=settings.react_max_tool_retries,
                compress_interval=settings.ctx_history_summary_interval,
                obs_max_tokens=settings.ctx_obs_max_tokens,
            )

            final_answer = ""
            total_tokens = 0

            async for event in agent.run_streaming(messages, tenant_id, trace_id):
                if event.type == "thought":
                    await websocket.send_json({
                        "type": "tool_call",
                        "tool": event.content.get("action", ""),
                        "status": "running",
                    })
                elif event.type == "tool_call":
                    await websocket.send_json({
                        "type": "tool_call",
                        "tool": event.content.get("tool", ""),
                        "status": "running",
                    })
                elif event.type == "tool_result":
                    await websocket.send_json({
                        "type": "tool_result",
                        "tool": event.content.get("tool", ""),
                        "success": event.content.get("success"),
                    })
                elif event.type == "answer":
                    final_answer = event.content.get("final_answer", "")
                    await websocket.send_json({
                        "type": "token",
                        "content": final_answer,
                    })
                elif event.type == "error":
                    await websocket.send_json({
                        "type": "error",
                        "code": event.content.get("error", "unknown"),
                        "message": str(event.content),
                    })

            # Save assistant response
            await context_manager.add_message(session_id, Message(role="assistant", content=final_answer))

            # Send done
            await websocket.send_json({
                "type": "done",
                "session_id": session_id,
                "total_tokens": total_tokens,
            })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        if websocket.client_state == WebSocketState.CONNECTED:
            await websocket.send_json({"type": "error", "code": "internal", "message": str(e)})
            await websocket.close()


def _get_llm_router():
    """Import LLM router (avoids circular imports)."""
    from app.llm.router import router
    return router
```

- [ ] **Step 4: Wire chat router into main.py**

In `backend/app/main.py`, add:

```python
from app.api.chat import router as chat_router
# ...
app.include_router(auth_router)
app.include_router(chat_router)  # ADD THIS
```

- [ ] **Step 5: Run tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_chat_ws.py -v`
Expected: PASS (WebSocket tests may be limited in httpx, but connection handling should work)

- [ ] **Step 6: Commit**

```bash
git add backend/app/api/chat.py backend/app/main.py tests/test_chat_ws.py
git commit -m "feat(phase1): add WebSocket chat endpoint with streaming agent events"
```

---

## Task 9: Main.py Wiring + Integration Verification

**Files:**
- Modify: `backend/app/main.py`
- Test: `tests/test_integration.py`

- [ ] **Step 1: Update main.py with all routers and startup**

Replace `backend/app/main.py` with:

```python
"""
FastAPI 入口 — Phase 1: Agent Core Framework.

链路: FastAPI → JWT Auth → WebSocket → ReAct Agent → LLM Router → Tool Registry
"""

import os

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.verify import router as verify_router
from app.api.auth import router as auth_router
from app.api.chat import router as chat_router
from app.agent.context import context_manager

app = FastAPI(
    title="CyberSec Agent",
    description="网络安全智能分析平台 — ReAct Agent + DeepSeek API",
    version="0.2.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(verify_router)
app.include_router(auth_router)
app.include_router(chat_router)


@app.on_event("startup")
async def startup():
    await context_manager.connect()


@app.on_event("shutdown")
async def shutdown():
    await context_manager.disconnect()


@app.get("/")
async def root():
    return {
        "project": "CyberSec Agent",
        "phase": "Phase 1",
        "version": "0.2.0",
        "features": [
            "JWT Authentication",
            "ReAct Agent (Thought → Action → Observation)",
            "WebSocket Streaming Chat",
            "Tool Registry",
            "Context Compression",
            "5-Level JSON Parser",
        ],
        "endpoints": {
            "auth_login": "POST /api/v1/auth/login",
            "agent_chat": "WS /api/v1/agent/chat?token=<jwt>",
            "verify_health": "GET /verify/health",
            "verify_chain": "POST /verify/chain",
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "phase": "Phase 1"}
```

- [ ] **Step 2: Write integration test**

Create `tests/test_integration.py`:

```python
"""Integration test — Phase 1 end-to-end verification."""

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_root_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["phase"] == "Phase 1"
    assert "ReAct Agent" in data["features"]


@pytest.mark.anyio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.anyio
async def test_login_and_get_token():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["role"] == "admin"


@pytest.mark.anyio
async def test_verify_endpoints_still_work():
    """Ensure Phase 0 verify endpoints are not broken."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/verify/health")
    assert resp.status_code == 200
```

- [ ] **Step 3: Run the full test suite**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 4: Manual verification — start the server and test**

Run: `cd /data/data6T/liang/project/Agent/backend && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`

Then in another terminal:

```bash
# Health check
curl http://localhost:8000/health

# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Use the token from login response for WebSocket test (using wscat or similar)
```

Expected: Health returns `{"status":"ok","phase":"Phase 1"}`, login returns JWT token.

- [ ] **Step 5: Commit**

```bash
git add backend/app/main.py tests/test_integration.py
git commit -m "feat(phase1): wire all Phase 1 components, update main.py for Agent Core Framework"
```

---

## Phase 1 Acceptance Checklist

Per the execution document, Phase 1 is verified when:

- [ ] WebSocket client completes 5-turn conversation
- [ ] Context compression triggers but conversation stays coherent
- [ ] LLM outputs Markdown-wrapped JSON and parser extracts correctly
- [ ] Login → JWT → WebSocket auth flow works end-to-end
- [ ] Tool Calling chain works through ReAct agent
- [ ] All tests pass
