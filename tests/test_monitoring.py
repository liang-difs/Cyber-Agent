"""Tests for monitoring and health endpoints."""

import pytest
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.monitoring import MODEL_PRESETS
from app.api.deps import get_current_user as auth_dep


class _MockResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _HealthyAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url):
        return _MockResponse(200, {"data": [{"id": "openai/qwen3-14b"}]})


class _FailingAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url):
        raise OSError("connection refused")


@pytest.mark.anyio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert data["version"] == "0.5.0"


@pytest.mark.anyio
async def test_detailed_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health/detailed")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "checks" in data
    # Checks should include core dependencies and LLM router status
    assert "postgresql" in data["checks"]
    assert "redis" in data["checks"]
    assert "elasticsearch" in data["checks"]
    assert "celery" in data["checks"]
    assert "llm" in data["checks"]
    assert "default_model" in data["checks"]["llm"]
    assert "circuits" in data["checks"]["llm"]


@pytest.mark.anyio
async def test_root_endpoint_phase4():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["phase"] == "Phase 4"
    assert data["version"] == "0.8.0"
    assert "Attack Chain Tracing" in str(data["features"])
    assert "attack_chains" in data["endpoints"]


@pytest.mark.anyio
async def test_llm_models_endpoint_exposes_provider_and_auth():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/llm/models")
    assert resp.status_code == 200
    data = resp.json()
    assert "provider_hint" in data["current"]
    assert "auth" in data["current"]
    assert isinstance(data["current"]["auth"], dict)
    assert "local" not in MODEL_PRESETS
    assert "local" not in data["presets"]


@pytest.mark.anyio
async def test_llm_switch_requires_admin():
    app.dependency_overrides[auth_dep] = lambda: {"user_id": "u1", "role": "viewer", "tenant_id": "t1"}
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/llm/switch", json={"preset": "deepseek"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_llm_switch_allows_admin():
    app.dependency_overrides[auth_dep] = lambda: {"user_id": "u1", "role": "admin", "tenant_id": "t1"}
    try:
        with patch("httpx.AsyncClient", _HealthyAsyncClient), patch(
            "app.llm.router.router.switch_model",
            return_value={"default_model": "deepseek-v4-flash", "base_url": "api"},
        ) as switch_model:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/llm/switch", json={"preset": "deepseek"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        switch_model.assert_called_once()
    finally:
        app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_llm_switch_rejects_unreachable_backend():
    app.dependency_overrides[auth_dep] = lambda: {"user_id": "u1", "role": "admin", "tenant_id": "t1"}
    try:
        with patch("httpx.AsyncClient", _FailingAsyncClient), patch(
            "app.llm.router.router.switch_model"
        ) as switch_model:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/llm/switch",
                    json={"model": "openai/gpt-4o-mini", "base_url": "http://example.invalid/v1"},
                )
        assert resp.status_code == 503
        assert "LLM" in resp.json()["detail"]
        switch_model.assert_not_called()
    finally:
        app.dependency_overrides.clear()
