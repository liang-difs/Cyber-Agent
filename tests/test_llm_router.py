"""Tests for LLM router retry and fallback behavior."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.llm.router import LLMRequest, LLMRouter
from app.core.config import get_settings


def _response(content: str = "ok") -> SimpleNamespace:
    message = SimpleNamespace(content=content, reasoning_content=None, tool_calls=None)
    choice = SimpleNamespace(message=message)
    usage = SimpleNamespace(prompt_tokens=3, completion_tokens=2, total_tokens=5)
    return SimpleNamespace(choices=[choice], usage=usage)


def test_llm_request_uses_configured_max_tokens(monkeypatch):
    monkeypatch.setattr("app.llm.router.get_llm_max_tokens", lambda: 24576)

    request = LLMRequest(messages=[{"role": "user", "content": "hi"}])

    assert request.max_tokens == 24576


def test_llm_request_explicit_max_tokens_still_wins():
    request = LLMRequest(messages=[{"role": "user", "content": "hi"}], max_tokens=1024)

    assert request.max_tokens == 1024


@pytest.mark.anyio
async def test_llm_router_retries_primary(monkeypatch):
    router = LLMRouter()
    router.default_model = "openai/primary"
    router.fallback_models = []
    router.max_retries = 1

    calls = []

    async def fake_completion(**kwargs):
        calls.append(kwargs["model"])
        if len(calls) == 1:
            raise RuntimeError("temporary")
        return _response("recovered")

    monkeypatch.setattr("app.llm.router.litellm.acompletion", fake_completion)
    monkeypatch.setattr("app.llm.router.litellm.completion_cost", lambda **_: 0.01)
    monkeypatch.setattr("app.llm.router.LLMRouter._sleep_before_retry", AsyncMock())

    result = await router.complete(LLMRequest(messages=[{"role": "user", "content": "hi"}]))

    assert result.content == "recovered"
    assert calls == ["openai/primary", "openai/primary"]
    assert result.cost_usd == 0.01
    assert router.usage_events[-1]["usage"]["total_tokens"] == 5


@pytest.mark.anyio
async def test_llm_router_falls_back_after_primary_failure(monkeypatch):
    router = LLMRouter()
    router.default_model = "openai/primary"
    router.fallback_models = ["openai/backup"]
    router.max_retries = 0

    calls = []

    async def fake_completion(**kwargs):
        calls.append(kwargs["model"])
        if kwargs["model"] == "openai/primary":
            raise RuntimeError("primary down")
        return _response("backup ok")

    monkeypatch.setattr("app.llm.router.litellm.acompletion", fake_completion)

    result = await router.complete(LLMRequest(messages=[{"role": "user", "content": "hi"}]))

    assert result.content == "backup ok"
    assert result.model == "openai/backup"
    assert calls == ["openai/primary", "openai/backup"]


@pytest.mark.anyio
async def test_llm_router_opens_circuit_and_skips_primary(monkeypatch):
    router = LLMRouter()
    router.default_model = "openai/primary"
    router.fallback_models = ["openai/backup"]
    router.max_retries = 0
    router.circuit_failure_threshold = 1
    router.circuit_reset_seconds = 60

    calls = []

    async def fake_completion(**kwargs):
        calls.append(kwargs["model"])
        if kwargs["model"] == "openai/primary":
            raise RuntimeError("primary down")
        return _response("backup ok")

    monkeypatch.setattr("app.llm.router.litellm.acompletion", fake_completion)

    first = await router.complete(LLMRequest(messages=[{"role": "user", "content": "hi"}]))
    second = await router.complete(LLMRequest(messages=[{"role": "user", "content": "again"}]))

    assert first.model == "openai/backup"
    assert second.model == "openai/backup"
    assert calls == ["openai/primary", "openai/backup", "openai/backup"]


@pytest.mark.anyio
async def test_llm_router_records_request_identity(monkeypatch):
    router = LLMRouter()
    router.default_model = "openai/primary"
    router.max_retries = 0

    async def fake_completion(**kwargs):
        return _response("ok")

    monkeypatch.setattr("app.llm.router.litellm.acompletion", fake_completion)

    await router.complete(LLMRequest(
        messages=[{"role": "user", "content": "hi"}],
        user_id="00000000-0000-0000-0000-000000000001",
        tenant_id="tenant-1",
    ))

    event = router.usage_events[-1]
    assert event["user_id"] == "00000000-0000-0000-0000-000000000001"
    assert event["tenant_id"] == "tenant-1"


@pytest.mark.anyio
async def test_llm_router_passes_local_api_key_alias(monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "qwen3-14b")
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:8001/v1")
    monkeypatch.setenv("LLM_API_KEY", "EMPTY")
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    get_settings.cache_clear()

    router = LLMRouter()
    captured = {}

    async def fake_completion(**kwargs):
        captured.update(kwargs)
        return _response("local ok")

    monkeypatch.setattr("app.llm.router.litellm.acompletion", fake_completion)

    result = await router.complete(LLMRequest(messages=[{"role": "user", "content": "hi"}]))

    assert result.content == "local ok"
    assert captured["api_base"] == "http://localhost:8001/v1"
    assert captured["api_key"] == "EMPTY"
    assert captured["model"] == "openai/qwen3-14b"
    get_settings.cache_clear()
