"""Shared test fixtures."""

import pytest



@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def test_env(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("AUTH_DEV_FALLBACK_ENABLED", "true")
    monkeypatch.setenv("JWT_SECRET", "")
    monkeypatch.setenv("LLM_MODEL", "deepseek-v4-flash")
    monkeypatch.setenv("LLM_BASE_URL", "")
    from app.core.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings():
    from app.core.config import get_settings
    s = get_settings()
    yield s
    get_settings.cache_clear()
