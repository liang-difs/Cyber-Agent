"""Tests for config module."""

from app.core.config import Settings, get_settings


def test_settings_defaults():
    s = Settings()
    assert s.llm_model == "deepseek-v4-flash"
    assert s.llm_fallback_models == ""
    assert s.llm_max_retries == 2
    assert s.llm_timeout == 30
    assert s.llm_max_tokens == 16384
    assert s.llm_circuit_failure_threshold == 3
    assert s.llm_circuit_reset_seconds == 60
    assert s.react_max_turns == 10
    assert s.react_max_tool_retries == 3
    assert s.ctx_compress_threshold == 8000
    assert s.ctx_obs_max_tokens == 2000
    assert s.ctx_history_summary_interval == 4
    assert s.ws_heartbeat_interval == 30
    assert s.jwt_algorithm == "HS256"
    assert s.jwt_expire_minutes == 60
    assert s.redis_url == "redis://localhost:6379/0"
    assert s.auth_dev_fallback_enabled is True


def test_settings_types():
    s = Settings()
    assert isinstance(s.llm_model, str)
    assert isinstance(s.llm_timeout, int)
    assert isinstance(s.react_max_turns, int)
    assert isinstance(s.ctx_obs_max_tokens, int)


def test_get_settings_returns_cached_instance():
    get_settings.cache_clear()
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2  # same object due to lru_cache
    get_settings.cache_clear()


def test_settings_has_otx_api_key(settings):
    assert hasattr(settings, "otx_api_key")
    assert isinstance(settings.otx_api_key, str)


def test_settings_has_abuseipdb_api_key(settings):
    assert hasattr(settings, "abuseipdb_api_key")
    assert isinstance(settings.abuseipdb_api_key, str)


def test_get_settings_reads_env(monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "custom-model")
    monkeypatch.setenv("MAX_TOKEN", "32768")
    monkeypatch.setenv("JWT_SECRET", "my-secret")
    get_settings.cache_clear()
    s = get_settings()
    assert s.llm_model == "custom-model"
    assert s.llm_max_tokens == 32768
    assert s.jwt_secret == "my-secret"
    get_settings.cache_clear()


def test_get_settings_supports_llm_api_key_alias(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "EMPTY")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    get_settings.cache_clear()
    s = get_settings()
    assert s.openai_api_key == "EMPTY"
    assert s.anthropic_api_key == "sk-ant-test"
    assert s.llm_provider == "openai"
    get_settings.cache_clear()
