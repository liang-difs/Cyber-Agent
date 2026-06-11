"""Tests for application constants."""

from __future__ import annotations

from app.core.constants import (
    APP_VERSION,
    APP_TITLE,
    DEFAULT_LLM_MODEL,
    DEFAULT_LLM_TIMEOUT,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_CONTEXT_WINDOW,
    RAG_TOP_K,
    RAG_MAX_OBSERVATION_TOKENS,
    MINI_PLANNER_MAX_STEPS,
    MINI_PLANNER_MAX_TIME,
    FULL_PLANNER_MAX_STEPS,
    FULL_PLANNER_MAX_TIME,
    JWT_SECRET_MIN_LENGTH,
    JWT_ALGORITHM,
    JWT_EXPIRY_HOURS,
    API_V1_PREFIX,
)


def test_app_version():
    assert APP_VERSION == "0.9.0"


def test_app_title():
    assert APP_TITLE == "CyberSec Agent"


def test_default_llm_model():
    assert DEFAULT_LLM_MODEL == "deepseek-v4-flash"


def test_default_llm_timeout():
    assert DEFAULT_LLM_TIMEOUT == 30


def test_max_tool_calls():
    assert DEFAULT_MAX_TOOL_CALLS == 4


def test_context_window():
    assert DEFAULT_CONTEXT_WINDOW == 32768


def test_rag_top_k():
    assert RAG_TOP_K == 4


def test_rag_max_observation_tokens():
    assert RAG_MAX_OBSERVATION_TOKENS == 2000


def test_mini_planner_config():
    assert MINI_PLANNER_MAX_STEPS == 4
    assert MINI_PLANNER_MAX_TIME == 60


def test_full_planner_config():
    assert FULL_PLANNER_MAX_STEPS == 12
    assert FULL_PLANNER_MAX_TIME == 120


def test_jwt_config():
    assert JWT_SECRET_MIN_LENGTH == 32
    assert JWT_ALGORITHM == "HS256"
    assert JWT_EXPIRY_HOURS == 24


def test_api_prefix():
    assert API_V1_PREFIX == "/api/v1"
