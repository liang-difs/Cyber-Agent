"""Tests for custom exceptions."""

from __future__ import annotations

import pytest

from app.core.exceptions import (
    CyberSecException,
    DatabaseConnectionError,
    LLMRouterError,
    ToolExecutionError,
    AgentTimeoutError,
    ConfigError,
)


def test_exception_hierarchy():
    """Test that all custom exceptions inherit from CyberSecException."""
    assert issubclass(DatabaseConnectionError, CyberSecException)
    assert issubclass(LLMRouterError, CyberSecException)
    assert issubclass(ToolExecutionError, CyberSecException)
    assert issubclass(AgentTimeoutError, CyberSecException)
    assert issubclass(ConfigError, CyberSecException)


def test_exception_inherits_from_base():
    """Test that CyberSecException inherits from Exception."""
    assert issubclass(CyberSecException, Exception)


def test_exception_message():
    """Test exception message is preserved."""
    exc = DatabaseConnectionError("Connection failed")
    assert str(exc) == "Connection failed"


def test_exception_catch_as_base():
    """Test that specific exceptions can be caught as base."""
    with pytest.raises(CyberSecException):
        raise DatabaseConnectionError("test")


def test_exception_catch_as_exception():
    """Test that CyberSecException can be caught as Exception."""
    with pytest.raises(Exception):
        raise LLMRouterError("routing failed")


def test_tool_execution_error():
    """Test ToolExecutionError with tool name context."""
    exc = ToolExecutionError("nmap_scan failed: timeout")
    assert "nmap_scan" in str(exc)
    assert "timeout" in str(exc)


def test_agent_timeout_error():
    """Test AgentTimeoutError with duration context."""
    exc = AgentTimeoutError("Agent exceeded 120s timeout")
    assert "120s" in str(exc)


def test_config_error():
    """Test ConfigError with missing key context."""
    exc = ConfigError("Missing required: DEEPSEEK_API_KEY")
    assert "DEEPSEEK_API_KEY" in str(exc)
