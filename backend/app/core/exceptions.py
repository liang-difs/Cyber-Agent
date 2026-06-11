"""Custom exceptions for CyberSec Agent."""

from __future__ import annotations


class CyberSecException(Exception):
    """Base exception for CyberSec Agent."""
    pass


class DatabaseConnectionError(CyberSecException):
    """Database connection failed."""
    pass


class LLMRouterError(CyberSecException):
    """LLM routing failed."""
    pass


class ToolExecutionError(CyberSecException):
    """Tool execution failed."""
    pass


class AgentTimeoutError(CyberSecException):
    """Agent execution timed out."""
    pass


class ConfigError(CyberSecException):
    """Configuration error."""
    pass
