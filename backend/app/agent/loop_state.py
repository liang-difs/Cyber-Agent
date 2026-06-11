"""Shared state and helpers for ReAct loop.

Eliminates code duplication between run() and run_streaming() methods.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class LoopState:
    """Encapsulates mutable state for a single ReAct loop execution.

    This class centralizes the dedup tracking, tool call counting,
    and fallback logic that was previously duplicated across run()
    and run_streaming().
    """

    # Counters
    tool_call_count: int = 0
    consecutive_failures: int = 0
    web_search_count: int = 0

    # Dedup tracking
    seen_tool_calls: set[str] = field(default_factory=set)

    # Last results for fallback
    last_web_search_query: str = ""
    last_web_search_result: Optional[dict[str, Any]] = None
    last_cve_catalog_result: Optional[dict[str, Any]] = None

    # Timing
    start_time: float = field(default_factory=time.time)
    total_tokens: int = 0

    def should_dedup(self, call_key: str) -> bool:
        """Check if this tool call should be deduplicated."""
        return call_key in self.seen_tool_calls

    def register_tool_call(
        self,
        call_key: str,
        tool_name: str,
        tool_result: dict[str, Any],
        action_input: dict[str, Any],
    ) -> None:
        """Register a completed tool call and update state."""
        self.seen_tool_calls.add(call_key)
        self.tool_call_count += 1

        if tool_name == "web_search" and tool_result.get("success"):
            self.web_search_count += 1
            self.last_web_search_query = str(action_input.get("query", "")).strip()
            self.last_web_search_result = tool_result

        if tool_name == "cve_catalog" and tool_result.get("success"):
            self.last_cve_catalog_result = tool_result

    def get_fallback_answer(self, thought: str = "") -> str:
        """Get fallback answer based on last results.

        Prefers web search results, then CVE catalog results,
        then falls back to the provided thought text.
        """
        if self.last_web_search_result is not None:
            from app.agent.react import _build_web_search_fallback
            return _build_web_search_fallback(
                self.last_web_search_query,
                self.last_web_search_result,
            )
        if self.last_cve_catalog_result is not None:
            from app.agent.react import _build_cve_catalog_fallback
            return _build_cve_catalog_fallback(self.last_cve_catalog_result)
        return thought or "基于已有信息，我无法获得更多数据，请尝试换个角度提问。"

    def get_fallback_confidence(self) -> float:
        """Get confidence for fallback answers."""
        if self.last_web_search_result is not None or self.last_cve_catalog_result is not None:
            return 0.5
        return 0.3

    def elapsed_ms(self) -> int:
        """Get elapsed time in milliseconds."""
        return int((time.time() - self.start_time) * 1000)
