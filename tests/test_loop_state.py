"""Tests for LoopState."""

from __future__ import annotations

from app.agent.loop_state import LoopState


def test_loop_state_initial():
    """Test LoopState initial values."""
    state = LoopState()
    assert state.tool_call_count == 0
    assert state.consecutive_failures == 0
    assert state.web_search_count == 0
    assert len(state.seen_tool_calls) == 0
    assert state.last_web_search_query == ""
    assert state.last_web_search_result is None
    assert state.last_cve_catalog_result is None
    assert state.total_tokens == 0


def test_should_dedup():
    """Test dedup detection."""
    state = LoopState()
    assert not state.should_dedup("key1")
    state.seen_tool_calls.add("key1")
    assert state.should_dedup("key1")


def test_register_tool_call():
    """Test tool call registration."""
    state = LoopState()
    state.register_tool_call(
        "key1", "ioc_lookup", {"success": True}, {"value": "1.2.3.4"}
    )
    assert state.tool_call_count == 1
    assert "key1" in state.seen_tool_calls
    assert state.last_web_search_result is None
    assert state.last_cve_catalog_result is None


def test_register_web_search():
    """Test web search tracking."""
    state = LoopState()
    state.register_tool_call(
        "key1", "web_search", {"success": True}, {"query": "test query"}
    )
    assert state.web_search_count == 1
    assert state.last_web_search_query == "test query"
    assert state.last_web_search_result is not None


def test_register_web_search_failure():
    """Test failed web search is not tracked."""
    state = LoopState()
    state.register_tool_call(
        "key1", "web_search", {"success": False}, {"query": "test"}
    )
    assert state.web_search_count == 0
    assert state.last_web_search_result is None


def test_register_cve_catalog():
    """Test CVE catalog tracking."""
    state = LoopState()
    state.register_tool_call(
        "key1", "cve_catalog", {"success": True}, {"query": "CVE-2024"}
    )
    assert state.last_cve_catalog_result is not None


def test_get_fallback_confidence():
    """Test fallback confidence calculation."""
    state = LoopState()
    assert state.get_fallback_confidence() == 0.3

    state.last_web_search_result = {"success": True}
    assert state.get_fallback_confidence() == 0.5


def test_elapsed_ms():
    """Test elapsed time calculation."""
    state = LoopState()
    elapsed = state.elapsed_ms()
    assert isinstance(elapsed, int)
    assert elapsed >= 0
