"""Tests for ToolCache."""

from __future__ import annotations

import time

from app.agent.tool_cache import ToolCache


def test_cache_set_get():
    """Test basic cache set and get."""
    cache = ToolCache(max_size=10, ttl_seconds=60)
    cache.set("tool1", {"arg": "val"}, {"success": True})
    result = cache.get("tool1", {"arg": "val"})
    assert result == {"success": True}


def test_cache_miss():
    """Test cache miss returns None."""
    cache = ToolCache()
    result = cache.get("tool1", {"arg": "val"})
    assert result is None


def test_cache_different_args():
    """Test different arguments produce different cache keys."""
    cache = ToolCache()
    cache.set("tool1", {"arg": "val1"}, {"result": 1})
    cache.set("tool1", {"arg": "val2"}, {"result": 2})
    assert cache.get("tool1", {"arg": "val1"}) == {"result": 1}
    assert cache.get("tool1", {"arg": "val2"}) == {"result": 2}


def test_cache_expiry():
    """Test cache entries expire after TTL."""
    cache = ToolCache(ttl_seconds=0)
    cache.set("tool1", {"arg": "val"}, {"success": True})
    time.sleep(0.1)
    result = cache.get("tool1", {"arg": "val"})
    assert result is None


def test_cache_eviction():
    """Test LRU eviction when cache is full."""
    cache = ToolCache(max_size=2)
    cache.set("t1", {}, {"v": 1})
    cache.set("t2", {}, {"v": 2})
    cache.set("t3", {}, {"v": 3})  # Should evict t1
    assert cache.get("t1", {}) is None
    assert cache.get("t2", {}) == {"v": 2}
    assert cache.get("t3", {}) == {"v": 3}


def test_cache_lru_order():
    """Test LRU eviction order."""
    cache = ToolCache(max_size=2)
    cache.set("t1", {}, {"v": 1})
    cache.set("t2", {}, {"v": 2})
    cache.get("t1", {})  # Access t1 to make it recently used
    cache.set("t3", {}, {"v": 3})  # Should evict t2 (least recently used)
    assert cache.get("t1", {}) == {"v": 1}
    assert cache.get("t2", {}) is None
    assert cache.get("t3", {}) == {"v": 3}


def test_cache_clear():
    """Test cache clear."""
    cache = ToolCache()
    cache.set("t1", {}, {"v": 1})
    cache.set("t2", {}, {"v": 2})
    cache.clear()
    assert cache.get("t1", {}) is None
    assert cache.get("t2", {}) is None


def test_cache_stats():
    """Test cache statistics."""
    cache = ToolCache(max_size=10, ttl_seconds=60)
    cache.set("t1", {}, {"v": 1})
    cache.get("t1", {})  # Hit
    cache.get("t2", {})  # Miss

    stats = cache.stats()
    assert stats["size"] == 1
    assert stats["max_size"] == 10
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["hit_rate"] == 0.5


def test_cache_stats_empty():
    """Test cache stats when empty."""
    cache = ToolCache()
    stats = cache.stats()
    assert stats["hit_rate"] == 0.0
