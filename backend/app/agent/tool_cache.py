"""Tool result cache with TTL and LRU eviction.

Provides caching for tool results to avoid redundant API calls
for identical queries within the TTL window.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ToolCache:
    """LRU cache for tool results with TTL expiration.

    Args:
        max_size: Maximum number of cached entries
        ttl_seconds: Time-to-live for cache entries
    """

    def __init__(self, max_size: int = 100, ttl_seconds: int = 300):
        self._cache: OrderedDict[str, tuple[dict[str, Any], float]] = OrderedDict()
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._hits = 0
        self._misses = 0

    def _make_key(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Generate cache key from tool name and arguments."""
        content = json.dumps({"tool": tool_name, "args": arguments}, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def get(self, tool_name: str, arguments: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Get cached result if available and not expired.

        Returns:
            Cached result dict or None if miss/expired
        """
        key = self._make_key(tool_name, arguments)
        if key not in self._cache:
            self._misses += 1
            return None

        result, timestamp = self._cache[key]
        if time.time() - timestamp > self._ttl_seconds:
            del self._cache[key]
            self._misses += 1
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        self._hits += 1
        return result

    def set(self, tool_name: str, arguments: dict[str, Any], result: dict[str, Any]) -> None:
        """Cache a tool result."""
        key = self._make_key(tool_name, arguments)
        self._cache[key] = (result, time.time())
        self._cache.move_to_end(key)

        # Evict oldest if over capacity
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache.clear()

    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "max_size": self._max_size,
            "ttl_seconds": self._ttl_seconds,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 3) if total > 0 else 0.0,
        }


# Global instance
_tool_cache: Optional[ToolCache] = None


def get_tool_cache() -> ToolCache:
    """Get or create the global tool cache instance."""
    global _tool_cache
    if _tool_cache is None:
        _tool_cache = ToolCache(max_size=100, ttl_seconds=300)
    return _tool_cache
