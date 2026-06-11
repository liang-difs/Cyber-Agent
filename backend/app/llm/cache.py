"""LLM response cache to avoid redundant API calls.

Provides caching for LLM responses to avoid redundant API calls
for identical inputs within the TTL window.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import Any, Optional

logger = logging.getLogger(__name__)


class LLMCache:
    """LRU cache for LLM responses with TTL expiration.

    Args:
        max_size: Maximum number of cached entries
        ttl_seconds: Time-to-live for cache entries
    """

    def __init__(self, max_size: int = 50, ttl_seconds: int = 600):
        self._cache: OrderedDict[str, tuple[dict[str, Any], float]] = OrderedDict()
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._hits = 0
        self._misses = 0

    def _make_key(self, messages: list[dict[str, Any]], model: str, temperature: float) -> str:
        """Generate cache key from request parameters."""
        content = json.dumps({
            "messages": messages,
            "model": model,
            "temperature": temperature,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def get(self, messages: list[dict[str, Any]], model: str, temperature: float) -> Optional[dict[str, Any]]:
        """Get cached response if available and not expired.

        Returns:
            Cached response dict or None if miss/expired
        """
        key = self._make_key(messages, model, temperature)
        if key not in self._cache:
            self._misses += 1
            return None

        response, timestamp = self._cache[key]
        if time.time() - timestamp > self._ttl_seconds:
            del self._cache[key]
            self._misses += 1
            return None

        self._cache.move_to_end(key)
        self._hits += 1
        return response

    def set(self, messages: list[dict[str, Any]], model: str, temperature: float, response: dict[str, Any]) -> None:
        """Cache an LLM response."""
        key = self._make_key(messages, model, temperature)
        self._cache[key] = (response, time.time())
        self._cache.move_to_end(key)

        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all cached responses."""
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
_llm_cache: Optional[LLMCache] = None


def get_llm_cache() -> LLMCache:
    """Get or create the global LLM cache instance."""
    global _llm_cache
    if _llm_cache is None:
        _llm_cache = LLMCache(max_size=50, ttl_seconds=600)
    return _llm_cache
