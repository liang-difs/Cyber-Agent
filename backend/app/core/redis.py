"""Shared Redis async client — singleton with connection pooling."""

from __future__ import annotations

import logging
from typing import Optional

import redis.asyncio as redis

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_client: Optional[redis.Redis] = None


async def get_redis() -> Optional[redis.Redis]:
    """Return a shared Redis client, or None if Redis is not configured."""
    global _client
    settings = get_settings()
    if not settings.redis_url:
        return None
    if _client is None:
        try:
            _client = redis.from_url(settings.redis_url, decode_responses=True)
            await _client.ping()
        except Exception as e:
            logger.warning("Redis connection failed: %s", e)
            _client = None
    return _client


async def close_redis() -> None:
    """Shutdown the shared Redis client."""
    global _client
    if _client is not None:
        try:
            await _client.aclose()
        except Exception:
            pass
        _client = None
