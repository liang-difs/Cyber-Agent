"""Retry logic with exponential backoff for transient failures."""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class RetryConfig:
    """Retry configuration.

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds between retries
        max_delay: Maximum delay in seconds
        exponential_base: Multiplier for exponential backoff
        retryable_exceptions: Tuple of exception types to retry on
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 10.0,
        exponential_base: float = 2.0,
        retryable_exceptions: tuple[type[Exception], ...] = (ConnectionError, TimeoutError),
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.retryable_exceptions = retryable_exceptions


async def retry_async(
    func: Callable[..., Any],
    *args: Any,
    config: Optional[RetryConfig] = None,
    **kwargs: Any,
) -> Any:
    """Execute async function with retry logic.

    Args:
        func: Async function to execute
        *args: Positional arguments for func
        config: Retry configuration (uses defaults if None)
        **kwargs: Keyword arguments for func

    Returns:
        Result of func call

    Raises:
        Last exception if all retries fail
    """
    if config is None:
        config = RetryConfig()

    last_exception: Optional[Exception] = None

    for attempt in range(config.max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except config.retryable_exceptions as e:
            last_exception = e
            if attempt < config.max_retries:
                delay = min(
                    config.base_delay * (config.exponential_base ** attempt),
                    config.max_delay,
                )
                # Add jitter to prevent thundering herd
                jitter = random.uniform(0, delay * 0.1)
                delay += jitter

                logger.warning(
                    "Retry %d/%d for %s after %.1fs: %s",
                    attempt + 1,
                    config.max_retries,
                    getattr(func, "__name__", str(func)),
                    delay,
                    str(e),
                )
                await asyncio.sleep(delay)
            else:
                logger.error(
                    "Max retries (%d) exceeded for %s: %s",
                    config.max_retries,
                    getattr(func, "__name__", str(func)),
                    str(e),
                )

    raise last_exception  # type: ignore[misc]


# Pre-configured retry configs for common tools
TOOL_RETRY_CONFIGS: dict[str, RetryConfig] = {
    "web_search": RetryConfig(max_retries=2, base_delay=0.5),
    "threat_intel": RetryConfig(max_retries=2, base_delay=1.0),
    "ioc_lookup": RetryConfig(max_retries=2, base_delay=0.5),
    "nmap_scan": RetryConfig(max_retries=1, base_delay=2.0),
    "vuln_scan": RetryConfig(max_retries=1, base_delay=2.0),
}
