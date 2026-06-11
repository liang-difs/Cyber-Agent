"""Tests for retry logic."""

from __future__ import annotations

import asyncio

import pytest

from app.agent.retry import RetryConfig, retry_async


def test_retry_success_first():
    """Test successful call on first attempt."""
    call_count = 0

    async def success_func():
        nonlocal call_count
        call_count += 1
        return "ok"

    result = asyncio.run(retry_async(success_func, config=RetryConfig(max_retries=3, base_delay=0.01)))
    assert result == "ok"
    assert call_count == 1


def test_retry_success_after_failure():
    """Test successful call after transient failures."""
    call_count = 0

    async def eventually_success():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ConnectionError("transient")
        return "ok"

    result = asyncio.run(retry_async(
        eventually_success,
        config=RetryConfig(max_retries=3, base_delay=0.01),
    ))
    assert result == "ok"
    assert call_count == 3


def test_retry_exhausted():
    """Test failure after max retries."""
    call_count = 0

    async def always_fail():
        nonlocal call_count
        call_count += 1
        raise ConnectionError("permanent")

    with pytest.raises(ConnectionError):
        asyncio.run(retry_async(
            always_fail,
            config=RetryConfig(max_retries=2, base_delay=0.01),
        ))
    assert call_count == 3  # 1 initial + 2 retries


def test_retry_non_retryable_exception():
    """Test non-retryable exceptions are not retried."""
    call_count = 0

    async def raises_value_error():
        nonlocal call_count
        call_count += 1
        raise ValueError("not retryable")

    with pytest.raises(ValueError):
        asyncio.run(retry_async(
            raises_value_error,
            config=RetryConfig(max_retries=3, base_delay=0.01),
        ))
    assert call_count == 1


def test_retry_timeout_error():
    """Test timeout errors are retried."""
    call_count = 0

    async def timeout_then_success():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise TimeoutError("timeout")
        return "ok"

    result = asyncio.run(retry_async(
        timeout_then_success,
        config=RetryConfig(max_retries=2, base_delay=0.01),
    ))
    assert result == "ok"
    assert call_count == 2


def test_retry_preserves_args():
    """Test arguments are passed through retries."""
    received_args = []

    async def record_args(a, b, c=None):
        received_args.append((a, b, c))
        if len(received_args) < 2:
            raise ConnectionError("retry")
        return "done"

    result = asyncio.run(retry_async(
        record_args,
        "arg1",
        "arg2",
        config=RetryConfig(max_retries=2, base_delay=0.01),
        c="kwarg",
    ))
    assert result == "done"
    assert len(received_args) == 2
    assert received_args[0] == ("arg1", "arg2", "kwarg")
    assert received_args[1] == ("arg1", "arg2", "kwarg")
