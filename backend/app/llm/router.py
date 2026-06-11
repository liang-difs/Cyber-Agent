"""
LLM Router — 统一模型路由层。

所有 LLM 调用必须经过此模块。禁止绕过。
遵循 ADR-001: LiteLLM Router。
"""

from __future__ import annotations

import os
import time
import uuid
import logging
from typing import Any, AsyncIterator, Optional

import litellm
from pydantic import BaseModel, Field

from app.core.config import get_settings, get_llm_max_tokens
from app.llm.cache import get_llm_cache

logger = logging.getLogger(__name__)


def _default_max_tokens() -> int:
    return get_llm_max_tokens()


class LLMRequest(BaseModel):
    """LLM 调用请求"""

    messages: list[dict[str, Any]]
    model: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = Field(default_factory=_default_max_tokens)
    tools: Optional[list[dict[str, Any]]] = None
    stream: bool = False
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    tenant_id: str = "default"


class LLMResponse(BaseModel):
    """LLM 调用响应"""

    content: str
    model: str
    tool_calls: list[dict[str, Any]] = []
    usage: dict[str, int] = {}
    trace_id: str
    latency_ms: int
    reasoning_content: Optional[str] = None
    cost_usd: float = 0.0
    provider: str = ""


class LLMRouter:
    """
    统一 LLM 路由器。

    职责：
    - 路由到正确的模型
    - 管理 API Key
    - 处理 streaming
    - 记录指标
    """

    # LiteLLM provider prefix 映射
    PROVIDER_PREFIXES = {
        "deepseek": "deepseek",
        "claude": "anthropic",
        "gpt": "openai",
        "qwen": "openai",
    }

    def __init__(self):
        self.settings = get_settings()
        self.provider_hint = (self.settings.llm_provider or "").strip().lower()
        self.default_model = self._normalize_model(self.settings.llm_model or "claude-opus-4-7", provider_hint=self.provider_hint)
        self.base_url = self.settings.llm_base_url
        self.timeout = int(self.settings.llm_timeout)
        self.max_retries = int(self.settings.llm_max_retries)
        self.circuit_failure_threshold = int(self.settings.llm_circuit_failure_threshold)
        self.circuit_reset_seconds = int(self.settings.llm_circuit_reset_seconds)
        fallback_raw = self.settings.llm_fallback_models or os.getenv("LLM_FALLBACK_MODELS", "")
        self.fallback_models = [
            self._normalize_model(m.strip(), provider_hint=self.provider_hint)
            for m in fallback_raw.split(",")
            if m.strip()
        ]
        self.openai_api_key = self.settings.openai_api_key or os.getenv("OPENAI_API_KEY", "") or os.getenv("LLM_API_KEY", "")
        self.anthropic_api_key = self.settings.anthropic_api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.deepseek_api_key = self.settings.deepseek_api_key or os.getenv("DEEPSEEK_API_KEY", "")
        self.usage_events: list[dict[str, Any]] = []
        self.circuit_state: dict[str, dict[str, float | int]] = {}

        if self.base_url:
            logger.info("LLM base_url configured: %s (model=%s)", self.base_url, self.default_model)

    @classmethod
    def _normalize_model(cls, model: str, provider_hint: str = "") -> str:
        """自动补全 LiteLLM provider 前缀"""
        if "/" in model:
            return model
        for prefix, provider in cls.PROVIDER_PREFIXES.items():
            if model.startswith(prefix):
                return f"{provider}/{model}"
        if provider_hint in cls.PROVIDER_PREFIXES.values():
            return f"{provider_hint}/{model}"
        return model

    @staticmethod
    def _provider_for_model(model: str) -> str:
        if "/" in model:
            return model.split("/", 1)[0]
        for prefix, provider in LLMRouter.PROVIDER_PREFIXES.items():
            if model.startswith(prefix):
                return provider
        return ""

    def _resolve_api_key(self, model: str) -> str:
        provider = self._provider_for_model(model)
        if provider == "anthropic":
            return self.anthropic_api_key
        if provider == "deepseek":
            return self.deepseek_api_key
        if provider == "openai":
            if self.base_url:
                return self.openai_api_key or "EMPTY"
            return self.openai_api_key
        return self.openai_api_key or ""

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """同步调用（非 streaming）with caching"""
        start = time.time()

        # Check cache for non-streaming requests
        model = request.model or self.default_model
        cache = get_llm_cache()
        cached = cache.get(request.messages, model, request.temperature)
        if cached:
            logger.info("LLM cache hit for trace=%s", request.trace_id)
            cached["trace_id"] = request.trace_id
            cached["latency_ms"] = int((time.time() - start) * 1000)
            return LLMResponse(**cached)

        last_error: Exception | None = None
        for model in self._model_candidates(request.model):
            for attempt in range(self.max_retries + 1):
                try:
                    response = await self._acompletion(request, model=model, stream=False)
                    latency_ms = int((time.time() - start) * 1000)
                    llm_response = self._build_response(
                        response=response,
                        model=model,
                        request=request,
                        latency_ms=latency_ms,
                    )

                    # Cache successful response
                    cache.set(request.messages, model, request.temperature, llm_response.model_dump())

                    return llm_response
                except Exception as e:
                    last_error = e
                    logger.warning(
                        "LLM completion failed model=%s attempt=%d/%d trace=%s: %s",
                        model,
                        attempt + 1,
                        self.max_retries + 1,
                        request.trace_id,
                        e,
                    )
                    if attempt < self.max_retries:
                        await self._sleep_before_retry(attempt)
            self._record_failure(model)

        assert last_error is not None
        raise last_error

    async def _acompletion(self, request: LLMRequest, model: str, stream: bool):
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": request.messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "timeout": self.timeout,
        }

        if self.base_url:
            kwargs["api_base"] = self.base_url

        api_key = self._resolve_api_key(model)
        if api_key:
            kwargs["api_key"] = api_key

        if request.tools:
            kwargs["tools"] = request.tools

        if stream:
            kwargs["stream"] = True

        return await litellm.acompletion(**kwargs)

    def _build_response(self, response: Any, model: str, request: LLMRequest, latency_ms: int) -> LLMResponse:
        content = response.choices[0].message.content or ""
        reasoning_content = getattr(response.choices[0].message, "reasoning_content", None)
        tool_calls = []
        if response.choices[0].message.tool_calls:
            for tc in response.choices[0].message.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                })

        usage = {}
        if response.usage:
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }

        cost_usd = self._estimate_cost(response, model)
        provider = model.split("/", 1)[0] if "/" in model else ""
        llm_response = LLMResponse(
            content=content,
            model=model,
            tool_calls=tool_calls,
            usage=usage,
            trace_id=request.trace_id,
            latency_ms=latency_ms,
            reasoning_content=reasoning_content,
            cost_usd=cost_usd,
            provider=provider,
        )
        self._record_success(model)
        self._record_usage(llm_response, request)
        return llm_response

    async def stream(self, request: LLMRequest) -> AsyncIterator[dict[str, Any]]:
        """Streaming 调用。每个 chunk 是 {"content": str, "reasoning_content": str, "finish_reason": str?}."""
        response = None
        selected_model = ""
        last_error: Exception | None = None
        for model in self._model_candidates(request.model):
            try:
                response = await self._acompletion(request, model=model, stream=True)
                selected_model = model
                self._record_success(model)
                break
            except Exception as e:
                last_error = e
                logger.warning("LLM stream open failed model=%s trace=%s: %s", model, request.trace_id, e)
                self._record_failure(model)
                continue

        if response is None:
            assert last_error is not None
            raise last_error

        async for chunk in response:
            delta = chunk.choices[0].delta
            finish_reason = getattr(chunk.choices[0], "finish_reason", None)
            content = delta.content or ""
            reasoning = getattr(delta, "reasoning_content", None) or ""
            if content or reasoning:
                yield {"content": content, "reasoning_content": reasoning, "model": selected_model, "finish_reason": finish_reason}

    def _model_candidates(self, requested_model: Optional[str]) -> list[str]:
        primary = self._normalize_model(requested_model) if requested_model else self.default_model
        candidates = [primary]
        for model in self.fallback_models:
            if model not in candidates:
                candidates.append(model)
        available = [model for model in candidates if self._model_available(model)]
        return available or candidates

    def _model_available(self, model: str) -> bool:
        state = self.circuit_state.get(model)
        if not state:
            return True
        opened_until = float(state.get("opened_until", 0))
        if opened_until <= 0:
            return True
        if time.time() >= opened_until:
            state["opened_until"] = 0
            state["failures"] = 0
            return True
        return False

    def _record_success(self, model: str) -> None:
        self.circuit_state[model] = {"failures": 0, "opened_until": 0}

    def _record_failure(self, model: str) -> None:
        state = self.circuit_state.setdefault(model, {"failures": 0, "opened_until": 0})
        failures = int(state.get("failures", 0)) + 1
        state["failures"] = failures
        if failures >= self.circuit_failure_threshold:
            state["opened_until"] = time.time() + self.circuit_reset_seconds
            logger.warning(
                "LLM circuit opened model=%s failures=%d reset_seconds=%d",
                model,
                failures,
                self.circuit_reset_seconds,
            )

    @staticmethod
    async def _sleep_before_retry(attempt: int) -> None:
        import asyncio

        await asyncio.sleep(min(2 ** attempt, 4))

    @staticmethod
    def _estimate_cost(response: Any, model: str) -> float:
        try:
            cost = litellm.completion_cost(completion_response=response, model=model)
            return float(cost or 0.0)
        except Exception:
            return 0.0

    def _record_usage(self, response: LLMResponse, request: LLMRequest) -> None:
        event = {
            "trace_id": response.trace_id,
            "provider": response.provider,
            "model": response.model,
            "usage": response.usage,
            "cost_usd": response.cost_usd,
            "latency_ms": response.latency_ms,
            "user_id": request.user_id,
            "tenant_id": request.tenant_id,
        }
        self.usage_events.append(event)
        # Keep this lightweight and bounded; DB persistence can build on this.
        if len(self.usage_events) > 1000:
            del self.usage_events[:500]
        self._persist_usage_best_effort(event)

    def status(self) -> dict[str, Any]:
        """Return current model routing and circuit-breaker state."""
        now = time.time()
        circuits = {}
        for model in self._model_candidates_including_open():
            state = self.circuit_state.get(model, {"failures": 0, "opened_until": 0})
            opened_until = float(state.get("opened_until", 0) or 0)
            circuits[model] = {
                "failures": int(state.get("failures", 0) or 0),
                "open": opened_until > now,
                "reset_in_seconds": max(0, int(opened_until - now)) if opened_until > now else 0,
            }

        recent_usage = self.usage_events[-10:]
        total_cost = round(sum(float(e.get("cost_usd", 0.0) or 0.0) for e in self.usage_events), 6)

        # Include cache stats
        cache = get_llm_cache()
        cache_stats = cache.stats()

        return {
            "default_model": self.default_model,
            "base_url": self.base_url or "api",
            "provider_hint": self.provider_hint or "auto",
            "auth": {
                "openai_api_key": bool(self.openai_api_key),
                "anthropic_api_key": bool(self.anthropic_api_key),
                "deepseek_api_key": bool(self.deepseek_api_key),
            },
            "fallback_models": list(self.fallback_models),
            "timeout_seconds": self.timeout,
            "max_retries": self.max_retries,
            "circuit_failure_threshold": self.circuit_failure_threshold,
            "circuit_reset_seconds": self.circuit_reset_seconds,
            "circuits": circuits,
            "usage_event_count": len(self.usage_events),
            "total_cost_usd": total_cost,
            "recent_usage": recent_usage,
            "cache": cache_stats,
        }

    def _model_candidates_including_open(self) -> list[str]:
        candidates = [self.default_model]
        for model in self.fallback_models:
            if model not in candidates:
                candidates.append(model)
        for model in self.circuit_state:
            if model not in candidates:
                candidates.append(model)
        return candidates

    def switch_model(self, model: str, base_url: str = "") -> dict[str, Any]:
        """Switch the active LLM model at runtime. Returns the new config."""
        old_model = self.default_model
        old_url = self.base_url

        self.default_model = self._normalize_model(model)
        self.base_url = base_url
        # Reset circuit breaker for the new model
        self.circuit_state.pop(self.default_model, None)

        logger.info("LLM model switched: %s (%s) -> %s (%s)", old_model, old_url or "api", self.default_model, self.base_url or "api")

        return self.status()

    @staticmethod
    def _persist_usage_best_effort(event: dict[str, Any]) -> None:
        """Persist usage when a DB loop is available; never block LLM responses."""
        try:
            import asyncio

            loop = asyncio.get_running_loop()
            loop.create_task(LLMRouter._persist_usage(event))
        except RuntimeError:
            return
        except Exception as e:
            logger.debug("LLM usage persistence scheduling skipped: %s", e)

    @staticmethod
    async def _persist_usage(event: dict[str, Any]) -> None:
        try:
            from app.models.base import get_session_factory
            from app.models.models import LLMUsage

            factory = get_session_factory()
            usage = event.get("usage") or {}
            user_id = event.get("user_id") if _is_uuid(event.get("user_id")) else None
            async with factory() as session:
                session.add(LLMUsage(
                    user_id=user_id,
                    provider=event.get("provider") or "",
                    model=(event.get("model") or "")[:64],
                    prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
                    completion_tokens=int(usage.get("completion_tokens", 0) or 0),
                    cost_usd=float(event.get("cost_usd", 0.0) or 0.0),
                    tenant_id=event.get("tenant_id") or "default",
                ))
                await session.commit()
        except Exception as e:
            logger.debug("LLM usage persistence failed: %s", e)


def _is_uuid(value: Any) -> bool:
    if not value:
        return False
    try:
        uuid.UUID(str(value))
        return True
    except (TypeError, ValueError):
        return False


router = LLMRouter()
