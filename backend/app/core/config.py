"""Centralized application settings."""

import logging
from functools import lru_cache
from typing import Optional

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    # Environment
    app_env: str = "development"

    # LLM
    llm_provider: str = Field(
        default="auto",
        validation_alias=AliasChoices("LLM_PROVIDER", "llm_provider"),
    )
    llm_model: str = "deepseek-v4-flash"
    llm_base_url: str = ""
    llm_fallback_models: str = ""
    llm_max_retries: int = 2
    llm_timeout: int = 30
    llm_max_tokens: int = Field(
        default=16384,
        validation_alias=AliasChoices(
            "LLM_MAX_TOKENS",
            "LLM_MAX_TOKEN",
            "MAX_TOKENS",
            "MAX_TOKEN",
            "llm_max_tokens",
            "llm_max_token",
            "max_tokens",
            "max_token",
        ),
    )
    llm_circuit_failure_threshold: int = 3
    llm_circuit_reset_seconds: int = 60
    deepseek_api_key: str = ""
    openai_api_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "OPENAI_API_KEY",
            "LLM_API_KEY",
            "openai_api_key",
            "llm_api_key",
        ),
    )
    anthropic_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("ANTHROPIC_API_KEY", "anthropic_api_key"),
    )

    # VirusTotal
    vt_api_key: str = ""

    # NVD
    nvd_api_key: str = ""

    # OTX AlienVault
    otx_api_key: str = ""

    # AbuseIPDB
    abuseipdb_api_key: str = ""

    # Shodan
    shodan_api_key: str = ""

    # GreyNoise
    greynoise_api_key: str = ""

    # SearXNG
    searxng_url: str = "http://localhost:8888"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # PostgreSQL
    database_url: str = "postgresql+asyncpg://cybersec:cybersec_pass@localhost:5432/cybersec"

    # Celery
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # MinIO
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin123"
    minio_bucket: str = "cybersec"

    # Elasticsearch
    elasticsearch_url: str = "http://localhost:9200"

    # JWT
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    auth_dev_fallback_enabled: Optional[bool] = None

    # CORS
    cors_origins: str = "http://localhost:3000"

    # Agent
    react_max_turns: int = 10
    react_max_tool_retries: int = 3
    ctx_compress_threshold: int = 8000
    ctx_obs_max_tokens: int = 2000
    ctx_history_summary_interval: int = 4

    # WebSocket
    ws_heartbeat_interval: int = 30

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }

    @model_validator(mode="after")
    def _apply_env_defaults(self):
        is_production = self.app_env.lower() == "production"

        if self.auth_dev_fallback_enabled is None:
            self.auth_dev_fallback_enabled = not is_production

        if is_production:
            if self.auth_dev_fallback_enabled:
                raise ValueError("AUTH_DEV_FALLBACK_ENABLED must be false in production.")
            if not self.jwt_secret:
                raise ValueError("JWT_SECRET must be configured in production.")
        return self


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if not s.jwt_secret:
        if s.app_env.lower() == "production":
            raise ValueError("JWT_SECRET must be configured in production.")
        import secrets
        s.jwt_secret = secrets.token_urlsafe(32)
        logger.warning(
            "JWT_SECRET not set — generated random ephemeral key for dev. "
            "Set JWT_SECRET in .env for persistent tokens."
        )
    return s


@lru_cache
def get_llm_max_tokens() -> int:
    return Settings().llm_max_tokens
