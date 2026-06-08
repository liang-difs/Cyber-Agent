"""SQLAlchemy ORM models — Phase 3 core tables."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    JSON,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[Optional[str]] = mapped_column(String(256), unique=True, nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="analyst")
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    audit_logs: Mapped[List["AuditLog"]] = relationship(back_populates="user")
    api_keys: Mapped[List["ApiKey"]] = relationship(back_populates="user")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(45))
    dst_ip: Mapped[Optional[str]] = mapped_column(String(45))
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(32), default="open")
    verdict: Mapped[Optional[str]] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    description: Mapped[Optional[str]] = mapped_column(Text)
    ttp_ids: Mapped[Optional[dict]] = mapped_column(JSON)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("idx_alerts_src_ip_created", "src_ip", "created_at"),
        Index("idx_alerts_tenant_status", "tenant_id", "status"),
    )


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    queue_name: Mapped[str] = mapped_column(String(64), default="default")
    input_ref: Mapped[Optional[str]] = mapped_column(String(512))
    result: Mapped[Optional[dict]] = mapped_column(JSON)
    error: Mapped[Optional[str]] = mapped_column(Text)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    created_by: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"))
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("idx_tasks_status_priority", "status", "priority"),
        Index("idx_tasks_tenant_created", "tenant_id", "created_at"),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    resource: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[Optional[dict]] = mapped_column(JSON)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    tenant_id: Mapped[str] = mapped_column(String(64), default="default")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    user: Mapped[Optional["User"]] = relationship(back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_logs_user_created", "user_id", "created_at"),
    )


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    scopes: Mapped[Optional[dict]] = mapped_column(JSON)
    last_used: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    user: Mapped["User"] = relationship(back_populates="api_keys")


class LLMUsage(Base):
    __tablename__ = "llm_usage"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(64))
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("idx_llm_usage_user_date", "user_id", "created_at"),
    )


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(256), default="新会话")
    summary: Mapped[Optional[str]] = mapped_column(Text)
    last_message_preview: Mapped[Optional[str]] = mapped_column(Text)
    model_name: Mapped[Optional[str]] = mapped_column(String(64))
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    extra_data: Mapped[Optional[dict]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    last_message_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    messages: Mapped[List["ChatMessage"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="ChatMessage.seq",
    )

    __table_args__ = (
        Index("idx_chat_sessions_tenant_updated", "tenant_id", "updated_at"),
        Index("idx_chat_sessions_user_updated", "user_id", "updated_at"),
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("chat_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    thinking: Mapped[Optional[str]] = mapped_column(Text)
    tool_calls: Mapped[Optional[list]] = mapped_column(JSON)
    tool_call_id: Mapped[Optional[str]] = mapped_column(String(128))
    extra_data: Mapped[Optional[dict]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    session: Mapped["ChatSession"] = relationship(back_populates="messages")

    __table_args__ = (
        Index("idx_chat_messages_session_seq", "session_id", "seq"),
        Index("idx_chat_messages_tenant_created", "tenant_id", "created_at"),
    )


class Asset(Base):
    """CMDB asset — hosts, servers, network devices tracked by the SOC."""
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(32), default="host")  # host, server, network, application
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(256))
    os: Mapped[Optional[str]] = mapped_column(String(128))
    owner: Mapped[Optional[str]] = mapped_column(String(128))
    department: Mapped[Optional[str]] = mapped_column(String(128))
    criticality: Mapped[str] = mapped_column(String(16), default="medium")  # critical, high, medium, low
    status: Mapped[str] = mapped_column(String(32), default="active")  # active, inactive, decommissioned
    tags: Mapped[Optional[list]] = mapped_column(JSON)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("idx_assets_tenant_ip", "tenant_id", "ip_address"),
        Index("idx_assets_tenant_name", "tenant_id", "name"),
    )


class ResponseAction(Base):
    """Response action execution history — persists all automated responses."""
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    action_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")  # pending, success, failed, rolled_back
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    message: Mapped[Optional[str]] = mapped_column(Text)
    details: Mapped[Optional[dict]] = mapped_column(JSON)
    params: Mapped[Optional[dict]] = mapped_column(JSON)
    rollback_available: Mapped[bool] = mapped_column(Boolean, default=False)
    rolled_back: Mapped[bool] = mapped_column(Boolean, default=False)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    execution_time_ms: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        Index("idx_response_actions_tenant_type", "tenant_id", "action_type"),
        Index("idx_response_actions_tenant_created", "tenant_id", "created_at"),
    )


class DecisionTraceRecord(Base):
    """Decision trace — persists agent reasoning chains for auditability."""
    __tablename__ = "decision_traces"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # trace_id
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(String(64), default="unknown")
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    query: Mapped[str] = mapped_column(Text)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    total_duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[Optional[str]] = mapped_column(Text)
    final_answer: Mapped[Optional[str]] = mapped_column(Text)
    final_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    steps_json: Mapped[Optional[dict]] = mapped_column(JSON)  # Full step data
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("idx_decision_traces_tenant_created", "tenant_id", "created_at"),
        Index("idx_decision_traces_user", "user_id", "created_at"),
    )
