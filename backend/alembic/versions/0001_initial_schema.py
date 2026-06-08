"""initial schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-05-29 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _existing_tables() -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return set(inspector.get_table_names())


def _create_indexes_for_users() -> None:
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"], unique=False)


def _create_indexes_for_alerts() -> None:
    op.create_index("idx_alerts_src_ip_created", "alerts", ["src_ip", "created_at"], unique=False)
    op.create_index("idx_alerts_tenant_status", "alerts", ["tenant_id", "status"], unique=False)


def _create_indexes_for_tasks() -> None:
    op.create_index("idx_tasks_status_priority", "tasks", ["status", "priority"], unique=False)
    op.create_index("idx_tasks_tenant_created", "tasks", ["tenant_id", "created_at"], unique=False)


def _create_indexes_for_audit_logs() -> None:
    op.create_index("idx_audit_logs_user_created", "audit_logs", ["user_id", "created_at"], unique=False)


def _create_indexes_for_llm_usage() -> None:
    op.create_index("idx_llm_usage_user_date", "llm_usage", ["user_id", "created_at"], unique=False)


def _create_indexes_for_chat_sessions() -> None:
    op.create_index("idx_chat_sessions_tenant_updated", "chat_sessions", ["tenant_id", "updated_at"], unique=False)
    op.create_index("idx_chat_sessions_user_updated", "chat_sessions", ["user_id", "updated_at"], unique=False)


def _create_indexes_for_chat_messages() -> None:
    op.create_index("idx_chat_messages_session_seq", "chat_messages", ["session_id", "seq"], unique=False)
    op.create_index("idx_chat_messages_tenant_created", "chat_messages", ["tenant_id", "created_at"], unique=False)


def upgrade() -> None:
    existing_tables = _existing_tables()

    if "users" not in existing_tables:
        op.create_table(
            "users",
            sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True, nullable=False),
            sa.Column("username", sa.String(length=64), nullable=False),
            sa.Column("email", sa.String(length=256), nullable=True),
            sa.Column("hashed_password", sa.String(length=256), nullable=False),
            sa.Column("role", sa.String(length=32), nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("email", name="uq_users_email"),
        )
        _create_indexes_for_users()

    if "alerts" not in existing_tables:
        op.create_table(
            "alerts",
            sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True, nullable=False),
            sa.Column("rule_id", sa.String(length=128), nullable=False),
            sa.Column("src_ip", sa.String(length=45), nullable=True),
            sa.Column("dst_ip", sa.String(length=45), nullable=True),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("verdict", sa.String(length=32), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("ttp_ids", sa.JSON(), nullable=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        _create_indexes_for_alerts()

    if "tasks" not in existing_tables:
        op.create_table(
            "tasks",
            sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True, nullable=False),
            sa.Column("type", sa.String(length=64), nullable=False),
            sa.Column("priority", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("queue_name", sa.String(length=64), nullable=False),
            sa.Column("input_ref", sa.String(length=512), nullable=True),
            sa.Column("result", sa.JSON(), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("cost_usd", sa.Float(), nullable=False),
            sa.Column("created_by", postgresql.UUID(as_uuid=False), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        )
        _create_indexes_for_tasks()

    if "audit_logs" not in existing_tables:
        op.create_table(
            "audit_logs",
            sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True, nullable=False),
            sa.Column("user_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("action", sa.String(length=32), nullable=False),
            sa.Column("resource", sa.String(length=128), nullable=False),
            sa.Column("detail", sa.JSON(), nullable=True),
            sa.Column("ip_address", sa.String(length=45), nullable=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        _create_indexes_for_audit_logs()

    if "api_keys" not in existing_tables:
        op.create_table(
            "api_keys",
            sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True, nullable=False),
            sa.Column("user_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("name", sa.String(length=64), nullable=False),
            sa.Column("key_hash", sa.String(length=256), nullable=False),
            sa.Column("scopes", sa.JSON(), nullable=True),
            sa.Column("last_used", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    if "llm_usage" not in existing_tables:
        op.create_table(
            "llm_usage",
            sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True, nullable=False),
            sa.Column("user_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("model", sa.String(length=64), nullable=False),
            sa.Column("prompt_tokens", sa.Integer(), nullable=False),
            sa.Column("completion_tokens", sa.Integer(), nullable=False),
            sa.Column("cost_usd", sa.Float(), nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        _create_indexes_for_llm_usage()

    if "chat_sessions" not in existing_tables:
        op.create_table(
            "chat_sessions",
            sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True, nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("user_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("title", sa.String(length=256), nullable=False),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("last_message_preview", sa.Text(), nullable=True),
            sa.Column("model_name", sa.String(length=64), nullable=True),
            sa.Column("message_count", sa.Integer(), nullable=False),
            sa.Column("extra_data", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_message_at", sa.DateTime(timezone=True), nullable=True),
        )
        _create_indexes_for_chat_sessions()

    if "chat_messages" not in existing_tables:
        op.create_table(
            "chat_messages",
            sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True, nullable=False),
            sa.Column(
                "session_id",
                postgresql.UUID(as_uuid=False),
                sa.ForeignKey("chat_sessions.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("seq", sa.Integer(), nullable=False),
            sa.Column("role", sa.String(length=16), nullable=False),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("thinking", sa.Text(), nullable=True),
            sa.Column("tool_calls", sa.JSON(), nullable=True),
            sa.Column("tool_call_id", sa.String(length=128), nullable=True),
            sa.Column("extra_data", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        _create_indexes_for_chat_messages()


def downgrade() -> None:
    existing_tables = _existing_tables()

    if "chat_messages" in existing_tables:
        op.drop_index("idx_chat_messages_tenant_created", table_name="chat_messages")
        op.drop_index("idx_chat_messages_session_seq", table_name="chat_messages")
        op.drop_table("chat_messages")

    if "chat_sessions" in existing_tables:
        op.drop_index("idx_chat_sessions_user_updated", table_name="chat_sessions")
        op.drop_index("idx_chat_sessions_tenant_updated", table_name="chat_sessions")
        op.drop_table("chat_sessions")

    if "llm_usage" in existing_tables:
        op.drop_index("idx_llm_usage_user_date", table_name="llm_usage")
        op.drop_table("llm_usage")

    if "api_keys" in existing_tables:
        op.drop_table("api_keys")

    if "audit_logs" in existing_tables:
        op.drop_index("idx_audit_logs_user_created", table_name="audit_logs")
        op.drop_table("audit_logs")

    if "tasks" in existing_tables:
        op.drop_index("idx_tasks_tenant_created", table_name="tasks")
        op.drop_index("idx_tasks_status_priority", table_name="tasks")
        op.drop_table("tasks")

    if "alerts" in existing_tables:
        op.drop_index("idx_alerts_tenant_status", table_name="alerts")
        op.drop_index("idx_alerts_src_ip_created", table_name="alerts")
        op.drop_table("alerts")

    if "users" in existing_tables:
        op.drop_index("ix_users_tenant_id", table_name="users")
        op.drop_index("ix_users_username", table_name="users")
        op.drop_table("users")
