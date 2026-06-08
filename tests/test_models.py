"""Tests for SQLAlchemy models — schema validation only (no DB required)."""

from app.models.models import User, Alert, Task, AuditLog, ApiKey, LLMUsage


def test_user_model_fields():
    assert hasattr(User, "username")
    assert hasattr(User, "hashed_password")
    assert hasattr(User, "role")
    assert hasattr(User, "tenant_id")
    assert hasattr(User, "is_active")
    assert User.__tablename__ == "users"


def test_alert_model_fields():
    assert hasattr(Alert, "rule_id")
    assert hasattr(Alert, "src_ip")
    assert hasattr(Alert, "dst_ip")
    assert hasattr(Alert, "severity")
    assert hasattr(Alert, "status")
    assert hasattr(Alert, "verdict")
    assert hasattr(Alert, "confidence")
    assert hasattr(Alert, "ttp_ids")
    assert Alert.__tablename__ == "alerts"


def test_task_model_fields():
    assert hasattr(Task, "type")
    assert hasattr(Task, "priority")
    assert hasattr(Task, "status")
    assert hasattr(Task, "queue_name")
    assert hasattr(Task, "result")
    assert hasattr(Task, "cost_usd")
    assert Task.__tablename__ == "tasks"


def test_audit_log_model_fields():
    assert hasattr(AuditLog, "user_id")
    assert hasattr(AuditLog, "action")
    assert hasattr(AuditLog, "resource")
    assert hasattr(AuditLog, "detail")
    assert hasattr(AuditLog, "ip_address")
    assert AuditLog.__tablename__ == "audit_logs"


def test_api_key_model_fields():
    assert hasattr(ApiKey, "user_id")
    assert hasattr(ApiKey, "name")
    assert hasattr(ApiKey, "key_hash")
    assert hasattr(ApiKey, "scopes")
    assert hasattr(ApiKey, "expires_at")
    assert ApiKey.__tablename__ == "api_keys"


def test_llm_usage_model_fields():
    assert hasattr(LLMUsage, "provider")
    assert hasattr(LLMUsage, "model")
    assert hasattr(LLMUsage, "prompt_tokens")
    assert hasattr(LLMUsage, "completion_tokens")
    assert hasattr(LLMUsage, "cost_usd")
    assert LLMUsage.__tablename__ == "llm_usage"


def test_user_column_defaults():
    """Verify column defaults are defined (DB-level, not Python-level)."""
    col = User.__table__.columns
    assert col["role"].default.arg == "analyst"
    assert col["tenant_id"].default.arg == "default"
    assert col["is_active"].default.arg is True


def test_alert_column_defaults():
    col = Alert.__table__.columns
    assert col["severity"].default.arg == "medium"
    assert col["status"].default.arg == "open"


def test_task_column_defaults():
    col = Task.__table__.columns
    assert col["priority"].default.arg == 2
    assert col["status"].default.arg == "pending"
    assert col["queue_name"].default.arg == "default"
