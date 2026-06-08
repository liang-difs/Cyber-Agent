"""RBAC permission definitions and role-based access control."""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable, Set

from fastapi import HTTPException


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Permission(str, Enum):
    # Chat & Agent
    CHAT = "chat"
    CHAT_STREAM = "chat_stream"

    # Tools
    TOOL_CVE = "tool:cve"
    TOOL_IOC = "tool:ioc"
    TOOL_IP = "tool:ip"
    TOOL_RAG = "tool:rag"
    TOOL_WEB = "tool:web"

    # Tasks
    TASK_SUBMIT = "task:submit"
    TASK_VIEW = "task:view"
    TASK_CANCEL = "task:cancel"

    # Alerts
    ALERT_VIEW = "alert:view"
    ALERT_TRIAGE = "alert:triage"
    ALERT_MANAGE = "alert:manage"

    # Reports
    REPORT_VIEW = "report:view"
    REPORT_GENERATE = "report:generate"

    # Admin
    USER_MANAGE = "user:manage"
    SYSTEM_CONFIG = "system:config"
    AUDIT_VIEW = "audit:view"


# Role → permissions mapping
ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.VIEWER: {
        Permission.CHAT,
        Permission.TOOL_CVE,
        Permission.TOOL_IOC,
        Permission.TOOL_IP,
        Permission.TOOL_RAG,
        Permission.TOOL_WEB,
        Permission.TASK_VIEW,
        Permission.ALERT_VIEW,
        Permission.REPORT_VIEW,
    },
    Role.ANALYST: {
        # All viewer permissions
        Permission.CHAT,
        Permission.CHAT_STREAM,
        Permission.TOOL_CVE,
        Permission.TOOL_IOC,
        Permission.TOOL_IP,
        Permission.TOOL_RAG,
        Permission.TOOL_WEB,
        Permission.TASK_VIEW,
        Permission.TASK_SUBMIT,
        Permission.ALERT_VIEW,
        Permission.ALERT_TRIAGE,
        Permission.REPORT_VIEW,
        Permission.REPORT_GENERATE,
    },
    Role.ADMIN: set(Permission),  # All permissions
}


def get_role_permissions(role: str) -> Set[Permission]:
    """Get permissions for a role string."""
    try:
        r = Role(role)
    except ValueError:
        return set()
    return ROLE_PERMISSIONS.get(r, set())


def has_permission(role: str, permission: Permission) -> bool:
    """Check if a role has a specific permission."""
    return permission in get_role_permissions(role)


def require_permission(permission: Permission, *, auth: Callable[..., Any]) -> Callable[..., None]:
    """Return a FastAPI dependency that enforces *permission* on the current user.

    *auth* must be the same ``Depends(get_current_user)`` wrapper used by the
    endpoint so that test dependency overrides apply to both.

    Uses a closure with ``Depends(auth)`` so FastAPI resolves the user from
    the same dependency chain as the endpoint.
    """

    async def checker(user: dict[str, Any] = auth) -> None:
        user_role = user.get("role", "viewer")
        if not has_permission(user_role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: {permission.value} required",
            )

    return checker
