"""Tests for RBAC permissions."""

import pytest
from app.rbac.permissions import (
    Role, Permission, get_role_permissions, has_permission, ROLE_PERMISSIONS
)


def test_viewer_has_basic_permissions():
    perms = get_role_permissions("viewer")
    assert Permission.CHAT in perms
    assert Permission.TOOL_CVE in perms
    assert Permission.ALERT_VIEW in perms
    assert Permission.REPORT_VIEW in perms


def test_viewer_lacks_admin_permissions():
    perms = get_role_permissions("viewer")
    assert Permission.USER_MANAGE not in perms
    assert Permission.SYSTEM_CONFIG not in perms
    assert Permission.TASK_SUBMIT not in perms


def test_analyst_has_extended_permissions():
    perms = get_role_permissions("analyst")
    assert Permission.TASK_SUBMIT in perms
    assert Permission.ALERT_TRIAGE in perms
    assert Permission.REPORT_GENERATE in perms
    assert Permission.CHAT_STREAM in perms


def test_analyst_lacks_admin_permissions():
    perms = get_role_permissions("analyst")
    assert Permission.USER_MANAGE not in perms
    assert Permission.SYSTEM_CONFIG not in perms
    assert Permission.AUDIT_VIEW not in perms


def test_admin_has_all_permissions():
    perms = get_role_permissions("admin")
    assert perms == set(Permission)


def test_unknown_role_has_no_permissions():
    perms = get_role_permissions("unknown")
    assert perms == set()


def test_has_permission_positive():
    assert has_permission("admin", Permission.USER_MANAGE) is True
    assert has_permission("analyst", Permission.TASK_SUBMIT) is True
    assert has_permission("viewer", Permission.CHAT) is True


def test_has_permission_negative():
    assert has_permission("viewer", Permission.USER_MANAGE) is False
    assert has_permission("analyst", Permission.AUDIT_VIEW) is False


def test_role_enum_values():
    assert Role.ADMIN == "admin"
    assert Role.ANALYST == "analyst"
    assert Role.VIEWER == "viewer"
