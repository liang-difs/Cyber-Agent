"""Tests for admin initialization script helpers."""

from __future__ import annotations

import pytest

from app.scripts.init_admin import _parse_args


def test_parse_init_admin_args():
    args = _parse_args([
        "--username", "root",
        "--password", "change-me-123",
        "--email", "root@example.com",
        "--tenant-id", "tenant-x",
    ])

    assert args.username == "root"
    assert args.password == "change-me-123"
    assert args.email == "root@example.com"
    assert args.tenant_id == "tenant-x"


def test_parse_init_admin_defaults():
    args = _parse_args([])

    assert args.username == "admin"
    assert args.password == ""
    assert args.email is None
    assert args.tenant_id == "default"
