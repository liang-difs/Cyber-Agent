"""Tests for persisted chat context reload."""

from __future__ import annotations

import uuid

import pytest

from app.agent.context import ContextManager, Message
from app.models.base import close_db


@pytest.mark.anyio
async def test_context_manager_persists_and_reload_from_db():
    tenant_id = f"tenant-{uuid.uuid4()}"
    await close_db()

    manager = ContextManager()
    conversation = await manager.create_session(tenant_id)
    saved = await manager.add_message(
        conversation.session_id,
        Message(role="user", content="请确认这条消息能从数据库重新读回"),
    )
    assert saved is True

    manager._memory_store.pop(conversation.session_id, None)

    reloaded = await manager.get_session(conversation.session_id, tenant_id)
    assert reloaded is not None
    assert reloaded.session_id == conversation.session_id
    assert reloaded.tenant_id == tenant_id
    assert reloaded.message_count == 1

    messages = await manager.get_session_messages(conversation.session_id, tenant_id)
    assert len(messages) == 1
    assert messages[0]["role"] == "user"
    assert messages[0]["content"] == "请确认这条消息能从数据库重新读回"

    await close_db()
