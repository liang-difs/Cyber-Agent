"""Tests for chat context session isolation."""

import pytest

from app.agent.context import ContextManager, Conversation


@pytest.mark.anyio
async def test_get_session_checks_tenant():
    manager = ContextManager()
    conversation = Conversation(session_id="session-1", tenant_id="tenant-a")
    manager._memory_store[conversation.session_id] = conversation

    assert await manager.get_session(conversation.session_id, "tenant-a") is conversation
    assert await manager.get_session(conversation.session_id, "tenant-b") is None
