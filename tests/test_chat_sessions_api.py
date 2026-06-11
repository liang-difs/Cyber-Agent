"""Tests for persisted chat session APIs."""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.security import create_access_token
from app.core.config import get_settings
from app.agent.context import context_manager, Message
from app.models.base import close_db
from app.main import app


def auth_headers(*, user_id: str, tenant_id: str) -> dict[str, str]:
    token = create_access_token(
        {"sub": user_id, "role": "analyst", "tenant_id": tenant_id},
        secret=get_settings().jwt_secret,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.anyio
async def test_chat_session_persists_messages_and_scopes_tenant():
    tenant_id = f"tenant-{uuid.uuid4()}"
    other_tenant_id = f"tenant-{uuid.uuid4()}"
    headers = auth_headers(user_id="user-001", tenant_id=tenant_id)
    other_headers = auth_headers(user_id="user-002", tenant_id=other_tenant_id)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        create_resp = await client.post("/api/v1/agent/sessions", headers=headers)
        assert create_resp.status_code == 200
        created = create_resp.json()
        session_id = created["id"]
        assert created["tenantId"] == tenant_id
        assert created["messageCount"] == 0

        list_resp = await client.get("/api/v1/agent/sessions", headers=headers)
        assert list_resp.status_code == 200
        sessions = list_resp.json()
        assert len(sessions) == 1
        assert sessions[0]["id"] == session_id
        assert sessions[0]["tenantId"] == tenant_id
        assert sessions[0]["messageCount"] == 0

        messages_resp = await client.get(
            f"/api/v1/agent/sessions/{session_id}/messages",
            headers=headers,
        )
        assert messages_resp.status_code == 200
        assert messages_resp.json() == []

        forbidden_resp = await client.get(
            f"/api/v1/agent/sessions/{session_id}",
            headers=other_headers,
        )
        assert forbidden_resp.status_code == 404

        delete_resp = await client.delete(
            f"/api/v1/agent/sessions/{session_id}",
            headers=headers,
        )
        assert delete_resp.status_code == 200
        assert delete_resp.json()["success"] is True

        not_found_resp = await client.get(
            f"/api/v1/agent/sessions/{session_id}",
            headers=headers,
        )
        assert not_found_resp.status_code == 404


@pytest.mark.anyio
async def test_chat_session_messages_hide_bootstrap_tool_protocol_messages():
    tenant_id = f"tenant-{uuid.uuid4()}"
    headers = auth_headers(user_id="user-001", tenant_id=tenant_id)

    await close_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        create_resp = await client.post("/api/v1/agent/sessions", headers=headers)
        assert create_resp.status_code == 200
        session_id = create_resp.json()["id"]

        await context_manager.add_message(session_id, Message(role="user", content="请分析附件"))
        await context_manager.add_message(
            session_id,
            Message(
                role="assistant",
                content='{"thought":"检测到 PCAP 请求，自动调用 pcap_analysis","action":"pcap_analysis"}',
                tool_calls=[{"id": "call-1", "type": "function", "function": {"name": "pcap_analysis", "arguments": "{}"}}],
                metadata={"bootstrap": "pcap_analysis", "hidden_in_ui": True},
            ),
        )
        await context_manager.add_message(
            session_id,
            Message(
                role="tool",
                content='{"success": true}',
                tool_call_id="call-1",
                metadata={"bootstrap": "pcap_analysis", "hidden_in_ui": True},
            ),
        )
        await context_manager.add_message(session_id, Message(role="assistant", content="## 结论\n无异常"))

        messages_resp = await client.get(
            f"/api/v1/agent/sessions/{session_id}/messages",
            headers=headers,
        )
        assert messages_resp.status_code == 200
        messages = messages_resp.json()
        assert [m["role"] for m in messages] == ["user", "assistant"]
        assert messages[-1]["content"] == "## 结论\n无异常"
    await close_db()


@pytest.mark.anyio
async def test_chat_session_rename_and_export():
    tenant_id = f"tenant-{uuid.uuid4()}"
    headers = auth_headers(user_id="user-001", tenant_id=tenant_id)

    await close_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        create_resp = await client.post("/api/v1/agent/sessions", headers=headers)
        assert create_resp.status_code == 200
        session_id = create_resp.json()["id"]

        rename_resp = await client.patch(
            f"/api/v1/agent/sessions/{session_id}",
            headers=headers,
            json={"title": "项目安全分析"},
        )
        assert rename_resp.status_code == 200
        assert rename_resp.json()["title"] == "项目安全分析"

        export_resp = await client.get(
            f"/api/v1/agent/sessions/{session_id}/export",
            headers=headers,
        )
        assert export_resp.status_code == 200
        payload = export_resp.json()
        assert payload["session"]["id"] == session_id
        assert payload["session"]["title"] == "项目安全分析"
        assert isinstance(payload["messages"], list)
    await close_db()
