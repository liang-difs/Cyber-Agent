"""Tests for WebSocket chat endpoint."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.security import create_access_token
from app.api.chat import (
    _extract_pcap_path,
    _extract_attachment_pcap_path,
    _sanitize_pcap_request,
    _sanitize_messages_for_llm,
    _infer_response_type,
    _build_pcap_fallback_report,
    _bootstrap_pcap_analysis,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def auth_token():
    return create_access_token(
        {"sub": "user-001", "role": "analyst", "tenant_id": "tenant-1"},
        secret="",
    )


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.anyio
async def test_ws_no_token(client):
    """Test WebSocket connection without token is rejected."""
    resp = await client.get("/api/v1/agent/chat")
    # Should fail - no WebSocket upgrade and no token
    assert resp.status_code in (400, 401, 403, 404, 422, 426)


@pytest.mark.anyio
async def test_ws_invalid_token(client):
    """Test WebSocket connection with invalid token."""
    resp = await client.get("/api/v1/agent/chat?token=invalid")
    assert resp.status_code in (400, 401, 403, 404, 426)


def test_extract_pcap_path_from_message():
    assert _extract_pcap_path("请分析这个pcap文件\n[文件路径: /tmp/demo.pcap]") == "/tmp/demo.pcap"
    assert _extract_pcap_path("直接路径 /tmp/demo.pcapng") == "/tmp/demo.pcapng"
    assert _extract_pcap_path("没有路径") is None


def test_extract_attachment_pcap_path():
    assert _extract_attachment_pcap_path({
        "attachments": [{"path": "/tmp/demo.pcap", "name": "demo.pcap"}]
    }) == "/tmp/demo.pcap"
    assert _extract_attachment_pcap_path({
        "attachments": [{"path": "/tmp/demo.txt", "name": "demo.txt"}]
    }) is None
    assert _extract_attachment_pcap_path({"attachments": []}) is None


def test_sanitize_messages_for_llm_drops_tool_protocol_messages():
    messages = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "{}", "tool_calls": [{"id": "call-1"}]},
        {"role": "tool", "content": "tool output", "tool_call_id": "call-1"},
        {"role": "assistant", "content": "final summary"},
    ]

    sanitized = _sanitize_messages_for_llm(messages)

    assert sanitized == [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "final summary"},
    ]


def test_infer_response_type_prefers_structured_markers():
    assert _infer_response_type("## CVE / KEV 结构化查询结果\n...") == "cve_catalog"
    assert _infer_response_type("## CVE-2024-3400 - 样例") == "cve"
    assert _infer_response_type("## IoC 分析报告 - example.com") == "ioc"
    assert _infer_response_type("## IP 威胁分析报告 - 1.2.3.4") == "ip"
    assert _infer_response_type("## PCAP 安全事件报告") == "pcap"
    assert _infer_response_type("anything else", pcap_bootstrapped=True) == "pcap"


@pytest.mark.anyio
async def test_bootstrap_pcap_analysis_runs_direct_tool_chain(monkeypatch):
    calls = []

    async def fake_execute(name, arguments, trace_id, tenant_id="default"):
        calls.append((name, arguments, trace_id, tenant_id))
        if name == "pcap_analysis":
            return {
                "success": True,
                "data": {
                    "summary": {"time_basis": "relative"},
                    "external_ips_for_lookup": ["1.2.3.4"],
                    "domains_for_lookup": ["evil.example"],
                },
                "evidence_source": ["tshark_pcap_analysis"],
                "execution_time_ms": 12,
            }
        return {
            "success": True,
            "data": {"result": name},
            "evidence_source": [name],
            "execution_time_ms": 3,
        }

    websocket = MagicMock()
    websocket.send_json = AsyncMock()
    add_message = AsyncMock()
    progress_steps = []

    monkeypatch.setattr("app.api.chat.tool_registry.execute", fake_execute)
    monkeypatch.setattr("app.api.chat.context_manager.add_message", add_message)

    settings = MagicMock()
    settings.ctx_obs_max_tokens = 1000

    did_bootstrap = await _bootstrap_pcap_analysis(
        session_id="session-1",
        user_content="请分析\n[文件路径: /tmp/demo.pcap]",
        pcap_path=None,
        tenant_id="tenant-1",
        trace_id="trace-1",
        websocket=websocket,
        settings=settings,
        progress_callback=progress_steps.append,
        bootstrap_context={},
    )

    assert did_bootstrap is True
    assert [item[0] for item in calls] == ["pcap_analysis", "ip_threat_analysis", "ioc_lookup"]
    assert calls[0][1]["display_filename"] == "demo.pcap"
    assert any("开始自动分析" in step for step in progress_steps)
    assert any("基础分析完成" in step for step in progress_steps)
    assert any("自动分析已完成" in step for step in progress_steps)
    assert websocket.send_json.await_count >= 1
    assert add_message.await_count >= 4
    assert _sanitize_pcap_request("whatever") == "请基于已完成的PCAP分析结果与后续威胁情报，生成详细研判报告，不要再次调用 pcap_analysis。"


@pytest.mark.anyio
async def test_bootstrap_pcap_analysis_queries_all_lookup_candidates(monkeypatch):
    calls = []

    async def fake_execute(name, arguments, trace_id, tenant_id="default"):
        calls.append((name, arguments, trace_id, tenant_id))
        if name == "pcap_analysis":
            return {
                "success": True,
                "data": {
                    "summary": {"time_basis": "relative"},
                    "external_ips_for_lookup": ["1.2.3.4", "5.6.7.8", "9.9.9.9"],
                    "domains_for_lookup": ["evil.example", "bad.example"],
                },
                "evidence_source": ["tshark_pcap_analysis"],
                "execution_time_ms": 12,
            }
        return {
            "success": True,
            "data": {"result": name},
            "evidence_source": [name],
            "execution_time_ms": 3,
        }

    websocket = MagicMock()
    websocket.send_json = AsyncMock()
    add_message = AsyncMock()

    monkeypatch.setattr("app.api.chat.tool_registry.execute", fake_execute)
    monkeypatch.setattr("app.api.chat.context_manager.add_message", add_message)

    settings = MagicMock()
    settings.ctx_obs_max_tokens = 1000

    did_bootstrap = await _bootstrap_pcap_analysis(
        session_id="session-3",
        user_content="请分析\n[文件路径: /tmp/demo.pcap]",
        pcap_path=None,
        tenant_id="tenant-1",
        trace_id="trace-3",
        websocket=websocket,
        settings=settings,
        progress_callback=None,
        bootstrap_context={},
    )

    assert did_bootstrap is True
    tool_names = [item[0] for item in calls]
    assert tool_names == ["pcap_analysis", "ip_threat_analysis", "ip_threat_analysis", "ip_threat_analysis", "ioc_lookup", "ioc_lookup"]


@pytest.mark.anyio
async def test_bootstrap_pcap_analysis_uses_hidden_attachment_path(monkeypatch):
    calls = []

    async def fake_execute(name, arguments, trace_id, tenant_id="default"):
        calls.append((name, arguments))
        if name == "pcap_analysis":
            return {
                "success": True,
                "data": {"summary": {"time_basis": "relative"}},
                "evidence_source": ["tshark_pcap_analysis"],
                "execution_time_ms": 12,
            }
        return {
            "success": True,
            "data": {"result": name},
            "evidence_source": [name],
            "execution_time_ms": 3,
        }

    websocket = MagicMock()
    websocket.send_json = AsyncMock()
    monkeypatch.setattr("app.api.chat.tool_registry.execute", fake_execute)
    monkeypatch.setattr("app.api.chat.context_manager.add_message", AsyncMock())

    settings = MagicMock()
    settings.ctx_obs_max_tokens = 1000

    did_bootstrap = await _bootstrap_pcap_analysis(
        session_id="session-2",
        user_content="请分析这个文件",
        pcap_path="/tmp/demo.pcap",
        tenant_id="tenant-1",
        trace_id="trace-2",
        websocket=websocket,
        settings=settings,
    )

    assert did_bootstrap is True
    assert calls[0][0] == "pcap_analysis"
    assert calls[0][1]["pcap_path"] == "/tmp/demo.pcap"
    assert calls[0][1]["display_filename"] == "demo.pcap"


def test_build_pcap_fallback_report_uses_generator_sections():
    report = _build_pcap_fallback_report({
        "summary": {
            "total_packets": 10,
            "total_flows": 2,
            "duration_s": 1.0,
            "total_bytes": 128,
            "start_time": "",
            "end_time": "",
            "time_basis": "relative",
            "anomaly_count": 1,
            "top_protocols": [{"protocol": "DNS", "count": 5}],
        },
        "anomalies": [{"type": "port_scan", "severity": "high", "detail": "scan", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}],
        "dns": {"stats": {}},
        "protocol_insights": {},
        "external_ips_for_lookup": ["8.8.8.8"],
        "domains_for_lookup": ["evil.example"],
        "pcap_identity": {"display_filename": "demo.pcap", "source_path": "/tmp/demo.pcap"},
    })

    assert "PCAP 流量概览" in report
    assert "PCAP 研判边界" in report
    assert "IoC 待查清单" in report
