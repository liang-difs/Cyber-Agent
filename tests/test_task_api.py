"""Tests for Task API endpoints."""

import pytest
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.security import create_access_token


def auth_headers() -> dict[str, str]:
    token = create_access_token(
        {"sub": "user-001", "role": "analyst", "tenant_id": "test"},
        secret="",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.anyio
async def test_task_status_not_found():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/tasks/nonexistent-task-id", headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["task_id"] == "nonexistent-task-id"
    # Celery not running in test env, so status is UNKNOWN
    assert data["status"] in ("PENDING", "UNKNOWN")


@pytest.mark.anyio
async def test_submit_alert_triage():
    mock_result = MagicMock()
    mock_result.id = "test-task-123"
    mock_inspect = MagicMock()
    mock_inspect.active.return_value = {"worker-1": []}

    with patch("app.tasks.alert_triage.triage_alert.delay", return_value=mock_result), \
         patch("app.tasks.celery_app.celery_app.control.inspect", return_value=mock_inspect):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/tasks/alert-triage",
                params={
                    "alert_id": "alert-001",
                    "rule_id": "port_scan",
                    "description": "test scan",
                    "src_ip": "10.0.0.1",
                },
                headers=auth_headers(),
            )

    assert resp.status_code == 200
    data = resp.json()
    assert data["task_id"] == "test-task-123"
    assert data["status"] == "submitted"
    assert data["queue"] == "celery_critical"


@pytest.mark.anyio
async def test_submit_pcap_analysis():
    mock_result = MagicMock()
    mock_result.id = "pcap-task-456"

    with patch("app.tasks.pcap_analysis.analyze_pcap.delay", return_value=mock_result):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/tasks/pcap-analysis",
                params={
                    "pcap_path": "/tmp/test.pcap",
                    "max_packets": 5000,
                },
                headers=auth_headers(),
            )

    assert resp.status_code == 200
    data = resp.json()
    assert data["task_id"] == "pcap-task-456"
    assert data["queue"] == "celery_high"


@pytest.mark.anyio
async def test_upload_pcap_sync_fallback_uses_scoped_tenant():
    inspector = MagicMock()
    inspector.active.return_value = None
    analysis_result = {"success": True, "summary": {"total_packets": 1}}

    with patch("app.tasks.celery_app.celery_app.control.inspect", return_value=inspector):
        with patch("app.tasks.pcap_analysis.analyze_pcap", return_value=analysis_result) as analyze:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/tasks/pcap-upload",
                    files={"file": ("sample.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 100, "application/vnd.tcpdump.pcap")},
                    data={"max_packets": "123"},
                    headers=auth_headers(),
                )

    assert resp.status_code == 200
    data = resp.json()
    assert data["sync"] is True
    assert data["queue"] == "sync"
    assert data["result"] == analysis_result
    assert analyze.call_args.kwargs["tenant_id"] == "test"
    assert analyze.call_args.kwargs["max_packets"] == 123
    assert analyze.call_args.kwargs["display_filename"] == "sample.pcap"


@pytest.mark.anyio
async def test_upload_pcap_submits_to_celery_when_worker_available():
    inspector = MagicMock()
    inspector.active.return_value = {"worker1": []}
    mock_result = MagicMock()
    mock_result.id = "pcap-upload-task"

    with patch("app.tasks.celery_app.celery_app.control.inspect", return_value=inspector):
        with patch("app.tasks.pcap_analysis.analyze_pcap.delay", return_value=mock_result) as delay:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/tasks/pcap-upload",
                    files={"file": ("sample.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 100, "application/vnd.tcpdump.pcap")},
                    data={"max_packets": "321"},
                    headers=auth_headers(),
                )

    assert resp.status_code == 200
    data = resp.json()
    assert data["sync"] is False
    assert data["task_id"] == "pcap-upload-task"
    assert data["queue"] == "celery_high"
    assert delay.call_args.kwargs["tenant_id"] == "test"
    assert delay.call_args.kwargs["max_packets"] == 321
    assert delay.call_args.kwargs["display_filename"] == "sample.pcap"
