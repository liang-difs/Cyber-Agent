"""Tests for PCAP tool output guardrails."""

import pytest
from unittest.mock import patch

from app.tasks.pcap_analysis import PCAP_MAGIC
from app.tools.pcap_tool import PcapTool, PcapToolInput


@pytest.fixture
def tool():
    return PcapTool()


@pytest.mark.anyio
async def test_execute_includes_time_basis_and_fact_separation(tmp_path, tool):
    pcap_file = tmp_path / "sample.pcap"
    pcap_file.write_bytes(PCAP_MAGIC + b"\x00" * 128)

    mock_analysis = {
        "success": True,
        "summary": {
            "total_packets": 2,
            "total_flows": 1,
            "duration_s": 1.0,
            "total_bytes": 120,
            "start_time": "",
            "end_time": "",
            "time_basis": "relative",
            "anomaly_count": 1,
            "top_protocols": [{"protocol": "DNS", "count": 1}],
        },
        "anomalies": [
            {"type": "dns_tunnel", "severity": "high", "detail": "DNS 隧道嫌疑"}
        ],
        "external_ips_for_lookup": ["1.2.3.4"],
        "domains_for_lookup": ["evil.example"],
    }

    with patch("app.tasks.pcap_analysis.analyze_pcap", return_value=mock_analysis):
        result = await tool.execute(PcapToolInput(
            pcap_path=str(pcap_file),
            max_packets=100,
            tenant_id="tenant-1",
            trace_id="trace-1",
        ))

    assert result.success is True
    assert "时间基准: relative" in result.data["summary_text"]
    assert "时间仅表示抓包内先后顺序" in result.data["summary_text"]
    assert "结论必须区分已确认事实与推断" in result.data["summary_text"]
    assert "检测到 1 个异常" in result.data["summary_text"]
    assert result.data["display_filename"] == "sample.pcap"
    assert result.data["pcap_identity"]["display_filename"] == "sample.pcap"

    # Evidence should be present and include doc_id and key_dates
    assert isinstance(result.data.get("evidence"), list)
    ev = result.data.get("evidence")[0]
    assert ev.get("source_type") == "pcap"
    assert ev.get("doc_id", "").startswith("pcap:")
    assert isinstance(ev.get("key_dates"), dict)


@pytest.mark.anyio
async def test_execute_prefers_original_display_filename(tmp_path, tool):
    pcap_file = tmp_path / "randomname.pcap"
    pcap_file.write_bytes(PCAP_MAGIC + b"\x00" * 128)

    mock_analysis = {
        "success": True,
        "summary": {
            "total_packets": 1,
            "total_flows": 1,
            "duration_s": 1.0,
            "total_bytes": 1,
            "start_time": "",
            "end_time": "",
            "time_basis": "relative",
            "anomaly_count": 0,
            "top_protocols": [],
        },
        "anomalies": [],
        "external_ips_for_lookup": [],
        "domains_for_lookup": [],
    }

    with patch("app.tasks.pcap_analysis.analyze_pcap", return_value=mock_analysis):
        result = await tool.execute(PcapToolInput(
            pcap_path=str(pcap_file),
            display_filename="Tinba.pcap",
            max_packets=100,
            tenant_id="tenant-1",
            trace_id="trace-2",
        ))

    assert result.success is True
    assert result.data["display_filename"] == "Tinba.pcap"
    assert result.data["pcap_identity"]["display_filename"] == "Tinba.pcap"


@pytest.mark.anyio
async def test_execute_handles_anomaly_summary_without_get_settings_error(tmp_path, tool):
    pcap_file = tmp_path / "Zeus.pcap"
    pcap_file.write_bytes(PCAP_MAGIC + b"\x00" * 128)

    mock_analysis = {
        "success": True,
        "summary": {
            "total_packets": 10,
            "total_flows": 2,
            "duration_s": 3.0,
            "total_bytes": 1000,
            "start_time": "",
            "end_time": "",
            "time_basis": "relative",
            "anomaly_count": 1,
            "top_protocols": [{"protocol": "TCP", "count": 1}],
        },
        "anomalies": [
            {"type": "port_scan", "severity": "high", "detail": "端口扫描嫌疑", "src_ip": "1.2.3.4"}
        ],
        "external_ips_for_lookup": ["1.2.3.4"],
        "domains_for_lookup": ["zeus.example"],
    }

    with patch("app.tools.pcap_tool.get_settings") as get_settings_mock:
        get_settings_mock.return_value.abuseipdb_api_key = ""
        with patch("app.tasks.pcap_analysis.analyze_pcap", return_value=mock_analysis):
            result = await tool.execute(PcapToolInput(
                pcap_path=str(pcap_file),
                display_filename="Zeus.pcap",
                max_packets=100,
                tenant_id="tenant-1",
                trace_id="trace-3",
            ))

    assert result.success is True
    assert result.data["display_filename"] == "Zeus.pcap"
    assert result.data["pcap_identity"]["display_filename"] == "Zeus.pcap"
    assert "Zeus.pcap" in result.data["summary_text"]
    assert "检测到 1 个异常" in result.data["summary_text"]
