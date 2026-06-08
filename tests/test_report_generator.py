"""Tests for report generator."""

import pytest
from datetime import datetime, timezone, timedelta

from app.reports.generator import generate_incident_report, generate_pcap_incident_report


def test_basic_report():
    report = generate_incident_report(
        title="Test Report",
        alerts=[],
        attack_chains=[],
        correlation_result={"total_alerts": 0, "patterns": [], "severity_distribution": {}},
    )
    assert "# Test Report" in report
    assert "CyberSec Agent" in report


def test_report_with_alerts():
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": "a1",
            "rule_id": "port_scan",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "high",
            "description": "Port scan",
            "created_at": now.isoformat(),
        },
    ]
    corr = {
        "total_alerts": 1,
        "patterns": [],
        "severity_distribution": {"high": 1},
        "top_src_ips": [{"ip": "1.2.3.4", "count": 1}],
        "top_rules": [{"rule_id": "port_scan", "count": 1}],
    }
    report = generate_incident_report(
        title="Scan Report",
        alerts=alerts,
        attack_chains=[],
        correlation_result=corr,
    )
    assert "1" in report  # total alerts
    assert "HIGH" in report
    assert "1.2.3.4" in report
    assert "## 研判边界" in report
    assert "模式置信度" in report
    assert "关联推断" in report or "关联模式" in report


def test_report_with_alert_assessment_section():
    alerts = [
        {
            "id": "a1",
            "rule_id": "port_scan",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "high",
            "description": "Port scan",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "open",
            "verdict": "suspicious",
            "confidence": 0.62,
            "assessment": {
                "confidence": 0.62,
                "confidence_label": "medium",
                "facts": ["规则 `port_scan` 命中", "源 IP: `1.2.3.4`"],
                "inferences": ["当前研判结果为 `suspicious`"],
                "boundary": ["告警命中表示检测结果，不自动等于已成功入侵或已发生外泄"],
                "evidence": ["rule_id:port_scan"],
            },
        }
    ]

    report = generate_incident_report(
        title="Assessment Report",
        alerts=alerts,
        attack_chains=[],
        correlation_result={"total_alerts": 1, "patterns": [], "severity_distribution": {"high": 1}},
    )

    assert "## 告警研判摘要" in report
    assert "已确认事实" in report
    assert "推断/研判" in report
    assert "边界说明" in report
    assert "rule_id:port_scan" in report


def test_report_with_attack_chains():
    chains = [{
        "chain_id": "chain-1",
        "severity": "critical",
        "progression_score": 0.85,
        "src_ips": ["1.2.3.4"],
        "dst_ips": ["10.0.0.1"],
        "tactics_covered": ["Reconnaissance", "InitialAccess", "Execution"],
        "nodes": [
            {
                "alert_id": "a1",
                "rule_id": "port_scan",
                "src_ip": "1.2.3.4",
                "dst_ip": "10.0.0.1",
                "tactic": "Reconnaissance",
                "severity": "medium",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            {
                "alert_id": "a2",
                "rule_id": "exploit",
                "src_ip": "1.2.3.4",
                "dst_ip": "10.0.0.1",
                "tactic": "InitialAccess",
                "severity": "critical",
                "timestamp": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            },
        ],
    }]
    corr = {"total_alerts": 2, "patterns": [], "severity_distribution": {"medium": 1, "critical": 1}}
    report = generate_incident_report(
        title="Chain Report",
        alerts=[],
        attack_chains=chains,
        correlation_result=corr,
    )
    assert "chain-1" in report
    assert "Attack Chains" in report
    assert "85%" in report or "Reconnaissance" in report


def test_report_with_patterns():
    corr = {
        "total_alerts": 5,
        "patterns": [
            {
                "pattern_type": "ip_cluster",
                "description": "IP 1.2.3.4 triggered 4 rules",
                "confidence": 0.8,
            },
        ],
        "severity_distribution": {"medium": 5},
    }
    report = generate_incident_report(
        title="Pattern Report",
        alerts=[],
        attack_chains=[],
        correlation_result=corr,
    )
    assert "Correlation Patterns" in report
    assert "ip_cluster" in report


def test_report_with_analyst_notes():
    report = generate_incident_report(
        title="Notes Report",
        alerts=[],
        attack_chains=[],
        correlation_result={"total_alerts": 0, "patterns": [], "severity_distribution": {}},
        analyst_notes="Manual investigation required.",
    )
    assert "Analyst Notes" in report
    assert "Manual investigation required" in report


def test_report_with_raw_data():
    alerts = [{"id": "a1", "rule_id": "r1", "severity": "low"}]
    report = generate_incident_report(
        title="Raw Report",
        alerts=alerts,
        attack_chains=[],
        correlation_result={"total_alerts": 1, "patterns": [], "severity_distribution": {}},
        include_raw_data=True,
    )
    assert "Appendix" in report
    assert "a1" in report


def test_report_executive_summary():
    corr = {
        "total_alerts": 10,
        "patterns": [{"pattern_type": "test", "description": "d", "confidence": 0.9}],
        "severity_distribution": {"high": 5, "medium": 5},
    }
    chains = [{"chain_id": "c1", "progression_score": 0.7, "severity": "high",
               "src_ips": [], "dst_ips": [], "tactics_covered": [], "nodes": []}]
    report = generate_incident_report(
        title="Summary Report",
        alerts=[],
        attack_chains=chains,
        correlation_result=corr,
    )
    assert "Executive Summary" in report
    assert "10" in report
    assert "1" in report  # 1 pattern


def test_pcap_report_adds_time_basis_and_risk_boundary():
    pcap_result = {
        "pcap_identity": {
            "display_filename": "Facetime.pcap",
            "original_filename": "Facetime.pcap",
            "source_path": "/tmp/277e04187fa64e218f6b82ae85a9b0d0.pcap",
            "sha256": "abc123",
        },
        "summary": {
            "total_packets": 2,
            "total_flows": 1,
            "duration_s": 1.5,
            "total_bytes": 2048,
            "time_basis": "relative",
            "start_time": "",
            "end_time": "",
            "anomaly_count": 1,
            "top_protocols": [{"protocol": "DNS", "count": 1}],
        },
        "anomalies": [
            {"type": "data_exfil", "severity": "high", "detail": "数据外泄嫌疑"}
        ],
        "dns": {"stats": {"long_subdomains": [], "txt_queries": [], "high_frequency": []}},
        "protocol_insights": {"http_hosts": [], "tls_sni": [], "tls_versions": {}, "ssh_versions": []},
        "external_ips_for_lookup": ["1.2.3.4"],
        "domains_for_lookup": ["evil.example"],
    }

    report = generate_pcap_incident_report(
        title="PCAP Report",
        pcap_result=pcap_result,
        alerts=[],
        attack_chains=[],
        correlation_result={"total_alerts": 0, "patterns": [], "severity_distribution": {}},
    )

    assert "## 研判边界" in report
    assert "分析文件" in report
    assert "Facetime.pcap" in report
    assert "- **时间基准:** relative" in report
    assert "不代表日历时间" in report
    assert "异常命中表示检测结果" in report
    assert "data_exfil" in report
    assert "仅表示大流量外传嫌疑" in report
    assert "候选 IoC，不等于已经完成恶意确认" in report
    assert "## DNS 异常（检测结果）" not in report


def test_pcap_report_highlights_internal_outbound_direction():
    pcap_result = {
        "pcap_identity": {
            "display_filename": "Skype.pcap",
            "original_filename": "Skype.pcap",
            "source_path": "/tmp/demo.pcap",
            "sha256": "abc123",
        },
        "summary": {
            "total_packets": 10,
            "total_flows": 2,
            "duration_s": 1.5,
            "total_bytes": 2048,
            "time_basis": "relative",
            "start_time": "",
            "end_time": "",
            "anomaly_count": 2,
            "top_protocols": [{"protocol": "TCP", "count": 10}],
        },
        "anomalies": [],
        "dns": {"stats": {"long_subdomains": [], "txt_queries": [], "high_frequency": []}},
        "protocol_insights": {"http_hosts": [], "tls_sni": [], "tls_versions": {}, "ssh_versions": []},
        "external_ips_for_lookup": ["1.2.3.4"],
        "domains_for_lookup": [],
    }
    chains = [{
        "chain_id": "chain-2",
        "severity": "high",
        "progression_score": 0.54,
        "src_ips": ["10.0.2.103"],
        "dst_ips": ["185.220.101.1"],
        "tactics_covered": ["CredentialAccess"],
        "nodes": [],
    }]

    report = generate_pcap_incident_report(
        title="PCAP Report",
        pcap_result=pcap_result,
        alerts=[],
        attack_chains=chains,
        correlation_result={"total_alerts": 0, "patterns": [], "severity_distribution": {}},
    )

    assert "内网主机对外联通" in report or "内网主机对外活动" in report
