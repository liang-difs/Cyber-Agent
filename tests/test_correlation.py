"""Tests for correlation analysis."""

import pytest
from datetime import datetime, timezone, timedelta

from app.analysis.correlation import analyze_correlations, CorrelationResult


def test_analyze_empty():
    result = analyze_correlations([])
    assert result.total_alerts == 0
    assert result.patterns == []


def test_analyze_single_alert():
    alerts = [{
        "id": "a1",
        "rule_id": "port_scan",
        "src_ip": "1.2.3.4",
        "dst_ip": "10.0.0.1",
        "severity": "medium",
        "description": "scan",
        "created_at": datetime.now(timezone.utc),
    }]
    result = analyze_correlations(alerts)
    assert result.total_alerts == 1
    assert result.severity_distribution == {"medium": 1}


def test_ip_cluster_detection():
    """Single IP triggering many different rules forms a cluster."""
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": f"a{i}",
            "rule_id": f"rule_{i}",
            "src_ip": "1.2.3.4",
            "dst_ip": f"10.0.0.{i}",
            "severity": "medium",
            "description": f"alert {i}",
            "created_at": now + timedelta(minutes=i),
        }
        for i in range(5)
    ]
    result = analyze_correlations(alerts, ip_cluster_min_alerts=3)
    patterns = [p for p in result.patterns if p.pattern_type == "ip_cluster"]
    assert len(patterns) == 1
    assert "1.2.3.4" in patterns[0].description
    assert patterns[0].confidence > 0.5


def test_cross_target_detection():
    """Same IP hitting many destinations triggers cross-target pattern."""
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": f"a{i}",
            "rule_id": "scan",
            "src_ip": "1.2.3.4",
            "dst_ip": f"10.0.0.{i}",
            "severity": "medium",
            "description": "scan",
            "created_at": now + timedelta(seconds=i),
        }
        for i in range(5)
    ]
    result = analyze_correlations(alerts)
    patterns = [p for p in result.patterns if p.pattern_type == "cross_target"]
    assert len(patterns) == 1
    assert "5" in patterns[0].description


def test_rule_burst_detection():
    """Many alerts of same rule in short time window."""
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": f"a{i}",
            "rule_id": "port_scan",
            "src_ip": f"10.0.0.{i}",
            "dst_ip": "192.168.1.1",
            "severity": "medium",
            "description": "scan",
            "created_at": now + timedelta(seconds=i * 30),
        }
        for i in range(6)
    ]
    result = analyze_correlations(alerts, burst_window_minutes=5, burst_threshold=5)
    patterns = [p for p in result.patterns if p.pattern_type == "rule_burst"]
    assert len(patterns) >= 1
    assert "port_scan" in patterns[0].description


def test_severity_distribution():
    now = datetime.now(timezone.utc)
    alerts = [
        {"id": "a1", "rule_id": "r1", "src_ip": "1.2.3.4", "severity": "high",
         "created_at": now},
        {"id": "a2", "rule_id": "r2", "src_ip": "1.2.3.4", "severity": "high",
         "created_at": now},
        {"id": "a3", "rule_id": "r3", "src_ip": "1.2.3.4", "severity": "low",
         "created_at": now},
    ]
    result = analyze_correlations(alerts)
    assert result.severity_distribution == {"high": 2, "low": 1}


def test_top_src_ips():
    now = datetime.now(timezone.utc)
    alerts = [
        {"id": f"a{i}", "rule_id": "r1", "src_ip": "1.2.3.4", "severity": "medium",
         "created_at": now + timedelta(seconds=i)}
        for i in range(3)
    ] + [
        {"id": f"b{i}", "rule_id": "r1", "src_ip": "5.6.7.8", "severity": "medium",
         "created_at": now + timedelta(seconds=i)}
        for i in range(2)
    ]
    result = analyze_correlations(alerts)
    assert result.top_src_ips[0] == ("1.2.3.4", 3)
    assert result.top_src_ips[1] == ("5.6.7.8", 2)


def test_to_dict():
    now = datetime.now(timezone.utc)
    alerts = [
        {"id": "a1", "rule_id": "r1", "src_ip": "1.2.3.4", "severity": "medium",
         "created_at": now},
    ]
    result = analyze_correlations(alerts)
    d = result.to_dict()
    assert "total_alerts" in d
    assert "patterns" in d
    assert "top_src_ips" in d
    assert "severity_distribution" in d


def test_no_src_ip():
    """Alerts without src_ip still work."""
    alerts = [
        {"id": "a1", "rule_id": "r1", "severity": "medium",
         "created_at": datetime.now(timezone.utc)},
    ]
    result = analyze_correlations(alerts)
    assert result.total_alerts == 1
