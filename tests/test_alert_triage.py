"""Tests for Alert Triage task."""

from app.tasks.alert_triage import _map_ttps, _compute_verdict, triage_alert


def test_map_ttps_scan():
    ttps = _map_ttps("port_scan_rule", "detected port scanning activity")
    assert len(ttps) >= 1
    assert any(t["technique"] == "T1595" for t in ttps)


def test_map_ttps_exploit():
    ttps = _map_ttps("exploit_cve_2024_3400", "exploitation attempt detected")
    assert any(t["technique"] == "T1203" for t in ttps)


def test_map_ttps_brute_force():
    ttps = _map_ttps("ssh_brute_force", "multiple failed login attempts")
    assert any(t["technique"] == "T1110" for t in ttps)


def test_map_ttps_unknown_defaults_to_initial_access():
    ttps = _map_ttps("unknown_rule", "some unknown alert")
    assert len(ttps) == 1
    assert ttps[0]["technique"] == "T1190"


def test_compute_verdict_true_positive():
    verdict, score = _compute_verdict(confidence=0.8)
    assert verdict == "true_positive"
    assert score >= 0.7


def test_compute_verdict_suspicious():
    verdict, score = _compute_verdict(confidence=0.5)
    assert verdict == "suspicious"
    assert 0.4 <= score < 0.7


def test_compute_verdict_false_positive():
    verdict, score = _compute_verdict(confidence=0.1)
    assert verdict == "false_positive"
    assert score < 0.4


def test_compute_verdict_with_reputation():
    verdict, score = _compute_verdict(confidence=0.5, src_ip_reputation=90.0)
    # 0.6*0.5 + 0.4*0.9 = 0.66 -> suspicious
    assert verdict == "suspicious"
    assert 0.4 <= score < 0.7

def test_compute_verdict_with_high_reputation():
    verdict, score = _compute_verdict(confidence=0.8, src_ip_reputation=95.0)
    # 0.6*0.8 + 0.4*0.95 = 0.86 -> true_positive
    assert verdict == "true_positive"
    assert score >= 0.7


def test_triage_alert_returns_structure():
    result = triage_alert(
        alert_id="test-001",
        rule_id="port_scan",
        description="port scanning detected",
        src_ip="192.168.1.100",
        tenant_id="test",
    )
    assert result["alert_id"] == "test-001"
    assert result["verdict"] in ("true_positive", "suspicious", "false_positive")
    assert 0.0 <= result["confidence"] <= 1.0
    assert len(result["ttps"]) >= 1
    assert result["tactic"] in ("TA0043", "TA0001")
    assert result["ttp_ids"] == [t["technique"] for t in result["ttps"]]
    assert "reasoning" in result
    assert "assessment" in result
    assert result["assessment"]["boundary"]
    assert result["assessment"]["facts"]
    assert result["tenant_id"] == "test"


def test_triage_alert_c2():
    result = triage_alert(
        alert_id="test-002",
        rule_id="c2_beacon",
        description="suspicious C2 communication detected",
    )
    assert any(t["technique"] == "T1071" for t in result["ttps"])
