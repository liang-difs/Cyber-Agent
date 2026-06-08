"""Tests for alert assessment helpers."""

from datetime import datetime, timezone
from types import SimpleNamespace

from app.analysis.alert_assessment import build_alert_assessment, confidence_label
from app.api.alerts import _serialize_alert_record


def test_confidence_label_thresholds():
    assert confidence_label(0.8) == "high"
    assert confidence_label(0.6) == "medium"
    assert confidence_label(0.4) == "low"
    assert confidence_label(0.1) == "insufficient"
    assert confidence_label(0.0) == "insufficient"


def test_build_alert_assessment_structure():
    assessment = build_alert_assessment(
        rule_id="port_scan",
        description="scan detected",
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        severity="high",
        status="open",
        verdict="suspicious",
        confidence=0.62,
        ttps=[{"name": "Reconnaissance", "technique": "T1595", "tactic": "TA0043"}],
        evidence=["rule_id:port_scan"],
    )

    assert assessment["confidence_label"] == "medium"
    assert assessment["facts"]
    assert assessment["inferences"]
    assert assessment["boundary"]
    assert assessment["evidence"] == ["rule_id:port_scan"]


def test_serialize_alert_record_includes_assessment():
    alert = SimpleNamespace(
        id="a1",
        rule_id="c2_beacon",
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        severity="medium",
        status="open",
        verdict=None,
        confidence=0.0,
        description="beacon-like traffic",
        ttp_ids=["T1071"],
        tenant_id="tenant-1",
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2024, 1, 2, tzinfo=timezone.utc),
    )

    serialized = _serialize_alert_record(alert)

    assert serialized["id"] == "a1"
    assert serialized["assessment"]["confidence_label"] == "insufficient"
    assert "告警命中表示检测结果" in serialized["assessment"]["boundary"][0]
