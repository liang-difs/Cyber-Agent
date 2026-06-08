"""Tests for attack chain tracing."""

import pytest
from datetime import datetime, timezone, timedelta

from app.analysis.attack_chain import (
    classify_tactic,
    build_attack_chains,
    AttackChain,
    ChainNode,
    TACTIC_ORDER,
)


def test_classify_tactic_scan():
    assert classify_tactic("port_scan") == "Reconnaissance"
    assert classify_tactic("network_recon") == "Reconnaissance"


def test_classify_tactic_brute():
    assert classify_tactic("brute_force_ssh") == "CredentialAccess"
    assert classify_tactic("credential_stuffing") == "CredentialAccess"


def test_classify_tactic_exploit():
    assert classify_tactic("exploit_cve_2024") == "InitialAccess"
    assert classify_tactic("sql_injection") == "InitialAccess"


def test_classify_tactic_rce():
    assert classify_tactic("rce_vulnerability") == "Execution"
    assert classify_tactic("malware_detected") == "Execution"


def test_classify_tactic_lateral():
    assert classify_tactic("lateral_movement") == "LateralMovement"
    assert classify_tactic("pivot_detected") == "LateralMovement"


def test_classify_tactic_default():
    assert classify_tactic("unknown_rule") == "Discovery"


def test_classify_tactic_uses_description():
    assert classify_tactic("rule1", "port scan detected") == "Reconnaissance"
    assert classify_tactic("rule1", "brute force attempt") == "CredentialAccess"


def test_build_chains_empty():
    chains = build_attack_chains([])
    assert chains == []


def test_build_chains_single_alert():
    """Single alert doesn't form a chain (min_chain_length=2)."""
    alerts = [{
        "id": "a1",
        "rule_id": "port_scan",
        "src_ip": "1.2.3.4",
        "dst_ip": "10.0.0.1",
        "severity": "medium",
        "description": "scan",
        "created_at": datetime.now(timezone.utc),
    }]
    chains = build_attack_chains(alerts, min_chain_length=2)
    assert len(chains) == 0


def test_build_chains_two_related_alerts():
    """Two alerts from same IP within time window form a chain."""
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": "a1",
            "rule_id": "port_scan",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "medium",
            "description": "scan",
            "created_at": now,
        },
        {
            "id": "a2",
            "rule_id": "exploit_attempt",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "high",
            "description": "exploit",
            "created_at": now + timedelta(minutes=30),
        },
    ]
    chains = build_attack_chains(alerts, min_chain_length=2)
    assert len(chains) == 1
    assert chains[0].length == 2
    assert "1.2.3.4" in chains[0].src_ips


def test_build_chains_different_ips():
    """Alerts from different IPs don't form same chain."""
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": "a1",
            "rule_id": "port_scan",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "medium",
            "description": "scan",
            "created_at": now,
        },
        {
            "id": "a2",
            "rule_id": "exploit_attempt",
            "src_ip": "5.6.7.8",
            "dst_ip": "10.0.0.1",
            "severity": "high",
            "description": "exploit",
            "created_at": now + timedelta(minutes=30),
        },
    ]
    chains = build_attack_chains(alerts, min_chain_length=2)
    assert len(chains) == 0


def test_build_chains_time_window_split():
    """Alerts outside time window form separate chains."""
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": "a1",
            "rule_id": "port_scan",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "medium",
            "description": "scan",
            "created_at": now,
        },
        {
            "id": "a2",
            "rule_id": "exploit_attempt",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "high",
            "description": "exploit",
            "created_at": now + timedelta(hours=2),  # Within 24h window
        },
        {
            "id": "a3",
            "rule_id": "c2_beacon",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "critical",
            "description": "c2",
            "created_at": now + timedelta(hours=48),  # Outside 24h window
        },
    ]
    chains = build_attack_chains(alerts, time_window_hours=24, min_chain_length=2)
    # a1+a2 form one chain, a3 alone doesn't meet min_chain_length
    assert len(chains) == 1
    assert chains[0].length == 2


def test_attack_chain_progression_score():
    """Chain with early+late tactics has higher progression."""
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": "a1",
            "rule_id": "port_scan",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "medium",
            "description": "scan",
            "created_at": now,
        },
        {
            "id": "a2",
            "rule_id": "c2_beacon",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "critical",
            "description": "c2",
            "created_at": now + timedelta(minutes=30),
        },
    ]
    chains = build_attack_chains(alerts, min_chain_length=2)
    assert len(chains) == 1
    # Reconnaissance (0) + CommandAndControl (11) → max_idx=11
    expected = round(11 / 13, 2)
    assert chains[0].progression_score == expected


def test_attack_chain_to_dict():
    now = datetime.now(timezone.utc)
    alerts = [
        {
            "id": "a1",
            "rule_id": "port_scan",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "medium",
            "description": "scan",
            "created_at": now,
        },
        {
            "id": "a2",
            "rule_id": "exploit",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "severity": "high",
            "description": "exploit",
            "created_at": now + timedelta(minutes=10),
        },
    ]
    chains = build_attack_chains(alerts, min_chain_length=2)
    assert len(chains) == 1
    d = chains[0].to_dict()
    assert "chain_id" in d
    assert "nodes" in d
    assert "progression_score" in d
    assert len(d["nodes"]) == 2
