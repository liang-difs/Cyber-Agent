"""Attack chain tracing — links related alerts by IP, time window, and TTP."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional

logger = logging.getLogger(__name__)

# MITRE ATT&CK tactical ordering
TACTIC_ORDER = [
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
]

TACTIC_INDEX = {t: i for i, t in enumerate(TACTIC_ORDER)}

# Keyword → tactic mapping (same as alert_triage, duplicated for independence)
KEYWORD_TACTIC = {
    "scan": "Reconnaissance",
    "recon": "Reconnaissance",
    "brute": "CredentialAccess",
    "credential": "CredentialAccess",
    "exploit": "InitialAccess",
    "injection": "InitialAccess",
    "rce": "Execution",
    "malware": "Execution",
    "ransomware": "Impact",
    "exfil": "Exfiltration",
    "c2": "CommandAndControl",
    "beacon": "CommandAndControl",
    "lateral": "LateralMovement",
    "pivot": "LateralMovement",
}


@dataclass
class ChainNode:
    """A single node in the attack chain."""

    alert_id: str
    rule_id: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    tactic: str
    severity: str
    timestamp: datetime
    description: Optional[str] = None

    @property
    def tactic_index(self) -> int:
        return TACTIC_INDEX.get(self.tactic, -1)


@dataclass
class AttackChain:
    """A sequence of related alerts forming an attack chain."""

    chain_id: str
    nodes: List[ChainNode] = field(default_factory=list)
    src_ips: set = field(default_factory=set)
    dst_ips: set = field(default_factory=set)
    tactics_covered: set = field(default_factory=set)
    severity: str = "low"

    @property
    def length(self) -> int:
        return len(self.nodes)

    @property
    def progression_score(self) -> float:
        """0-1 score indicating how far the attack has progressed (based on tactic ordering)."""
        if not self.nodes:
            return 0.0
        max_idx = max(n.tactic_index for n in self.nodes)
        return round(max_idx / (len(TACTIC_ORDER) - 1), 2)

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "length": self.length,
            "src_ips": list(self.src_ips),
            "dst_ips": list(self.dst_ips),
            "tactics_covered": sorted(self.tactics_covered),
            "progression_score": self.progression_score,
            "severity": self.severity,
            "nodes": [
                {
                    "alert_id": n.alert_id,
                    "rule_id": n.rule_id,
                    "src_ip": n.src_ip,
                    "dst_ip": n.dst_ip,
                    "tactic": n.tactic,
                    "severity": n.severity,
                    "timestamp": n.timestamp.isoformat(),
                    "description": n.description,
                }
                for n in sorted(self.nodes, key=lambda x: x.timestamp)
            ],
        }


def classify_tactic(rule_id: str, description: str = "") -> str:
    """Classify alert into MITRE ATT&CK tactic based on rule_id and description."""
    text = f"{rule_id} {description}".lower()
    for keyword, tactic in KEYWORD_TACTIC.items():
        if keyword in text:
            return tactic
    return "Discovery"  # Default fallback


def _severity_rank(severity: str) -> int:
    """Map severity to numeric for comparison."""
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity.lower(), 0)


def build_attack_chains(
    alerts: List[dict],
    time_window_hours: int = 24,
    min_chain_length: int = 2,
) -> List[AttackChain]:
    """Build attack chains from a list of alerts.

    Groups alerts by:
    1. Same src_ip within time window
    2. Related dst_ip from same src_ip
    3. TTP progression (early → late tactics)

    Args:
        alerts: List of dicts with keys: id, rule_id, src_ip, dst_ip, severity,
                description, created_at, status
        time_window_hours: Max time gap between alerts in same chain
        min_chain_length: Minimum alerts to form a chain

    Returns:
        List of AttackChain objects, sorted by severity and progression.
    """
    if not alerts:
        return []

    # Parse alerts into ChainNodes
    nodes: List[ChainNode] = []
    for a in alerts:
        ts = a.get("created_at")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        elif ts is None:
            ts = datetime.now(timezone.utc)

        tactic = classify_tactic(a.get("rule_id", ""), a.get("description", ""))
        nodes.append(ChainNode(
            alert_id=a.get("id", ""),
            rule_id=a.get("rule_id", ""),
            src_ip=a.get("src_ip"),
            dst_ip=a.get("dst_ip"),
            tactic=tactic,
            severity=a.get("severity", "medium"),
            timestamp=ts,
            description=a.get("description"),
        ))

    # Group by src_ip
    by_src: dict[str, List[ChainNode]] = {}
    no_src: List[ChainNode] = []
    for n in nodes:
        if n.src_ip:
            by_src.setdefault(n.src_ip, []).append(n)
        else:
            no_src.append(n)

    chains: List[AttackChain] = []
    chain_counter = 0

    for src_ip, group in by_src.items():
        # Sort by timestamp
        group.sort(key=lambda x: x.timestamp)

        # Split into sub-chains by time window
        current_chain: List[ChainNode] = [group[0]]
        for node in group[1:]:
            gap = node.timestamp - current_chain[-1].timestamp
            if gap <= timedelta(hours=time_window_hours):
                current_chain.append(node)
            else:
                if len(current_chain) >= min_chain_length:
                    chain_counter += 1
                    chains.append(_build_chain(chain_counter, current_chain))
                current_chain = [node]

        # Don't forget the last sub-chain
        if len(current_chain) >= min_chain_length:
            chain_counter += 1
            chains.append(_build_chain(chain_counter, current_chain))

    # Sort by progression score (desc), then severity
    chains.sort(key=lambda c: (-c.progression_score, -_severity_rank(c.severity)))
    return chains


def _build_chain(chain_id: int, nodes: List[ChainNode]) -> AttackChain:
    """Build an AttackChain from a list of nodes."""
    src_ips = {n.src_ip for n in nodes if n.src_ip}
    dst_ips = {n.dst_ip for n in nodes if n.dst_ip}
    tactics = {n.tactic for n in nodes}
    worst_severity = "low"
    for n in nodes:
        if _severity_rank(n.severity) > _severity_rank(worst_severity):
            worst_severity = n.severity

    return AttackChain(
        chain_id=f"chain-{chain_id}",
        nodes=nodes,
        src_ips=src_ips,
        dst_ips=dst_ips,
        tactics_covered=tactics,
        severity=worst_severity,
    )
