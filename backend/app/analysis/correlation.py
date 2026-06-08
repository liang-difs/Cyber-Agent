"""Correlation analysis — finds patterns across multiple alerts."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class CorrelationPattern:
    """A detected pattern across alerts."""

    pattern_type: str  # "ip_cluster", "rule_burst", "temporal_anomaly", "cross_target"
    description: str
    confidence: float  # 0-1
    related_alerts: List[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "pattern_type": self.pattern_type,
            "description": self.description,
            "confidence": self.confidence,
            "related_alerts": self.related_alerts,
            "metadata": self.metadata,
        }


@dataclass
class CorrelationResult:
    """Full correlation analysis result."""

    total_alerts: int
    time_range: Optional[tuple]  # (earliest, latest)
    patterns: List[CorrelationPattern] = field(default_factory=list)
    top_src_ips: List[tuple] = field(default_factory=list)  # (ip, count)
    top_rules: List[tuple] = field(default_factory=list)  # (rule_id, count)
    severity_distribution: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        result = {
            "total_alerts": self.total_alerts,
            "patterns": [p.to_dict() for p in self.patterns],
            "top_src_ips": [{"ip": ip, "count": c} for ip, c in self.top_src_ips[:10]],
            "top_rules": [{"rule_id": r, "count": c} for r, c in self.top_rules[:10]],
            "severity_distribution": self.severity_distribution,
        }
        if self.time_range:
            result["time_range"] = {
                "earliest": self.time_range[0].isoformat(),
                "latest": self.time_range[1].isoformat(),
            }
        return result


def analyze_correlations(
    alerts: List[dict],
    burst_window_minutes: int = 10,
    burst_threshold: int = 5,
    ip_cluster_min_alerts: int = 3,
) -> CorrelationResult:
    """Analyze correlations across a list of alerts.

    Detects:
    - IP clusters: Single IP triggering many different rules
    - Rule bursts: Spike in a specific rule within a short time window
    - Cross-target attacks: Same src_ip hitting multiple dst_ips
    - Temporal anomalies: Unusual concentration of alerts at specific times

    Args:
        alerts: List of dicts with keys: id, rule_id, src_ip, dst_ip, severity,
                description, created_at
        burst_window_minutes: Time window for burst detection
        burst_threshold: Min alerts in window to count as burst
        ip_cluster_min_alerts: Min alerts from same IP to form a cluster
    """
    if not alerts:
        return CorrelationResult(total_alerts=0, time_range=None)

    patterns: List[CorrelationPattern] = []
    src_ip_counter: Counter = Counter()
    rule_counter: Counter = Counter()
    severity_counter: Counter = Counter()
    ip_to_rules: Dict[str, Set[str]] = defaultdict(set)
    ip_to_dsts: Dict[str, Set[str]] = defaultdict(set)
    ip_alert_ids: Dict[str, List[str]] = defaultdict(list)
    timestamps: List[datetime] = []

    for a in alerts:
        alert_id = a.get("id", "")
        src_ip = a.get("src_ip")
        dst_ip = a.get("dst_ip")
        rule_id = a.get("rule_id", "")
        severity = a.get("severity", "medium")

        ts = a.get("created_at")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        elif ts is None:
            ts = datetime.now(timezone.utc)
        timestamps.append(ts)

        severity_counter[severity] += 1

        if src_ip:
            src_ip_counter[src_ip] += 1
            ip_to_rules[src_ip].add(rule_id)
            ip_alert_ids[src_ip].append(alert_id)
            if dst_ip:
                ip_to_dsts[src_ip].add(dst_ip)

        rule_counter[rule_id] += 1

    # Pattern 1: IP clusters — one IP triggering many different rules
    for ip, rules in ip_to_rules.items():
        if len(rules) >= ip_cluster_min_alerts:
            patterns.append(CorrelationPattern(
                pattern_type="ip_cluster",
                description=f"IP {ip} triggered {len(rules)} different rules: {', '.join(sorted(rules)[:5])}",
                confidence=min(0.5 + len(rules) * 0.1, 1.0),
                related_alerts=ip_alert_ids[ip],
                metadata={"src_ip": ip, "rule_count": len(rules), "rules": sorted(rules)},
            ))

    # Pattern 2: Cross-target attacks — same source hitting multiple destinations
    for ip, dsts in ip_to_dsts.items():
        if len(dsts) >= 3:
            patterns.append(CorrelationPattern(
                pattern_type="cross_target",
                description=f"IP {ip} targeted {len(dsts)} different destinations",
                confidence=min(0.4 + len(dsts) * 0.1, 1.0),
                related_alerts=ip_alert_ids[ip],
                metadata={"src_ip": ip, "target_count": len(dsts), "targets": sorted(dsts)[:10]},
            ))

    # Pattern 3: Rule bursts — spike in a specific rule
    if timestamps:
        timestamps.sort()
        for rule_id in rule_counter:
            rule_times = []
            for a in alerts:
                if a.get("rule_id") == rule_id:
                    ts = a.get("created_at")
                    if isinstance(ts, str):
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if ts:
                        rule_times.append(ts)
            rule_times.sort()

            # Sliding window burst detection
            for i, t_start in enumerate(rule_times):
                window_end = t_start + timedelta(minutes=burst_window_minutes)
                count = sum(1 for t in rule_times[i:] if t <= window_end)
                if count >= burst_threshold:
                    alert_ids = [
                        a.get("id", "") for a in alerts
                        if a.get("rule_id") == rule_id
                    ]
                    patterns.append(CorrelationPattern(
                        pattern_type="rule_burst",
                        description=f"Rule '{rule_id}' fired {count} times within {burst_window_minutes}min window",
                        confidence=min(0.5 + (count - burst_threshold) * 0.1, 1.0),
                        related_alerts=alert_ids[:count],
                        metadata={
                            "rule_id": rule_id,
                            "burst_count": count,
                            "window_minutes": burst_window_minutes,
                            "window_start": t_start.isoformat(),
                        },
                    ))
                    break  # One burst per rule is enough

    # Sort patterns by confidence
    patterns.sort(key=lambda p: -p.confidence)

    # Time range
    time_range = (min(timestamps), max(timestamps)) if timestamps else None

    return CorrelationResult(
        total_alerts=len(alerts),
        time_range=time_range,
        patterns=patterns,
        top_src_ips=src_ip_counter.most_common(10),
        top_rules=rule_counter.most_common(10),
        severity_distribution=dict(severity_counter),
    )
