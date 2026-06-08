"""Alert assessment helpers — shared summary/guardrail structure."""

from __future__ import annotations

from typing import Any, Optional


def confidence_label(confidence: float) -> str:
    """Map confidence score to a label reflecting evidence sufficiency.

    Decoupled from severity — this measures how well-supported the verdict is,
    not how dangerous the alert is.
    """
    if confidence >= 0.80:
        return "high"
    if confidence >= 0.60:
        return "medium"
    if confidence >= 0.35:
        return "low"
    return "insufficient"


def build_alert_assessment(
    *,
    rule_id: str,
    description: str = "",
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    verdict: Optional[str] = None,
    confidence: float = 0.0,
    ttps: Optional[list[dict[str, str]]] = None,
    evidence: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Build a consistent assessment object for alerts and triage results."""
    ttps = ttps or []
    evidence = evidence or []

    facts = [f"规则 `{rule_id}` 命中"]
    if src_ip:
        facts.append(f"源 IP: `{src_ip}`")
    if dst_ip:
        facts.append(f"目标 IP: `{dst_ip}`")
    if severity:
        facts.append(f"严重程度: `{severity}`")
    if status:
        facts.append(f"状态: `{status}`")
    if description:
        facts.append(f"描述: {description}")

    inferences = []
    if verdict:
        inferences.append(f"当前研判结果为 `{verdict}`")
    if ttps:
        tactic_names = sorted({
            t.get("name") or t.get("technique") or t.get("tactic")
            for t in ttps
            if (t.get("name") or t.get("technique") or t.get("tactic"))
        })
        if tactic_names:
            inferences.append(f"映射到 ATT&CK 战术/技术：{', '.join(tactic_names)}")
    if confidence > 0:
        inferences.append(f"研判置信度约为 {round(confidence * 100):d}%")
    else:
        inferences.append("尚未形成可用的研判置信度，需要进一步分析")

    boundary = [
        "告警命中表示检测结果，不自动等于已成功入侵或已发生外泄",
        "需要结合主机日志、EDR、代理日志或原始流量进一步验证",
        "信誉分或地理位置只能作为辅助信息，不能替代行为证据",
    ]

    if ttps:
        boundary.append("ATT&CK 映射是规则/描述驱动的关联结果，不能当作直接事实")

    return {
        "confidence": round(confidence, 2),
        "confidence_label": confidence_label(confidence),
        "facts": facts,
        "inferences": inferences,
        "boundary": boundary,
        "evidence": evidence,
    }
