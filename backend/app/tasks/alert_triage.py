"""
Alert triage task — ATT&CK mapping + confidence scoring.

Flow:
1. Receive alert metadata
2. Enrich with IoC lookups (IP reputation)
3. Map to MITRE ATT&CK TTPs
4. Compute verdict (true_positive / false_positive / suspicious)
5. Update alert in DB
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.tasks.celery_app import celery_app
from app.analysis.alert_assessment import build_alert_assessment

logger = logging.getLogger(__name__)

# Simplified ATT&CK tactic mapping based on alert rule patterns.
# Order matters: more specific patterns must come before generic ones.
TACTIC_MAP = {
    "suspicious_port": {"tactic": "TA0011", "name": "Command and Control", "technique": "T1571"},
    "tls_downgrade": {"tactic": "TA0005", "name": "Defense Evasion", "technique": "T1600"},
    "beacon": {"tactic": "TA0011", "name": "Command and Control", "technique": "T1071"},
    "scan": {"tactic": "TA0043", "name": "Reconnaissance", "technique": "T1595"},
    "brute": {"tactic": "TA0006", "name": "Credential Access", "technique": "T1110"},
    "exploit": {"tactic": "TA0002", "name": "Execution", "technique": "T1203"},
    "lateral": {"tactic": "TA0008", "name": "Lateral Movement", "technique": "T1021"},
    "exfil": {"tactic": "TA0010", "name": "Exfiltration", "technique": "T1041"},
    "c2": {"tactic": "TA0011", "name": "Command and Control", "technique": "T1071"},
    "persist": {"tactic": "TA0003", "name": "Persistence", "technique": "T1053"},
    "privilege": {"tactic": "TA0004", "name": "Privilege Escalation", "technique": "T1068"},
    "defense_evasion": {"tactic": "TA0005", "name": "Defense Evasion", "technique": "T1070"},
    "collection": {"tactic": "TA0009", "name": "Collection", "technique": "T1005"},
}


def _map_ttps(rule_id: str, description: str = "") -> list[dict[str, str]]:
    """Map alert rule to ATT&CK TTPs based on keyword matching."""
    text = f"{rule_id} {description}".lower()
    matched = []
    for keyword, ttp in TACTIC_MAP.items():
        if keyword in text:
            matched.append(ttp)
    return matched if matched else [{"tactic": "TA0001", "name": "Initial Access", "technique": "T1190"}]


def _compute_verdict(
    confidence: float,
    src_ip_reputation: Optional[float] = None,
) -> tuple[str, float]:
    """Compute verdict from confidence and IP reputation."""
    score = confidence
    if src_ip_reputation is not None:
        score = 0.6 * confidence + 0.4 * (src_ip_reputation / 100.0)

    if score >= 0.7:
        return "true_positive", score
    elif score >= 0.4:
        return "suspicious", score
    else:
        return "false_positive", score


@celery_app.task(name="app.tasks.alert_triage.triage_alert", queue="celery_critical")
def triage_alert(
    alert_id: str,
    rule_id: str,
    description: str = "",
    src_ip: Optional[str] = None,
    tenant_id: str = "default",
) -> dict[str, Any]:
    """
    Triage a single alert.

    Returns verdict, TTPs, and updated confidence.
    """
    logger.info("Triaging alert %s (rule=%s, src_ip=%s)", alert_id, rule_id, src_ip)

    ttps = _map_ttps(rule_id, description)
    tactic = ttps[0]["tactic"] if ttps else None
    ttp_ids = [t["technique"] for t in ttps]

    verdict, final_confidence = _compute_verdict(confidence=0.5)
    assessment = build_alert_assessment(
        rule_id=rule_id,
        description=description,
        src_ip=src_ip,
        verdict=verdict,
        confidence=final_confidence,
        ttps=ttps,
        evidence=[
            f"rule_id:{rule_id}",
            *( [f"description:{description}"] if description else [] ),
            *( [f"src_ip:{src_ip}"] if src_ip else [] ),
        ],
    )

    result = {
        "alert_id": alert_id,
        "verdict": verdict,
        "confidence": round(final_confidence, 2),
        "ttps": ttps,
        "tactic": tactic,
        "ttp_ids": ttp_ids,
        "reasoning": f"规则 {rule_id} 命中 {len(ttps)} 个 ATT&CK 映射项",
        "assessment": assessment,
        "tenant_id": tenant_id,
        "enrichment": {
            "ip_reputation": None,
            "geo": None,
        },
    }

    # Persist triage results back to the Alert row
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from app.models.models import Alert
        from app.core.config import get_settings

        settings = get_settings()
        if settings.database_url:
            sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")
            engine = create_engine(sync_url)
            with Session(engine) as session:
                alert = session.get(Alert, alert_id)
                if alert:
                    alert.verdict = verdict
                    alert.confidence = round(final_confidence, 2)
                    alert.ttp_ids = ttp_ids
                    session.commit()
                    logger.info("Alert %s updated in DB: verdict=%s", alert_id, verdict)
            engine.dispose()
    except Exception as e:
        logger.warning("Failed to persist triage result for alert %s: %s", alert_id, e)

    logger.info(
        "Alert %s triaged: verdict=%s, confidence=%.2f, ttps=%d",
        alert_id, verdict, final_confidence, len(ttps),
    )

    # 触发告警事件管线（异步）
    try:
        from app.events.alert_pipeline import get_alert_pipeline
        import asyncio

        pipeline = get_alert_pipeline()

        # 构建告警数据
        alert_data = {
            "id": alert_id,
            "rule_id": rule_id,
            "description": description,
            "src_ip": src_ip,
            "severity": "medium",  # 默认严重等级
            "verdict": verdict,
            "confidence": final_confidence,
            "tenant_id": tenant_id,
        }

        # 异步触发管线（不阻塞当前任务）
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # 如果事件循环正在运行，创建任务
                asyncio.ensure_future(pipeline.process_alert(alert_data))
            else:
                # 否则直接运行
                loop.run_until_complete(pipeline.process_alert(alert_data))
        except RuntimeError:
            # 没有事件循环，创建新的
            asyncio.run(pipeline.process_alert(alert_data))

        logger.info("Alert pipeline triggered for alert %s", alert_id)
    except Exception as e:
        logger.warning("Failed to trigger alert pipeline for alert %s: %s", alert_id, e)

    return result
