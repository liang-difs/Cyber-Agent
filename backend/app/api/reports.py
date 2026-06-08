"""Reports API — incident report generation."""

from __future__ import annotations

import re
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from app.api.deps import get_current_user, scoped_tenant
from app.api.alerts import _serialize_alert_record
from app.rbac.permissions import Permission, require_permission

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])

_HTML_STYLE = """
body { font-family: -apple-system, 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 24px; color: #333; line-height: 1.6; font-size: 14px; }
h1 { font-size: 22px; border-bottom: 2px solid #1890ff; padding-bottom: 8px; }
h2 { font-size: 18px; margin-top: 24px; color: #1890ff; }
h3 { font-size: 15px; margin-top: 16px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: 13px; }
th { background: #f5f5f5; font-weight: 600; }
code { background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 13px; }
pre { background: #f5f5f5; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
blockquote { border-left: 3px solid #1890ff; margin: 12px 0; padding: 8px 16px; background: #f9f9f9; }
ul, ol { padding-left: 24px; }
li { margin-bottom: 4px; }
hr { border: none; border-top: 1px solid #eee; margin: 16px 0; }
strong { color: #222; }
@media print { body { padding: 0; } h2 { page-break-before: auto; } }
"""


def _markdown_to_html(md: str) -> str:
    """Lightweight markdown-to-HTML converter (no external deps)."""
    lines = md.split("\n")
    html_lines = []
    in_code = False
    in_table = False

    for line in lines:
        if line.startswith("```"):
            if in_code:
                html_lines.append("</code></pre>")
                in_code = False
            else:
                html_lines.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            html_lines.append(line.replace("&", "&amp;").replace("<", "&lt;"))
            continue

        # Table
        if "|" in line and line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue  # separator row
            if not in_table:
                html_lines.append("<table>")
                tag = "th"
                in_table = True
            else:
                tag = "td"
            row = "".join(f"<{tag}>{c}</{tag}>" for c in cells)
            html_lines.append(f"<tr>{row}</tr>")
            continue
        elif in_table:
            html_lines.append("</table>")
            in_table = False

        # Headings
        if line.startswith("### "):
            html_lines.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("# "):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("> "):
            html_lines.append(f"<blockquote>{line[2:]}</blockquote>")
        elif line.startswith("---"):
            html_lines.append("<hr>")
        elif line.startswith("- "):
            html_lines.append(f"<li>{line[2:]}</li>")
        elif line.strip() == "":
            html_lines.append("")
        else:
            # Inline formatting
            text = line
            text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
            text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
            html_lines.append(f"<p>{text}</p>")

    if in_table:
        html_lines.append("</table>")

    return "\n".join(html_lines)


def _wrap_html(title: str, body_md: str) -> str:
    """Wrap markdown content in a styled HTML page."""
    body_html = _markdown_to_html(body_md)
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>{title}</title>
<style>{_HTML_STYLE}</style></head><body>{body_html}</body></html>"""


def _get_current_user(user: dict = Depends(get_current_user)) -> dict:
    return user


def _build_alerts_from_anomalies(anomalies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build alert-like dicts from PCAP anomalies with proper confidence."""
    from app.analysis.alert_assessment import build_alert_assessment
    from app.tasks.pcap_analysis import _alert_base_confidence, _build_pcap_alert_fields

    alerts = []
    for a in anomalies:
        triage = _build_pcap_alert_fields(a)
        confidence = triage["confidence"]
        assessment = build_alert_assessment(
            rule_id=f"pcap_{a.get('type', 'unknown')}",
            description=a.get("detail", ""),
            src_ip=a.get("src_ip"),
            dst_ip=a.get("dst_ip"),
            severity=a.get("severity", "medium"),
            verdict=triage["verdict"],
            confidence=confidence,
            ttps=triage.get("ttps"),
            evidence=[f"pcap_anomaly:{a.get('type', 'unknown')}"],
        )
        alerts.append({
            "id": f"pcap-{a.get('type', '')}-{len(alerts)}",
            "rule_id": f"pcap_{a.get('type', 'unknown')}",
            "src_ip": a.get("src_ip"),
            "dst_ip": a.get("dst_ip"),
            "severity": a.get("severity", "medium"),
            "status": "open",
            "verdict": triage["verdict"],
            "confidence": confidence,
            "description": a.get("detail", ""),
            "ttp_ids": triage.get("ttp_ids", []),
            "created_at": None,
            "assessment": assessment,
        })
    return alerts


class ReportRequest(BaseModel):
    title: str = "Incident Report"
    tenant_id: str = "default"
    time_window_hours: int = 24
    analyst_notes: str = ""
    include_raw_data: bool = False
    src_ip: Optional[str] = None


class PcapReportRequest(BaseModel):
    title: str = "PCAP 安全事件报告"
    tenant_id: str = "default"
    time_window_hours: int = 24
    analyst_notes: str = ""
    pcap_result: dict  # Full PCAP analysis result


@router.post("/generate")
async def generate_report(
    req: ReportRequest,
    format: str = Query(default="markdown", pattern="^(markdown|html|pdf|docx)$"),
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.REPORT_GENERATE, auth=Depends(_get_current_user))),
):
    """Generate a Markdown incident report from alerts.

    Supports formats: markdown, html, pdf, docx.
    """

    try:
        from app.models.base import get_session_factory
        from app.models.models import Alert
        from sqlalchemy import select

        factory = get_session_factory()
        if factory is None:
            raise HTTPException(status_code=503, detail="Database not available")

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            query = select(Alert).where(Alert.tenant_id == tenant_id)
            if req.src_ip:
                query = query.where(Alert.src_ip == req.src_ip)
            query = query.order_by(Alert.created_at).limit(1000)

            result = await session.execute(query)
            db_alerts = result.scalars().all()

        if not db_alerts:
            return PlainTextResponse(
                "# No Alerts Found\n\nNo alerts match the specified criteria.",
                media_type="text/markdown",
            )

        alerts = [_serialize_alert_record(a) for a in db_alerts]

        # Run analysis
        from app.analysis.attack_chain import build_attack_chains
        from app.analysis.correlation import analyze_correlations
        from app.reports.generator import generate_incident_report

        chains = build_attack_chains(alerts, time_window_hours=req.time_window_hours)
        corr = analyze_correlations(alerts)

        report = generate_incident_report(
            title=req.title,
            alerts=alerts,
            attack_chains=[c.to_dict() for c in chains],
            correlation_result=corr.to_dict(),
            analyst_notes=req.analyst_notes,
            include_raw_data=req.include_raw_data,
        )

        if format == "html":
            return HTMLResponse(_wrap_html(req.title, report))
        if format == "pdf":
            from app.reports.exporters import export_to_pdf
            from fastapi.responses import Response
            html = _wrap_html(req.title, report)
            pdf_bytes = export_to_pdf(req.title, html)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{req.title}.pdf"'},
            )
        if format == "docx":
            from app.reports.exporters import export_to_docx
            from fastapi.responses import Response
            docx_bytes = export_to_docx(req.title, report)
            return Response(
                content=docx_bytes,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": f'attachment; filename="{req.title}.docx"'},
            )
        return PlainTextResponse(report, media_type="text/markdown")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-pcap")
async def generate_pcap_report(
    req: PcapReportRequest,
    format: str = Query(default="markdown", pattern="^(markdown|html|pdf|docx)$"),
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.REPORT_GENERATE, auth=Depends(_get_current_user))),
):
    """Generate a Markdown incident report enriched with PCAP analysis data.

    Supports formats: markdown, html, pdf, docx.
    """

    try:
        from app.models.base import get_session_factory
        from app.models.models import Alert
        from sqlalchemy import select

        factory = get_session_factory()
        alerts: list[dict[str, Any]] = []

        if factory is not None:
            try:
                async with factory() as session:
                    tenant_id = scoped_tenant(user)
                    query = select(Alert).where(Alert.tenant_id == tenant_id)
                    query = query.order_by(Alert.created_at).limit(1000)
                    result = await session.execute(query)
                    db_alerts = result.scalars().all()
                alerts = [_serialize_alert_record(a) for a in db_alerts]
            except Exception:
                pass

        # If DB alerts are empty or all have 0 confidence, merge from pcap_result anomalies
        all_zero = alerts and all(a.get("confidence", 0) == 0 for a in alerts)
        if not alerts or all_zero:
            anomalies = req.pcap_result.get("anomalies", [])
            if anomalies:
                alerts = _build_alerts_from_anomalies(anomalies)

        from app.analysis.attack_chain import build_attack_chains
        from app.analysis.correlation import analyze_correlations
        from app.reports.generator import generate_pcap_incident_report

        chains = build_attack_chains(alerts, time_window_hours=req.time_window_hours)
        corr = analyze_correlations(alerts)

        report = generate_pcap_incident_report(
            title=req.title,
            pcap_result=req.pcap_result,
            alerts=alerts,
            attack_chains=[c.to_dict() for c in chains],
            correlation_result=corr.to_dict(),
            analyst_notes=req.analyst_notes,
        )

        if format == "html":
            return HTMLResponse(_wrap_html(req.title, report))
        if format == "pdf":
            from app.reports.exporters import export_to_pdf
            from fastapi.responses import Response
            html = _wrap_html(req.title, report)
            pdf_bytes = export_to_pdf(req.title, html)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{req.title}.pdf"'},
            )
        if format == "docx":
            from app.reports.exporters import export_to_docx
            from fastapi.responses import Response
            docx_bytes = export_to_docx(req.title, report)
            return Response(
                content=docx_bytes,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": f'attachment; filename="{req.title}.docx"'},
            )
        return PlainTextResponse(report, media_type="text/markdown")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
