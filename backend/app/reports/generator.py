"""Report generator — produces Markdown incident reports from analysis data."""

from __future__ import annotations

import logging
import ipaddress
import re
from datetime import datetime, timezone
from typing import List, Optional

logger = logging.getLogger(__name__)


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


# Known malware families — matched from pcap filenames (keyword → description).
# Longer keywords first to avoid partial matches (e.g. "emotet" before "emote").
_MALWARE_CONTEXT: dict[str, str] = {
    "cobaltstrike": "Cobalt Strike 是渗透测试框架，常被 APT 组织用于 C2 和横向移动。流量特征：HTTP/HTTPS/DNS 信标，规律性心跳间隔。",
    "asyncrat": "AsyncRAT 是开源远控木马，常出现在钓鱼攻击后的持久化阶段，使用加密 TCP 通信。",
    "wannacry": "WannaCry 是勒索软件，利用 EternalBlue (MS17-010) 漏洞在 SMB 端口 445 传播。",
    "nanocore": "NanoCore 是 RAT，常通过邮件附件传播，使用 TCP/HTTP C2 通道。",
    "formbook": "FormBook 是信息窃取器，以键盘记录和表单抓取为主，通过 HTTP POST 外传数据。",
    "trickbot": "TrickBot 是银行木马/僵尸网络，常与 Emotet 联动，通过 HTTPS 与 C2 通信。",
    "dridex": "Dridex 是银行木马，通过宏文档传播，常与 Emotet 配合使用，使用 P2P 网络架构。",
    "qakbot": "QakBot（QBot）是银行木马/加载器，常用于勒索软件预投放，通过 SMB 横向传播。",
    "emotet": "Emotet 是模块化僵尸网络，通过钓鱼邮件传播，功能包括凭据窃取、载荷投递和 C2 通信。",
    "geodo": "Geodo（Emotet 别名）是银行木马/僵尸网络加载器，感染后对外发起 C2 信标并横向传播。流量特征：对多个外部 IP 的固定端口（如 8080）高频连接。",
    "mirai": "Mirai 是 IoT 僵尸网络恶意软件，通过默认凭据暴力破解 Telnet (23/2323) 扩散，DDoS 攻击载荷。",
    "ryuk": "Ryuk 勒索软件，通常由 TrickBot/Emotet 投递，针对性加密高价值目标。",
    "conti": "Conti 勒索软件团伙流量，通过 RDP 横向移动 + SMB 文件加密。",
    "metasploit": "Meterpreter 或 Metasploit 载荷流量，特征为反向 TCP/HTTPS 连接。",
    "beacon": "Cobalt Strike Beacon 流量特征，使用 HTTP/HTTPS/DNS 作为 C2 通道。",
}

# Application protocol context based on common pcap filenames
_APP_PROTOCOL_CONTEXT: dict[str, str] = {
    "gmail": "Gmail 使用 HTTPS (443) 与 Google 服务器通信，SMTP/IMAP 用于邮件收发。正常流量中应以 TLS 加密为主。",
    "skype": "Skype 使用 HTTPS (443) 和自定义端口进行信令与媒体传输。可能出现 P2P 直连流量。",
    "http": "HTTP 明文流量，需重点关注敏感数据泄露（凭据、Cookie 等）。",
    "dns": "DNS 流量，需关注 DNS 隧道、高频查询、异常长子域名等。",
    "tls": "TLS 加密流量，需关注弱协议版本、证书异常等。",
    "ssh": "SSH 流量，需关注暴力破解、异常连接目标等。",
    "smtp": "SMTP 邮件流量，需关注中继滥用、钓鱼附件等。",
    "ftp": "FTP 明文传输，凭据和数据均未加密，高风险。",
    "telnet": "Telnet 明文协议，凭据未加密，建议禁用。",
    "bitcoin": "比特币相关流量，需关注挖矿行为、钱包地址泄露等。",
}


def _get_app_protocol_context(filename: str) -> Optional[str]:
    """Return context based on filename — malware families take priority over app protocols."""
    name = (filename or "").lower()
    stem = re.sub(r"\.(pcap|pcapng)$", "", name)

    # Malware family match (higher priority) — exact stem match first, then word-boundary regex
    if stem in _MALWARE_CONTEXT:
        return f"[恶意软件] {_MALWARE_CONTEXT[stem]}"
    for keyword, context in _MALWARE_CONTEXT.items():
        if re.search(rf"\b{re.escape(keyword)}\b", name):
            return f"[恶意软件] {context}"

    # Application protocol match
    for key, context in _APP_PROTOCOL_CONTEXT.items():
        if key in name:
            return context
    return None


def _format_chain_direction_note(chain: dict) -> Optional[str]:
    src_ips = chain.get("src_ips", []) or []
    dst_ips = chain.get("dst_ips", []) or []
    src_private = any(_is_private_ip(ip) for ip in src_ips if isinstance(ip, str))
    dst_private = any(_is_private_ip(ip) for ip in dst_ips if isinstance(ip, str))

    if src_private and not dst_private:
        return "- **方向提示:** 该攻击链表现为内网主机对外联通，优先隔离相关内网主机并核查其进程、账号和持久化痕迹"
    if not src_private and any(_is_private_ip(ip) for ip in dst_ips if isinstance(ip, str)):
        return "- **方向提示:** 该攻击链表现为外部对内网的活动，应优先检查边界封禁与受害主机"
    return None


def _format_general_risk_boundary(
    alerts: list[dict],
    attack_chains: list[dict],
    correlation_result: dict,
) -> list[str]:
    patterns = correlation_result.get("patterns", [])
    max_pattern_conf = max((p.get("confidence", 0) for p in patterns), default=0)
    max_chain_progression = max((c.get("progression_score", 0) for c in attack_chains), default=0)
    severity_dist = correlation_result.get("severity_distribution", {})
    total_alerts = correlation_result.get("total_alerts", len(alerts))

    notes = [
        f"- **已确认事实:** 本报告基于 {total_alerts} 条告警与其关联分析结果生成",
        "- **研判边界:** correlation/attack chain 结果属于关联推断，不自动等于已成功入侵、已持久化或已外泄",
        "- **推断原则:** 只有在告警描述、主机日志或外部情报给出直接证据时，才可把“疑似”升级为“已确认”",
    ]

    if severity_dist:
        dist_str = ", ".join(f"{v} {k}" for k, v in sorted(severity_dist.items()))
        notes.append(f"- **告警分布:** {dist_str}")

    if patterns:
        notes.append(f"- **模式置信度:** 当前最高关联模式置信度为 {max_pattern_conf:.0%}")
    else:
        notes.append("- **模式置信度:** 未发现可量化的关联模式，置信度仅能参考单条告警本身")

    if attack_chains:
        notes.append(f"- **链路进展:** 当前最高攻击链进展评分为 {max_chain_progression:.0%}")
        if any(_format_chain_direction_note(chain) for chain in attack_chains):
            notes.append("- **方向提示:** 部分攻击链显示内网主机对外活动，应优先隔离内网主机而不是只封禁外部地址")

    return notes


def _format_alert_assessments(alerts: list[dict]) -> list[str]:
    assessment_alerts = [a for a in alerts if a.get("assessment")]
    if not assessment_alerts:
        return []

    sections = ["## 告警研判摘要", ""]
    sections.append("以下内容来自告警记录中的 assessment 字段，用于区分事实、推断和边界。")
    sections.append("")

    for alert in assessment_alerts[:10]:
        assessment = alert.get("assessment") or {}
        sections.append(f"### `{alert.get('rule_id', 'unknown')}`")
        if alert.get("src_ip") or alert.get("dst_ip"):
            src = alert.get("src_ip", "-")
            dst = alert.get("dst_ip", "-")
            sections.append(f"- **关联流向:** `{src}` → `{dst}`")
        if alert.get("verdict"):
            sections.append(f"- **当前判定:** `{alert.get('verdict')}`")
        if assessment.get("confidence") is not None:
            sections.append(
                f"- **置信度:** {(assessment.get('confidence', 0) * 100):.0f}% "
                f"({assessment.get('confidence_label', 'unknown')})"
            )

        facts = assessment.get("facts", [])
        if facts:
            sections.append("- **已确认事实:**")
            for fact in facts[:5]:
                sections.append(f"  - {fact}")

        inferences = assessment.get("inferences", [])
        if inferences:
            sections.append("- **推断/研判:**")
            for item in inferences[:5]:
                sections.append(f"  - {item}")

        boundary = assessment.get("boundary", [])
        if boundary:
            sections.append("- **边界说明:**")
            for item in boundary[:5]:
                sections.append(f"  - {item}")

        evidence = assessment.get("evidence", [])
        if evidence:
            sections.append(f"- **证据标记:** {', '.join(evidence[:6])}")
        sections.append("")

    if len(assessment_alerts) > 10:
        sections.append(f"> 仅展示前 10 条告警研判摘要，共 {len(assessment_alerts)} 条包含 assessment。")
        sections.append("")

    return sections


def _format_pcap_time_note(summary: dict) -> list[str]:
    time_basis = summary.get("time_basis", "unknown")
    notes = [f"- **时间基准:** {time_basis}"]
    if time_basis == "relative":
        notes.append("- **时间说明:** 下面的时间仅表示抓包内先后顺序，不代表日历时间")
    elif summary.get("start_time") and summary.get("end_time"):
        notes.append(
            f"- **绝对时间范围:** {summary.get('start_time')} → {summary.get('end_time')}"
        )
    return notes


def _format_pcap_risk_boundary(summary: dict, anomalies: list[dict], pcap_result: dict) -> list[str]:
    notes = [
        "- **已确认事实:** 抓包中存在异常检测结果、协议元数据和 IoC 候选项",
        "- **研判边界:** 异常命中表示检测结果，不自动等于已成功入侵、已认证成功或已发生外泄",
        "- **推断原则:** 只有在 pcap_result 或外部情报给出直接证据时，才能写“已失陷 / 已外泄 / 已成功认证”",
    ]

    if any(a.get("type") == "data_exfil" for a in anomalies):
        notes.append("- **数据外泄提示:** `data_exfil` 仅表示大流量外传嫌疑，需要结合主机日志与内容解码进一步确认")

    if pcap_result.get("external_ips_for_lookup") or pcap_result.get("domains_for_lookup"):
        notes.append("- **IoC 提示:** 下方 IoC 待查清单中的条目是候选项，不代表全部已被情报命中")

    return notes


def generate_incident_report(
    title: str,
    alerts: List[dict],
    attack_chains: List[dict],
    correlation_result: dict,
    analyst_notes: str = "",
    include_raw_data: bool = False,
) -> str:
    """Generate a Markdown incident report.

    Args:
        title: Report title
        alerts: List of alert dicts
        attack_chains: List of attack chain dicts (from AttackChain.to_dict())
        correlation_result: Correlation result dict (from CorrelationResult.to_dict())
        analyst_notes: Optional analyst notes to include
        include_raw_data: Whether to include raw alert data in appendix

    Returns:
        Markdown string
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = []

    # Header
    sections.append(f"# {title}")
    sections.append(f"")
    sections.append(f"**Generated:** {now}")
    sections.append(f"**Total Alerts:** {correlation_result.get('total_alerts', len(alerts))}")
    sections.append("")

    # Executive Summary
    sections.append("## Executive Summary")
    sections.append("")
    summary_parts = []
    total = correlation_result.get("total_alerts", len(alerts))
    severity_dist = correlation_result.get("severity_distribution", {})
    if severity_dist:
        dist_str = ", ".join(f"{v} {k}" for k, v in sorted(severity_dist.items()))
        summary_parts.append(f"Analysis of **{total}** alerts ({dist_str}).")
    else:
        summary_parts.append(f"Analysis of **{total}** alerts.")

    patterns = correlation_result.get("patterns", [])
    if patterns:
        summary_parts.append(f"Detected **{len(patterns)}** correlation patterns.")

    chains = attack_chains
    if chains:
        max_progression = max(c.get("progression_score", 0) for c in chains)
        summary_parts.append(
            f"Identified **{len(chains)}** attack chain(s) "
            f"(max progression: {max_progression:.0%})."
        )

    sections.append(" ".join(summary_parts))
    sections.append("")

    # Reporting boundary
    sections.append("## 研判边界")
    sections.append("")
    sections.extend(_format_general_risk_boundary(alerts, attack_chains, correlation_result))
    sections.append("")

    alert_assessment_sections = _format_alert_assessments(alerts)
    if alert_assessment_sections:
        sections.extend(alert_assessment_sections)

    # Severity Distribution
    if severity_dist:
        sections.append("## Severity Distribution")
        sections.append("")
        for sev in ["critical", "high", "medium", "low"]:
            count = severity_dist.get(sev, 0)
            if count > 0:
                bar = "#" * min(count, 20)
                sections.append(f"- **{sev.upper()}**: {count} {bar}")
        sections.append("")

    # Top Source IPs
    top_ips = correlation_result.get("top_src_ips", [])
    if top_ips:
        sections.append("## Top Source IPs")
        sections.append("")
        sections.append("| IP | Alert Count |")
        sections.append("|---|---|")
        for entry in top_ips[:10]:
            if isinstance(entry, dict):
                ip = entry.get("ip", "")
                count = entry.get("count", 0)
            else:
                ip, count = entry[0], entry[1]
            sections.append(f"| `{ip}` | {count} |")
        sections.append("")

    # Attack Chains
    if chains:
        sections.append("## Attack Chains")
        sections.append("")
        for chain in chains:
            chain_id = chain.get("chain_id", "unknown")
            sections.append(f"### {chain_id}")
            sections.append("")
            sections.append(f"- **Severity:** {chain.get('severity', 'unknown')}")
            sections.append(f"- **Progression:** {chain.get('progression_score', 0):.0%}")
            sections.append(f"- **Source IPs:** {', '.join(f'`{ip}`' for ip in chain.get('src_ips', []))}")
            sections.append(f"- **Target IPs:** {', '.join(f'`{ip}`' for ip in chain.get('dst_ips', []))}")
            sections.append(f"- **Tactics:** {', '.join(chain.get('tactics_covered', []))}")
            direction_note = _format_chain_direction_note(chain)
            if direction_note:
                sections.append(direction_note)
            sections.append("")

            nodes = chain.get("nodes", [])
            if nodes:
                sections.append("**Timeline:**")
                sections.append("")
                for node in nodes:
                    ts = node.get("timestamp", "")
                    if isinstance(ts, str) and len(ts) > 19:
                        ts = ts[:19].replace("T", " ")
                    sections.append(
                        f"1. `{ts}` — **{node.get('tactic', '')}** via "
                        f"`{node.get('rule_id', '')}` "
                        f"({node.get('src_ip', '?')} → {node.get('dst_ip', '?')})"
                    )
                sections.append("")

    # Correlation Patterns
    if patterns:
        sections.append("## Correlation Patterns")
        sections.append("")
        for i, p in enumerate(patterns, 1):
            ptype = p.get("pattern_type", "unknown")
            desc = p.get("description", "")
            conf = p.get("confidence", 0)
            sections.append(f"{i}. **{ptype}** (confidence: {conf:.0%})")
            sections.append(f"   {desc}")
            sections.append("")

    # Top Rules
    top_rules = correlation_result.get("top_rules", [])
    if top_rules:
        sections.append("## Top Triggered Rules")
        sections.append("")
        sections.append("| Rule | Count |")
        sections.append("|---|---|")
        for entry in top_rules[:10]:
            if isinstance(entry, dict):
                rule = entry.get("rule_id", "")
                count = entry.get("count", 0)
            else:
                rule, count = entry[0], entry[1]
            sections.append(f"| `{rule}` | {count} |")
        sections.append("")

    # Analyst Notes
    if analyst_notes:
        sections.append("## Analyst Notes")
        sections.append("")
        sections.append(analyst_notes)
        sections.append("")

    # Raw Data Appendix
    if include_raw_data and alerts:
        sections.append("## Appendix: Raw Alert Data")
        sections.append("")
        sections.append("```json")
        import json
        sections.append(json.dumps(alerts[:50], indent=2, default=str))
        if len(alerts) > 50:
            sections.append(f"... and {len(alerts) - 50} more alerts")
        sections.append("```")
        sections.append("")

    # Footer
    sections.append("---")
    from app.core.constants import APP_VERSION
    sections.append(f"*Report generated by CyberSec Agent v{APP_VERSION} — {now}*")

    return "\n".join(sections)


def generate_pcap_incident_report(
    title: str,
    pcap_result: dict,
    alerts: List[dict],
    attack_chains: List[dict],
    correlation_result: dict,
    analyst_notes: str = "",
) -> str:
    """Generate an incident report enriched with PCAP analysis data.

    Args:
        title: Report title
        pcap_result: Full PCAP analysis result dict
        alerts: List of alert dicts
        attack_chains: List of attack chain dicts
        correlation_result: Correlation result dict
        analyst_notes: Optional analyst notes

    Returns:
        Markdown string with base report + PCAP-specific sections
    """
    # Generate base report
    base_report = generate_incident_report(
        title=title,
        alerts=alerts,
        attack_chains=attack_chains,
        correlation_result=correlation_result,
        analyst_notes=analyst_notes,
    )

    pcap_sections = []
    summary = pcap_result.get("summary", {})

    # Traffic Overview
    pcap_sections.append("## PCAP 流量概览")
    pcap_sections.append("")
    pcap_identity = pcap_result.get("pcap_identity", {}) if isinstance(pcap_result.get("pcap_identity"), dict) else {}
    display_filename = pcap_identity.get("display_filename") or pcap_result.get("display_filename")
    source_path = pcap_identity.get("source_path") or pcap_result.get("source_path") or pcap_result.get("pcap_path")
    if display_filename:
        pcap_sections.append(f"- **分析文件:** `{display_filename}`")
        app_ctx = _get_app_protocol_context(display_filename)
        if app_ctx:
            pcap_sections.append(f"- **应用背景:** {app_ctx}")
    if source_path and source_path != display_filename:
        pcap_sections.append(f"- **源路径:** `{source_path}`")
    pcap_sections.append(f"- **总包数:** {summary.get('total_packets', 0):,}")
    pcap_sections.append(f"- **流记录数:** {summary.get('total_flows', 0):,}")
    dur = summary.get("duration_s")
    if dur is not None:
        pcap_sections.append(f"- **抓包时长:** {dur:,.1f}s")
    else:
        pcap_sections.append("- **抓包时长:** N/A（相对时间模式下无法计算）")
    pcap_sections.extend(_format_pcap_time_note(summary))
    total_bytes = summary.get("total_bytes", 0)
    if total_bytes > 1024 * 1024:
        pcap_sections.append(f"- **总字节数:** {total_bytes / 1024 / 1024:,.1f} MB")
    elif total_bytes > 1024:
        pcap_sections.append(f"- **总字节数:** {total_bytes / 1024:,.1f} KB")
    else:
        pcap_sections.append(f"- **总字节数:** {total_bytes:,} B")
    pcap_sections.append(f"- **异常数:** {summary.get('anomaly_count', 0)}")
    top_protos = summary.get("top_protocols", [])
    if top_protos:
        proto_str = ", ".join(f"{p['protocol']}({p['count']})" for p in top_protos[:5])
        pcap_sections.append(f"- **主要协议:** {proto_str}")
    pcap_sections.append("")

    # Reporting boundary
    pcap_sections.append("## PCAP 研判边界")
    pcap_sections.append("")
    pcap_sections.extend(_format_pcap_risk_boundary(summary, pcap_result.get("anomalies", []), pcap_result))
    pcap_sections.append("")

    # DNS Anomalies
    dns_stats = pcap_result.get("dns", {}).get("stats", {})
    long_subs = dns_stats.get("long_subdomains", [])
    txt_queries = dns_stats.get("txt_queries", [])
    high_freq = dns_stats.get("high_frequency", [])
    if long_subs or txt_queries or high_freq:
        pcap_sections.append("## DNS 异常（检测结果）")
        pcap_sections.append("")
        if long_subs:
            pcap_sections.append(f"**超长子域名** ({len(long_subs)} 个，可能 DNS 隧道):")
            for d in long_subs[:10]:
                pcap_sections.append(f"- `{d}`")
            pcap_sections.append("")
        if txt_queries:
            pcap_sections.append(f"**TXT 查询** ({len(txt_queries)} 个):")
            for d in txt_queries[:10]:
                pcap_sections.append(f"- `{d}`")
            pcap_sections.append("")
        if high_freq:
            pcap_sections.append("**高频查询:**")
            for h in high_freq[:5]:
                pcap_sections.append(f"- `{h['domain']}` — {h['count']}次/{h['window_s']}s")
            pcap_sections.append("")

    # Protocol Insights
    insights = pcap_result.get("protocol_insights", {})
    tls_sni = insights.get("tls_sni", [])
    http_hosts = insights.get("http_hosts", [])
    tls_versions = insights.get("tls_versions", {})
    weak_tls = {v: c for v, c in tls_versions.items() if v in ("SSLv3", "TLSv1.0", "TLSv1.1") or v.startswith("0x030")}
    if tls_sni or http_hosts or weak_tls:
        pcap_sections.append("## 协议深度分析（观察到的元数据）")
        pcap_sections.append("")
        if http_hosts:
            pcap_sections.append("**HTTP Hosts:**")
            for h in http_hosts[:10]:
                pcap_sections.append(f"- `{h['host']}` ({h['count']}次, 方法: {', '.join(h.get('methods', []))})")
            pcap_sections.append("")
        if tls_sni:
            pcap_sections.append("**TLS SNI (Server Name):**")
            for s in tls_sni[:10]:
                pcap_sections.append(f"- `{s['server_name']}` ({s['count']}次)")
            pcap_sections.append("")
        if weak_tls:
            pcap_sections.append("**弱 TLS 版本:**")
            for v, c in weak_tls.items():
                pcap_sections.append(f"- `{v}` — {c}次")
            pcap_sections.append("")

    # Anomaly Detection Summary
    anomalies = pcap_result.get("anomalies", [])
    if anomalies:
        pcap_sections.append("## PCAP 异常检测汇总")
        pcap_sections.append("")
        pcap_sections.append(f"共检测到 {len(anomalies)} 类异常：")
        pcap_sections.append("")
        conf_map = {"critical": 0.8, "high": 0.65, "medium": 0.45, "low": 0.25}
        for a in anomalies:
            sev = a.get("severity", "medium").upper()
            atype = a.get("type", "unknown")
            detail = a.get("detail", "")
            src = a.get("src_ip", "")
            dst = a.get("dst_ip", "")
            count = a.get("count", 1)
            loc = f" `{src}` → `{dst}`" if src and dst else ""
            conf = conf_map.get(a.get("severity", "medium").lower(), 0.35)
            line = f"- **[{sev}] {atype}**{loc} ({count}次) — 置信度 {conf:.0%}"
            pcap_sections.append(line)
            if detail:
                pcap_sections.append(f"  - {detail}")
        pcap_sections.append("")

    # IoC Lookup List
    ext_ips = pcap_result.get("external_ips_for_lookup", [])
    domains = pcap_result.get("domains_for_lookup", [])
    if ext_ips or domains:
        pcap_sections.append("## IoC 待查清单")
        pcap_sections.append("")
        pcap_sections.append("> 这些条目是候选 IoC，不等于已经完成恶意确认。")
        pcap_sections.append("")
        if ext_ips:
            pcap_sections.append("**外部 IP（可用于威胁情报查询）:**")
            for ip in ext_ips[:20]:
                pcap_sections.append(f"- `{ip}`")
            pcap_sections.append("")
        if domains:
            pcap_sections.append("**域名（可用于 IoC 查询）:**")
            for d in domains[:20]:
                pcap_sections.append(f"- `{d}`")
            pcap_sections.append("")

    # Insert PCAP sections before the footer
    footer_marker = "---\n*Report generated"
    if footer_marker in base_report:
        return base_report.replace(footer_marker, "\n".join(pcap_sections) + "\n\n" + footer_marker)
    return base_report + "\n\n" + "\n".join(pcap_sections)