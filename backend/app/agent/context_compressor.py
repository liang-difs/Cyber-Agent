"""Context compression for ReAct agent.

Handles:
- Observation truncation (token budget)
- History compression (summarize old turns)
- Token estimation
"""

from __future__ import annotations

import json
import os
from typing import Any


def estimate_tokens(text: str) -> int:
    """Token estimation with CJK-aware heuristic.

    CJK characters are typically 1-2 tokens each, while ASCII is ~4 chars/token.
    This function weights CJK characters more heavily.
    """
    if not text:
        return 0
    cjk_count = sum(1 for c in text if '\u4e00' <= c <= '\u9fff' or '\u3000' <= c <= '\u303f')
    ascii_count = len(text) - cjk_count
    return max(1, cjk_count // 2 + ascii_count // 4)


def truncate_observation(observation: str, max_tokens: int = 2000) -> str:
    """Truncate tool observation to fit token budget.

    Preserves the first max_tokens worth of content and adds [TRUNCATED] marker.
    """
    estimated = estimate_tokens(observation)
    if estimated <= max_tokens:
        return observation

    # Approximate char limit from token budget
    char_limit = max_tokens * 4
    truncated = observation[:char_limit]

    # Try to cut at a clean boundary (last newline or comma)
    for sep in ["\n", ",", " "]:
        last_sep = truncated.rfind(sep)
        if last_sep > char_limit * 0.8:
            truncated = truncated[:last_sep]
            break

    return truncated + "\n[TRUNCATED]"


def _compact_cve_catalog_observation(tool_result: dict[str, Any]) -> dict[str, Any]:
    """Keep cve_catalog observations structured and compact."""
    data = tool_result.get("data") if isinstance(tool_result.get("data"), dict) else {}
    stats = data.get("stats") if isinstance(data.get("stats"), dict) else {}
    items = data.get("items") if isinstance(data.get("items"), list) else []
    evidence_rows = data.get("evidence") if isinstance(data.get("evidence"), list) else []

    compact_items: list[dict[str, Any]] = []
    for item in items[:10]:
        if not isinstance(item, dict):
            continue
        compact_items.append({
            "cve_id": item.get("cve_id", ""),
            "doc_id": item.get("doc_id", ""),
            "title": item.get("title", ""),
            "published": item.get("published", ""),
            "cvss_score": item.get("cvss_score", 0.0),
            "severity": item.get("severity", "UNKNOWN"),
            "is_kev": item.get("is_kev", False),
            "kev_date": item.get("kev_date", ""),
            "vendor": item.get("vendor", ""),
            "product": item.get("product", ""),
            "source_path": item.get("source_path", ""),
            "first_seen": item.get("first_seen", ""),
        })

    compact_evidence: list[dict[str, Any]] = []
    for entry in evidence_rows[:20]:
        if not isinstance(entry, dict):
            continue
        compact_evidence.append({
            "cve_id": entry.get("cve_id", ""),
            "source_type": entry.get("source_type", ""),
            "source_path": entry.get("source_path", ""),
            "doc_id": entry.get("doc_id", ""),
            "key_dates": entry.get("key_dates", {}),
            "note": entry.get("note", ""),
        })

    compact = {
        "success": tool_result.get("success"),
        "tool_name": tool_result.get("tool_name"),
        "tool_version": tool_result.get("tool_version"),
        "confidence": tool_result.get("confidence"),
        "evidence_source": tool_result.get("evidence_source", []),
        "execution_time_ms": tool_result.get("execution_time_ms", 0),
        "query": data.get("query", ""),
        "filters": data.get("filters", {}),
        "summary_text": data.get("summary_text", ""),
        "total_cve_docs": data.get("total_cve_docs", 0),
        "total_kev_docs": data.get("total_kev_docs", 0),
        "matched_count": data.get("matched_count", 0),
        "kev_count": data.get("kev_count", 0),
        "returned_count": data.get("returned_count", len(items)),
        "returned_kev_count": data.get("returned_kev_count", 0),
        "stats": {
            "matched_count": stats.get("matched_count", data.get("matched_count", 0)),
            "kev_count": stats.get("kev_count", data.get("kev_count", 0)),
            "kev_hit_rate": stats.get("kev_hit_rate", 0.0),
            "by_year": stats.get("by_year", {}),
            "by_severity": stats.get("by_severity", {}),
            "kev_by_year": stats.get("kev_by_year", {}),
            "kev_by_severity": stats.get("kev_by_severity", {}),
            "coverage": stats.get("coverage", {}),
        },
        "evidence": compact_evidence,
        "items": compact_items,
        "reporting_requirements": [
            "必须优先使用 summary_text 和 stats 总结结果，不要只复述原始 items。",
            "当 items 数量超过返回条数时，只把当前返回项当作样本，不要把它们说成全集。",
            "需要展示时优先列出 top items 的 cve_id、doc_id、published、cvss_score、severity、is_kev。",
            "必须区分已命中的全集统计与分页/截断后的返回条数。",
            "如果问题要求按年、按严重级别或 KEV 命中率统计，应直接引用 stats 里的对应字段。",
            "证据字段必须显式保留 source_type、source_path、doc_id、key_dates。",
        ],
    }

    return compact


def compact_tool_observation(tool_result: dict[str, Any], max_tokens: int = 2000) -> str:
    """Compact tool output for LLM observation without losing critical fields.

    PCAP analysis results can contain thousands of flows/timeline rows. Generic
    string truncation may cut off later anomalies and expose `[TRUNCATED]` to the
    LLM, which then leaks that implementation detail to users. For PCAP, keep
    the full anomaly list and core metadata, and omit bulky raw tables.
    """
    if tool_result.get("tool_name") == "cve_catalog":
        compact = _compact_cve_catalog_observation(tool_result)
        observation = json.dumps(compact, ensure_ascii=False)
        if estimate_tokens(observation) <= max_tokens:
            return observation

        compact["items"] = []
        observation = json.dumps(compact, ensure_ascii=False)
        if estimate_tokens(observation) <= max_tokens:
            return observation

        compact.pop("stats", None)
        compact.pop("summary_text", None)
        return json.dumps(compact, ensure_ascii=False)

    if tool_result.get("tool_name") != "pcap_analysis":
        return truncate_observation(json.dumps(tool_result, ensure_ascii=False), max_tokens)

    data = tool_result.get("data") or {}
    pcap_path = data.get("pcap_path") or data.get("source_path") or ""
    pcap_identity = data.get("pcap_identity") if isinstance(data.get("pcap_identity"), dict) else {}
    display_filename = (
        pcap_identity.get("display_filename")
        or pcap_identity.get("original_filename")
        or data.get("display_filename")
        or (os.path.basename(pcap_path) if pcap_path else "")
    )
    anomalies = data.get("anomalies") or []
    summary = data.get("summary") or {}
    protocols = data.get("protocols") or {}
    dns = data.get("dns") or {}
    dns_stats = dns.get("stats", {}) if isinstance(dns, dict) else {}
    protocol_insights = data.get("protocol_insights") or {}

    compact = {
        "success": tool_result.get("success"),
        "tool_name": tool_result.get("tool_name"),
        "tool_version": tool_result.get("tool_version"),
        "confidence": tool_result.get("confidence"),
        "evidence_source": tool_result.get("evidence_source", []),
        "execution_time_ms": tool_result.get("execution_time_ms", 0),
        "pcap_identity": {
            "display_filename": display_filename,
            "original_filename": pcap_identity.get("original_filename") or display_filename,
            "source_path": pcap_path,
            "sha256": data.get("sha256"),
        },
        "summary": summary,
        "time_basis": summary.get("time_basis", "unknown"),
        "summary_text": data.get("summary_text", ""),
        "anomalies_complete": True,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "external_ips_for_lookup": data.get("external_ips_for_lookup", []),
        "domains_for_lookup": data.get("domains_for_lookup", []),
        "protocols": protocols,
        "dns_stats": dns_stats,
        "protocol_insights": {
            "http_hosts": protocol_insights.get("http_hosts", [])[:20] if isinstance(protocol_insights, dict) else [],
            "tls_sni": protocol_insights.get("tls_sni", [])[:20] if isinstance(protocol_insights, dict) else [],
            "tls_versions": protocol_insights.get("tls_versions", {}) if isinstance(protocol_insights, dict) else {},
            "ssh_versions": protocol_insights.get("ssh_versions", [])[:20] if isinstance(protocol_insights, dict) else [],
        },
        "omitted_large_fields": ["flows", "timeline", "dns.queries", "ips"],
        "reporting_requirements": [
            "必须逐条列出 anomalies 中的每一项；不得声称异常列表被截断。",
            "报告文件名必须使用 pcap_identity.display_filename；不得编造其他文件名。",
            "若 summary.time_basis 为 relative，只能使用抓包内先后顺序或 T+xx 表达时间，不得写绝对日期。",
            "不得编造未在工具结果中出现的主机 IP、国家/城市、哈希、payload、认证成功或数据外泄结论。",
            "必须区分已确认事实与推断；没有直接证据时使用“疑似/可能/不能排除”。",
            "若存在 high/critical 行为异常，不得仅因 IP 信誉低风险就给出低危结论，必须解释行为证据与情报证据的权重差异。",
        ],
    }

    observation = json.dumps(compact, ensure_ascii=False)
    if estimate_tokens(observation) <= max_tokens:
        return observation

    # If a PCAP has an unusually large anomaly list, still keep every anomaly
    # and shed secondary fields first.
    compact.pop("protocol_insights", None)
    compact.pop("dns_stats", None)
    compact.pop("protocols", None)
    observation = json.dumps(compact, ensure_ascii=False)
    if estimate_tokens(observation) <= max_tokens:
        return observation

    compact.pop("summary_text", None)
    return json.dumps(compact, ensure_ascii=False)


def should_compress(message_count: int, interval: int = 4) -> bool:
    """Check if history compression should trigger."""
    return message_count >= interval


def compress_history(messages: list[dict[str, Any]], keep_recent: int = 4) -> list[dict[str, Any]]:
    """Compress older messages into a summary, keeping recent messages intact.

    Args:
        messages: Full message list in LLM format
        keep_recent: Number of recent messages to keep verbatim

    Returns:
        Compressed message list: [summary_message, ...recent_messages]
    """
    if len(messages) <= keep_recent:
        return messages

    leading_system: list[dict[str, Any]] = []
    working_messages = list(messages)
    if working_messages and working_messages[0].get("role") == "system":
        leading_system = [working_messages[0]]
        working_messages = working_messages[1:]

    if len(working_messages) <= keep_recent:
        return messages

    old_messages = working_messages[:-keep_recent]
    recent_messages = working_messages[-keep_recent:]

    # Build summary of old messages
    summary_parts = []
    for msg in old_messages:
        role = msg.get("role", "unknown")
        content = msg.get("content", "")
        if role == "tool":
            # Summarize tool results briefly
            summary_parts.append(f"[Tool result: {estimate_tokens(content)} tokens]")
        elif role == "assistant" and msg.get("tool_calls"):
            tool_names = [tc.get("function", {}).get("name", "?") for tc in msg["tool_calls"]]
            summary_parts.append(f"[Called tools: {', '.join(tool_names)}]")
        else:
            # Truncate long content for summary
            brief = content[:200] + "..." if len(content) > 200 else content
            summary_parts.append(f"[{role}]: {brief}")

    summary_text = "=== 历史对话摘要 ===\n" + "\n".join(summary_parts)

    summary_message = {
        "role": "assistant",
        "content": summary_text,
    }

    return leading_system + [summary_message] + recent_messages
