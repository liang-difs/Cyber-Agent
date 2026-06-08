"""Log Analysis Tool — parses and analyzes security log files.

Supports syslog, Windows Event Log (XML/JSON), Apache/Nginx access logs,
and generic structured logs. Extracts IOCs, anomalies, and attack patterns.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter
from typing import Any

from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)

# ── IOC extraction patterns ──────────────────────────────────────
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}")
_HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# ── Suspicious keyword patterns ──────────────────────────────────
_SUSPICIOUS = {
    "brute_force": re.compile(r"(failed|invalid|incorrect).*(password|login|auth)", re.I),
    "injection": re.compile(r"(union\s+select|or\s+1=1|<script>|eval\(|exec\()", re.I),
    "privilege_escalation": re.compile(r"(sudo|su\s+root|runas|privilege|token.*elevat)", re.I),
    "lateral_movement": re.compile(r"(rdp|ssh|smb|psexec|wmi|winrm).*(connect|login|session)", re.I),
    "data_exfiltration": re.compile(r"(upload|post|send|transfer).*(large|bulk|mass|data)", re.I),
    "malware": re.compile(r"(malware|trojan|backdoor|ransomware|cryptominer|keylog)", re.I),
    "persistence": re.compile(r"(cron|scheduled\s+task|startup|registry\s+key|service\s+install)", re.I),
    "defense_evasion": re.compile(r"(clear\s+log|delete\s+event|disable.*antivirus|obfuscat)", re.I),
}

# Well-known private/internal IP ranges (to filter noise)
_PRIVATE_IP_RE = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)")


class LogAnalysisInput(ToolInput):
    """Log Analysis Tool input."""

    log_content: str = Field(..., description="日志文本内容（直接粘贴或从文件读取）")
    log_type: str = Field(
        default="auto",
        description="日志类型：auto(自动检测), syslog, apache, nginx, windows_event, json, generic",
    )
    max_lines: int = Field(default=5000, ge=10, le=50000, description="最大分析行数")
    extract_iocs: bool = Field(default=True, description="是否提取 IoC（IP/域名/Hash/URL）")


def _auto_detect_type(content: str) -> str:
    """Guess log format from first few lines."""
    head = content[:2000]
    if '"EventID"' in head or "<EventID>" in head:
        return "windows_event"
    if head.lstrip().startswith("{") and any(k in head for k in ('"level"', '"severity"', '"message"')):
        return "json"
    if re.search(r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}", head):
        return "apache"
    if re.search(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", head) and "HTTP" in head:
        return "nginx"
    if re.search(r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\w+", head):
        return "syslog"
    return "generic"


def _extract_iocs_from_lines(lines: list[str]) -> dict[str, list[str]]:
    """Extract unique IOCs from log lines."""
    ips: set[str] = set()
    domains: set[str] = set()
    hashes: set[str] = set()
    urls: set[str] = set()
    emails: set[str] = set()

    for line in lines:
        ips.update(_IP_RE.findall(line))
        hashes.update(_HASH_SHA256.findall(line))
        hashes.update(_HASH_SHA1.findall(line))
        hashes.update(_HASH_MD5.findall(line))
        urls.update(_URL_RE.findall(line))
        emails.update(_EMAIL_RE.findall(line))
        domains.update(_DOMAIN_RE.findall(line))

    # Filter out common non-IOC domains
    noise = {"com", "org", "net", "io", "co", "local", "localhost", "example.com"}
    domains = {d for d in domains if d not in noise and len(d) > 4}
    # Filter private IPs from external IOC list
    external_ips = {ip for ip in ips if not _PRIVATE_IP_RE.match(ip)}

    return {
        "ips_all": sorted(ips)[:100],
        "ips_external": sorted(external_ips)[:50],
        "domains": sorted(domains)[:50],
        "hashes": sorted(hashes)[:30],
        "urls": sorted(urls)[:30],
        "emails": sorted(emails)[:20],
    }


def _detect_suspicious_patterns(lines: list[str]) -> list[dict[str, Any]]:
    """Detect suspicious security patterns in log lines."""
    hits: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        for pattern_name, regex in _SUSPICIOUS.items():
            if regex.search(line):
                hits.append({
                    "pattern": pattern_name,
                    "line_number": i + 1,
                    "evidence": line[:300],
                })
                break  # One hit per line
    return hits


def _analyze_log(content: str, log_type: str, max_lines: int, extract_iocs: bool) -> dict[str, Any]:
    """Core log analysis logic."""
    lines = content.splitlines()
    total_lines = len(lines)
    lines = lines[:max_lines]

    result: dict[str, Any] = {
        "log_type": log_type,
        "total_lines": total_lines,
        "analyzed_lines": len(lines),
        "truncated": total_lines > max_lines,
    }

    # Line frequency analysis
    line_counter: Counter[str] = Counter()
    for line in lines:
        # Normalize: strip timestamps and IDs for grouping
        normalized = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP>", line[:200])
        normalized = re.sub(r"\b[a-fA-F0-9]{32,64}\b", "<HASH>", normalized)
        line_counter[normalized[:120]] += 1

    # Top repeated patterns (likely recurring events)
    result["top_patterns"] = [
        {"pattern": p, "count": c}
        for p, c in line_counter.most_common(15)
        if c >= 3
    ]

    # Suspicious pattern detection
    suspicious = _detect_suspicious_patterns(lines)
    result["suspicious_count"] = len(suspicious)
    result["suspicious_summary"] = {}
    for hit in suspicious:
        name = hit["pattern"]
        result["suspicious_summary"][name] = result["suspicious_summary"].get(name, 0) + 1
    result["suspicious_hits"] = suspicious[:50]  # Cap for context

    # IOC extraction
    if extract_iocs:
        iocs = _extract_iocs_from_lines(lines)
        result["iocs"] = iocs
        result["ioc_summary"] = {
            "unique_ips": len(iocs["ips_all"]),
            "external_ips": len(iocs["ips_external"]),
            "domains": len(iocs["domains"]),
            "hashes": len(iocs["hashes"]),
            "urls": len(iocs["urls"]),
        }

    # Severity assessment
    severity_score = 0
    if result["suspicious_summary"].get("brute_force", 0) > 5:
        severity_score += 3
    if result["suspicious_summary"].get("injection", 0) > 0:
        severity_score += 4
    if result["suspicious_summary"].get("malware", 0) > 0:
        severity_score += 5
    if result["suspicious_summary"].get("data_exfiltration", 0) > 0:
        severity_score += 4
    if result["suspicious_summary"].get("privilege_escalation", 0) > 0:
        severity_score += 4

    if severity_score >= 8:
        result["overall_severity"] = "critical"
    elif severity_score >= 5:
        result["overall_severity"] = "high"
    elif severity_score >= 2:
        result["overall_severity"] = "medium"
    else:
        result["overall_severity"] = "low"
    result["severity_score"] = severity_score

    return result


class LogAnalysisTool:
    """日志分析工具 — 解析安全日志，提取 IoC 和攻击模式。"""

    name = "log_analysis"
    version = "v1"
    input_class = LogAnalysisInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": (
                    "分析安全日志文件（syslog、Apache/Nginx访问日志、Windows事件日志等）。"
                    "自动提取 IoC（IP/域名/Hash/URL）、检测可疑攻击模式"
                    "（暴力破解、注入、提权、横向移动、数据外泄等）、"
                    "统计高频事件模式、评估整体威胁严重等级。"
                    "应急响应场景中的核心分析工具。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "log_content": {
                            "type": "string",
                            "description": "日志文本内容",
                        },
                        "log_type": {
                            "type": "string",
                            "enum": ["auto", "syslog", "apache", "nginx", "windows_event", "json", "generic"],
                            "description": "日志类型，默认自动检测",
                        },
                        "max_lines": {"type": "integer", "description": "最大分析行数"},
                        "extract_iocs": {"type": "boolean", "description": "是否提取 IoC"},
                    },
                    "required": ["log_content"],
                },
            },
        }

    async def execute(self, input_data: LogAnalysisInput) -> ToolResult:
        start = time.monotonic()

        if not input_data.log_content.strip():
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="log_content is empty",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )

        log_type = input_data.log_type
        if log_type == "auto":
            log_type = _auto_detect_type(input_data.log_content)

        try:
            result = _analyze_log(
                input_data.log_content, log_type,
                input_data.max_lines, input_data.extract_iocs,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"Log analysis failed: {e}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )

        elapsed_ms = int((time.monotonic() - start) * 1000)
        confidence = 0.85 if result.get("suspicious_count", 0) > 0 else 0.7

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result,
            error=None,
            confidence=confidence,
            evidence_source=["log_analysis"],
            trace_id=input_data.trace_id,
            execution_time_ms=elapsed_ms,
        )
