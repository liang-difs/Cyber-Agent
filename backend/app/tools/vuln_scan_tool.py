"""Vulnerability Scan Tool — runs nuclei for vulnerability detection.

Wraps the nuclei CLI. Returns structured vulnerability findings.
Requires nuclei installed on the host system.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
from typing import Any

from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)


class VulnScanInput(ToolInput):
    """Vulnerability Scan Tool input."""

    target: str = Field(..., description="扫描目标 URL 或 IP，如 https://example.com 或 192.168.1.1")
    severity: str = Field(
        default="low,medium,high,critical",
description="过滤严重等级，逗号分隔。可选: info,low,medium,high,critical",
    )
    templates: str = Field(
        default="",
        description="nuclei 模板路径或标签，如 'cves' 或 'misconfig'。留空使用默认模板",
    )
    timeout: int = Field(default=300, ge=30, le=900, description="扫描超时（秒）")


class VulnScanTool:
    """漏洞扫描工具 — 调用 nuclei 进行自动化漏洞检测。"""

    name = "vuln_scan"
    version = "v1"
    input_class = VulnScanInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": (
                    "使用 nuclei 进行自动化漏洞扫描。支持 CVE 检测、安全配置错误检查、"
                    "暴露面检测等。返回发现的漏洞列表及其严重等级、描述和修复建议。"
                    "漏洞挖掘和渗透测试场景使用。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "扫描目标 URL 或 IP",
                        },
                        "severity": {
                            "type": "string",
                            "description": "严重等级过滤，默认 'low,medium,high,critical'",
                        },
                        "templates": {
                            "type": "string",
                            "description": "nuclei 模板路径或标签",
                        },
                    },
                    "required": ["target"],
                },
            },
        }

    async def execute(self, input_data: VulnScanInput) -> ToolResult:
        start = time.monotonic()

        if not shutil.which("nuclei"):
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="nuclei is not installed. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )

        args = [
            "nuclei",
            "-u", input_data.target,
            "-jsonl",
            "-severity", input_data.severity,
            "-silent",
        ]
        if input_data.templates:
            args.extend(["-t", input_data.templates])

        logger.info("Running nuclei: %s", " ".join(args))

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=input_data.timeout,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"nuclei scan timed out after {input_data.timeout}s",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"nuclei execution failed: {e}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )

        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")[:500]

        # Parse JSONL output
        findings: list[dict[str, Any]] = []
        for line in stdout_text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                findings.append({
                    "template_id": item.get("template-id", ""),
                    "name": item.get("info", {}).get("name", ""),
                    "severity": item.get("info", {}).get("severity", ""),
                    "type": item.get("type", ""),
                    "host": item.get("host", ""),
                    "matched_at": item.get("matched-at", ""),
                    "description": item.get("info", {}).get("description", "")[:300],
                    "reference": item.get("info", {}).get("reference", []),
                    "matcher_name": item.get("matcher-name", ""),
                    "extracted": item.get("extracted-results", []),
                })
            except json.JSONDecodeError:
                continue

        # Summary by severity
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        elapsed_ms = int((time.monotonic() - start) * 1000)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data={
                "target": input_data.target,
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "findings": findings[:50],  # Cap to avoid context overflow
                "nuclei_stderr": stderr_text if stderr_text else None,
            },
            error=None,
            confidence=0.85 if findings else 0.7,
            evidence_source=["nuclei"],
            trace_id=input_data.trace_id,
            execution_time_ms=elapsed_ms,
        )
