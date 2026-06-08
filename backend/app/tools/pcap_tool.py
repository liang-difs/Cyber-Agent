"""
PCAP Analysis Tool — 分析 pcap/pcapng 文件中的网络流量。

在 Agent 对话中调用，执行流量分析并返回结构化结果。
结果包含 external_ips_for_lookup 和 domains_for_lookup，供 Agent 自动串联 IP/IoC 查询。
"""

import os
import time
import hashlib
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.governance.tool_protocol import ToolInput, ToolResult


PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Allowed base directories for pcap file access
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_BACKEND_DATA = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
_ALLOWED_DIRS = [
    os.path.join(_PROJECT_ROOT, "data"),
    _BACKEND_DATA,
    "/tmp",
]


def _validate_pcap_path(pcap_path: str) -> Optional[str]:
    """Validate that pcap_path is within allowed directories.

    Returns None if valid, or an error message string if invalid.
    """
    try:
        resolved = os.path.realpath(os.path.abspath(pcap_path))
    except (ValueError, OSError) as e:
        return f"无效路径: {e}"

    for allowed in _ALLOWED_DIRS:
        if resolved.startswith(os.path.abspath(allowed) + os.sep) or resolved == os.path.abspath(allowed):
            return None

    return f"路径不在允许的目录范围内: {pcap_path}"


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class PcapToolInput(ToolInput):
    """PCAP 分析工具输入"""

    pcap_path: str = Field(..., description="pcap/pcapng 文件的服务器路径")
    max_packets: int = Field(default=10000, description="最大解析包数")
    display_filename: Optional[str] = Field(default=None, description="用户选择的原始文件名")


class PcapTool:
    """分析 pcap 文件中的网络流量，检测异常行为"""

    name = "pcap_analysis"
    version = "v1"
    input_class = PcapToolInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "pcap_analysis",
                "description": (
                    "分析 pcap/pcapng 网络流量文件。"
                    "返回 Flow 流记录、协议分布、DNS 深度分析、时间线、异常检测等结构化数据。"
                    "可用于网络安全分析、威胁检测、流量取证。"
                    "\n\n分析完成后，建议按以下顺序串联其他工具："
                    "1. 使用返回的 external_ips_for_lookup 调用 ip_threat_analysis 检查外部 IP 信誉"
                    "2. 使用返回的 domains_for_lookup 调用 ioc_lookup 检查域名信誉"
                    "3. 检测到的异常已自动写入告警系统，用户可要求生成安全事件报告"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pcap_path": {
                            "type": "string",
                            "description": "pcap/pcapng 文件的服务器路径",
                        },
                        "display_filename": {
                            "type": "string",
                            "description": "用户选择的原始文件名（建议传入，用于报告展示）",
                        },
                        "max_packets": {
                            "type": "integer",
                            "description": "最大解析包数，默认 10000",
                        },
                    },
                    "required": ["pcap_path"],
                },
            },
        }

    async def execute(self, input_data: PcapToolInput) -> ToolResult:
        start = time.time()

        # Validate path is within allowed directories
        path_error = _validate_pcap_path(input_data.pcap_path)
        if path_error:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=path_error,
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Validate file exists
        if not os.path.exists(input_data.pcap_path):
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"文件不存在: {input_data.pcap_path}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Validate magic bytes
        try:
            with open(input_data.pcap_path, "rb") as f:
                header = f.read(4)
            if header not in (PCAP_MAGIC, PCAPNG_MAGIC):
                return ToolResult(
                    success=False,
                    tool_name=self.name,
                    tool_version=self.version,
                    data={},
                    error="无效的 pcap 文件（magic bytes 不匹配）",
                    confidence=0.0,
                    evidence_source=[],
                    trace_id=input_data.trace_id,
                    execution_time_ms=int((time.time() - start) * 1000),
                )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"读取文件失败: {e}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Run analysis
        try:
            from app.tasks.pcap_analysis import analyze_pcap
            result = analyze_pcap(
                pcap_path=input_data.pcap_path,
                tenant_id=input_data.tenant_id,
                max_packets=input_data.max_packets,
            )
            result["pcap_path"] = input_data.pcap_path
            result["source_path"] = input_data.pcap_path
            original_name = input_data.display_filename or os.path.basename(input_data.pcap_path)
            result["display_filename"] = original_name
            result["pcap_identity"] = {
                "display_filename": original_name,
                "original_filename": input_data.display_filename or original_name,
                "source_path": input_data.pcap_path,
                "sha256": None,
            }
            result["sha256"] = _sha256_file(input_data.pcap_path)
            result["pcap_identity"]["sha256"] = result["sha256"]
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"分析执行失败: {e}",
                confidence=0.0,
                evidence_source=["pcap_analysis_task"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Enrich anomalies with IP reputation data
        anomalies = result.get("anomalies", [])
        if anomalies:
            ip_rep_map = await self._query_ip_reputations(anomalies)
            if ip_rep_map:
                from app.tasks.pcap_analysis import _build_pcap_alert_fields
                for a in anomalies:
                    src = a.get("src_ip", "")
                    rep = ip_rep_map.get(src)
                    if rep is not None:
                        triage = _build_pcap_alert_fields(a, ip_reputation=rep)
                        a["confidence"] = triage["confidence"]
                        a["verdict"] = triage["verdict"]

        execution_time_ms = int((time.time() - start) * 1000)

        if not result.get("success"):
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data=result,
                error=result.get("error", "分析失败"),
                confidence=0.0,
                evidence_source=["pcap_analysis_task"],
                trace_id=input_data.trace_id,
                execution_time_ms=execution_time_ms,
            )

        # Build summary for Agent
        summary = result.get("summary", {})
        anomaly_count = summary.get("anomaly_count", len(result.get("anomalies", [])))
        total_packets = summary.get("total_packets", 0)
        total_flows = summary.get("total_flows", 0)

        duration_s = summary.get("duration_s", 0)
        display_filename = result.get("display_filename") or input_data.display_filename or os.path.basename(input_data.pcap_path)
        summary_parts = [
            f"分析文件: {display_filename}；源路径: {input_data.pcap_path}",
            f"共解析 {total_packets} 个数据包，{total_flows} 条流记录，持续时间 {duration_s} 秒",
        ]

        time_basis = summary.get("time_basis", "unknown")
        summary_parts.append(f"时间基准: {time_basis}")
        if time_basis == "relative":
            summary_parts.append("时间仅表示抓包内先后顺序，不可写成绝对日期或外部日历时间")
        elif summary.get("start_time") and summary.get("end_time"):
            summary_parts.append(f"绝对时间范围: {summary.get('start_time')} → {summary.get('end_time')}")
        summary_parts.append("结论必须区分已确认事实与推断；未见直接证据时只能写疑似/可能/不能排除")

        top_protos = summary.get("top_protocols", [])
        if top_protos:
            proto_str = ", ".join(f"{p['protocol']}({p['count']})" for p in top_protos[:5])
            summary_parts.append(f"协议分布: {proto_str}")

        if anomaly_count > 0:
            summary_parts.append(f"检测到 {anomaly_count} 个异常（必须在回复中逐条列出）:")
            for a in result.get("anomalies", []):
                sev = a.get("severity", "medium").upper()
                atype = a.get("type", "unknown")
                detail = a.get("detail", "")
                src = a.get("src_ip", "")
                dst = a.get("dst_ip", "")
                loc = f" [{src}→{dst}]" if src and dst else ""
                summary_parts.append(f"  - [{sev}] {atype}{loc}: {detail}")
        else:
            summary_parts.append("未检测到异常")

        ext_ips = result.get("external_ips_for_lookup", [])
        if ext_ips:
            summary_parts.append(f"外部 IP（可查询信誉）: {', '.join(ext_ips[:5])}")

        domains = result.get("domains_for_lookup", [])
        if domains:
            summary_parts.append(f"域名（可查询 IoC）: {', '.join(domains[:5])}")

        result["summary_text"] = "；".join(summary_parts)

        # Attach structured evidence entry for the pcap analysis
        evidence_rows = [
            {
                "source_type": "pcap",
                "source_path": input_data.pcap_path,
                "doc_id": f"pcap:{result.get('sha256', '')}",
                "key_dates": {
                    "start_time": result.get("start_time", summary.get("start_time")),
                    "end_time": result.get("end_time", summary.get("end_time")),
                },
                "note": "pcap analysis summary",
            }
        ]
        result["evidence"] = evidence_rows

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result,
            error=None,
            confidence=0.9 if anomaly_count == 0 else 0.7,
            evidence_source=["tshark_pcap_analysis"],
            trace_id=input_data.trace_id,
            execution_time_ms=execution_time_ms,
        )

    async def _query_ip_reputations(self, anomalies: list[dict]) -> dict[str, int]:
        """Query AbuseIPDB for unique source IPs in anomalies. Returns {ip: score}."""
        import asyncio
        ips = list({a["src_ip"] for a in anomalies if a.get("src_ip")})
        if not ips:
            return {}

        settings = get_settings()
        if not settings.abuseipdb_api_key:
            return {}

        # Limit to top 5 IPs to avoid rate limits
        ips = ips[:5]
        results: dict[str, int] = {}

        async def _query_one(ip: str):
            try:
                from app.tools.ip_tool import IPThreatTool
                tool = IPThreatTool()
                from app.tools.ip_tool import IPThreatInput
                import uuid
                inp = IPThreatInput(ip=ip, trace_id=str(uuid.uuid4()), tenant_id="pcap")
                r = await tool.execute(inp)
                if r.success and r.data:
                    abuse = r.data.get("abuse", {})
                    results[ip] = abuse.get("abuse_confidence_score", 0)
            except Exception:
                pass

        await asyncio.gather(*[_query_one(ip) for ip in ips])
        return results


pcap_tool = PcapTool()
