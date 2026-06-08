"""Nmap Scan Tool — network port scanning and service detection.

Wraps the nmap CLI (subprocess). Returns structured scan results.
Requires nmap installed on the host system.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
import xml.etree.ElementTree as ET
from typing import Any

from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)


class NmapScanInput(ToolInput):
    """Nmap Scan Tool input."""

    target: str = Field(..., description="扫描目标：IP地址、CIDR网段或主机名，如 192.168.1.1 或 10.0.0.0/24")
    scan_type: str = Field(
        default="quick",
        description="扫描类型：quick(-F 快速扫描), standard(-sV 服务版本), "
                    "aggressive(-A 综合扫描), stealth(-sS SYN半开扫描), udp(-sU UDP扫描)",
    )
    ports: str = Field(default="", description="指定端口范围，如 '80,443' 或 '1-1000'。留空则使用扫描类型默认值")
    timeout: int = Field(default=120, ge=10, le=600, description="扫描超时（秒）")


def _build_nmap_args(input_data: NmapScanInput) -> list[str]:
    """Build nmap command arguments."""
    args = ["nmap", "-oX", "-"]  # XML output to stdout

    scan_type = input_data.scan_type.lower()
    if scan_type == "quick":
        args.extend(["-F", "--top-ports", "100"])
    elif scan_type == "standard":
        args.extend(["-sV", "-sC"])
    elif scan_type == "aggressive":
        args.extend(["-A", "-sV", "-sC", "-O"])
    elif scan_type == "stealth":
        args.extend(["-sS", "-T3"])
    elif scan_type == "udp":
        args.extend(["-sU", "--top-ports", "20"])
    else:
        args.extend(["-F"])

    if input_data.ports:
        args.extend(["-p", input_data.ports])

    args.append(input_data.target)
    return args


def _parse_nmap_xml(xml_output: str) -> dict[str, Any]:
    """Parse nmap XML output into structured data."""
    result: dict[str, Any] = {
        "hosts": [],
        "summary": {},
    }

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        return {"error": f"Failed to parse nmap XML: {e}", "raw_output": xml_output[:2000]}

    run_summary = root.find("runstats")
    if run_summary is not None:
        finished = run_summary.find("finished")
        if finished is not None:
            result["summary"] = {
                "elapsed_seconds": finished.get("elapsed", ""),
                "exit_status": finished.get("exit", ""),
                "total_hosts": run_summary.findtext("hosts", "0"),
                "up_hosts": "",
                "down_hosts": "",
            }
            hosts_el = run_summary.find("hosts")
            if hosts_el is not None:
                result["summary"]["up_hosts"] = hosts_el.get("up", "0")
                result["summary"]["down_hosts"] = hosts_el.get("down", "0")

    for host_el in root.findall("host"):
        host: dict[str, Any] = {"ports": [], "scripts": []}

        # Status
        status = host_el.find("status")
        if status is not None:
            host["state"] = status.get("state", "unknown")
            host["reason"] = status.get("reason", "")

        # Address
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host["ip"] = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                host["mac"] = addr.get("addr", "")

        # Hostname
        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                host["hostname"] = hn.get("name", "")

        # Ports
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_info: dict[str, Any] = {
                    "port": port_el.get("portid", ""),
                    "protocol": port_el.get("protocol", "tcp"),
                }
                state_el = port_el.find("state")
                if state_el is not None:
                    port_info["state"] = state_el.get("state", "")
                    port_info["reason"] = state_el.get("reason", "")
                service_el = port_el.find("service")
                if service_el is not None:
                    port_info["service"] = service_el.get("name", "")
                    port_info["product"] = service_el.get("product", "")
                    port_info["version"] = service_el.get("version", "")
                    port_info["extra_info"] = service_el.get("extrainfo", "")
                host["ports"].append(port_info)

        # OS detection
        os_el = host_el.find("os")
        if os_el is not None:
            os_matches = []
            for osmatch in os_el.findall("osmatch"):
                os_matches.append({
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                })
            host["os_matches"] = os_matches[:3]

        # Script output
        hostscript = host_el.find("hostscript")
        if hostscript is not None:
            for script_el in hostscript.findall("script"):
                host["scripts"].append({
                    "id": script_el.get("id", ""),
                    "output": script_el.get("output", "")[:500],
                })

        result["hosts"].append(host)

    # Stats
    total_open = sum(
        1 for h in result["hosts"] for p in h.get("ports", []) if p.get("state") == "open"
    )
    result["summary"]["open_ports"] = total_open

    return result


class NmapScanTool:
    """网络端口扫描工具 — 调用 nmap 进行端口发现和服务识别。"""

    name = "nmap_scan"
    version = "v1"
    input_class = NmapScanInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": (
                    "使用 nmap 进行网络端口扫描和服务版本检测。"
                    "支持快速扫描、标准扫描、综合扫描、SYN半开扫描、UDP扫描。"
                    "返回开放端口、服务版本、操作系统识别等信息。"
                    "渗透测试信息收集阶段必备工具。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "扫描目标：IP、CIDR网段或主机名",
                        },
                        "scan_type": {
                            "type": "string",
                            "enum": ["quick", "standard", "aggressive", "stealth", "udp"],
                            "description": "扫描类型，默认 quick",
                        },
                        "ports": {
                            "type": "string",
                            "description": "指定端口范围，如 '80,443' 或 '1-1000'",
                        },
                    },
                    "required": ["target"],
                },
            },
        }

    async def execute(self, input_data: NmapScanInput) -> ToolResult:
        start = time.monotonic()

        # Check nmap availability
        if not shutil.which("nmap"):
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="nmap is not installed on the host system. Install it with: apt install nmap / brew install nmap",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )

        args = _build_nmap_args(input_data)
        logger.info("Running nmap: %s", " ".join(args))

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
                error=f"nmap scan timed out after {input_data.timeout}s",
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
                error=f"nmap execution failed: {e}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )

        xml_output = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")[:500]

        if not xml_output.strip():
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={"stderr": stderr_text},
                error="nmap produced no output",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )

        parsed = _parse_nmap_xml(xml_output)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Build concise summary for agent
        hosts_summary = []
        for h in parsed.get("hosts", []):
            open_ports = [p for p in h.get("ports", []) if p.get("state") == "open"]
            hosts_summary.append({
                "ip": h.get("ip", "unknown"),
                "hostname": h.get("hostname", ""),
                "state": h.get("state", ""),
                "open_port_count": len(open_ports),
                "open_ports": open_ports,
                "os_matches": h.get("os_matches", []),
            })

        parsed["hosts_summary"] = hosts_summary
        parsed["target"] = input_data.target
        parsed["scan_type"] = input_data.scan_type

        confidence = 0.9 if parsed.get("hosts") else 0.3

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=parsed,
            error=None,
            confidence=confidence,
            evidence_source=["nmap"],
            trace_id=input_data.trace_id,
            execution_time_ms=elapsed_ms,
        )
