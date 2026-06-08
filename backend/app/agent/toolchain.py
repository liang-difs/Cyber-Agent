"""Tool Chain Templates — predefined multi-tool orchestration for common scenarios.

When the Agent detects a matching scenario, it can automatically execute
a chain of tools in sequence, passing results between steps.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ToolChainStep:
    """A single step in a tool chain."""

    def __init__(
        self,
        tool_name: str,
        description: str,
        input_builder: Optional[dict[str, Any]] = None,
        depends_on_step: Optional[int] = None,
        optional: bool = False,
    ):
        self.tool_name = tool_name
        self.description = description
        self.input_builder = input_builder or {}
        self.depends_on_step = depends_on_step
        self.optional = optional

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "description": self.description,
            "depends_on_step": self.depends_on_step,
            "optional": self.optional,
        }


class ToolChain:
    """A named sequence of tools to execute for a specific scenario."""

    def __init__(
        self,
        name: str,
        description: str,
        steps: list[ToolChainStep],
        auto_chain: bool = True,
    ):
        self.name = name
        self.description = description
        self.steps = steps
        self.auto_chain = auto_chain

    def get_tools_needed(self) -> list[str]:
        return list(dict.fromkeys(s.tool_name for s in self.steps))

    def filter_by_available(self, available: set[str]) -> "ToolChain":
        """Return a copy with only steps whose tools are available."""
        filtered = [
            s for s in self.steps
            if s.tool_name in available or s.tool_name == "synthesis"
        ]
        return ToolChain(self.name, self.description, filtered, self.auto_chain)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "auto_chain": self.auto_chain,
            "steps": [s.to_dict() for s in self.steps],
            "tools_needed": self.get_tools_needed(),
        }


# ── Predefined tool chains ────────────────────────────────────────

TOOL_CHAINS: dict[str, ToolChain] = {
    "incident_response": ToolChain(
        name="incident_response",
        description="应急响应标准流程：日志分析 -> IoC关联 -> IP威胁评估 -> 处置建议",
        steps=[
            ToolChainStep("log_analysis", "分析日志中的异常模式和攻击特征"),
            ToolChainStep("ioc_lookup", "查询 IoC 威胁情报", depends_on_step=0),
            ToolChainStep("ip_threat_analysis", "分析相关 IP 威胁评分", depends_on_step=0),
            ToolChainStep("rag_search", "检索知识库中的处置方案"),
        ],
    ),
    "penetration_recon": ToolChain(
        name="penetration_recon",
        description="渗透测试信息收集：端口扫描 -> 漏洞扫描 -> 目录枚举 -> 利用建议",
        steps=[
            ToolChainStep("nmap_scan", "端口扫描和服务发现"),
            ToolChainStep("vuln_scan", "漏洞扫描", depends_on_step=0),
            ToolChainStep("dir_scan", "Web目录枚举", optional=True),
            ToolChainStep("rag_search", "检索漏洞利用方式和修复建议"),
        ],
    ),
    "threat_hunting": ToolChain(
        name="threat_hunting",
        description="威胁狩猎：流量分析 -> IP情报 -> IoC关联 -> CVE关联",
        steps=[
            ToolChainStep("pcap_analysis", "分析网络流量中的异常"),
            ToolChainStep("ip_threat_analysis", "分析外联 IP 威胁", depends_on_step=0),
            ToolChainStep("ioc_lookup", "查询 IoC 情报关联", depends_on_step=0),
            ToolChainStep("cve_catalog", "关联 CVE 漏洞信息"),
        ],
    ),
    "forensics": ToolChain(
        name="forensics",
        description="数字取证：Hash查询 -> 编码分析 -> 恶意软件情报 -> IoC关联",
        steps=[
            ToolChainStep("hash_lookup", "查询恶意样本哈希信息"),
            ToolChainStep("encoding_tool", "分析编码/加密内容", optional=True),
            ToolChainStep("rag_search", "检索恶意软件家族信息"),
            ToolChainStep("ioc_lookup", "查询关联 IoC", depends_on_step=0),
        ],
    ),
    "pcap_deep_analysis": ToolChain(
        name="pcap_deep_analysis",
        description="深度流量分析：PCAP解析 -> IP威胁 -> IoC情报 -> 报告",
        steps=[
            ToolChainStep("pcap_analysis", "分析网络流量包"),
            ToolChainStep("ip_threat_analysis", "分析可疑外联 IP", depends_on_step=0),
            ToolChainStep("ioc_lookup", "查询域名/IP IoC", depends_on_step=0),
            ToolChainStep("rag_search", "检索相关漏洞和处置建议"),
        ],
    ),
    "ctf_analysis": ToolChain(
        name="ctf_analysis",
        description="CTF解题辅助：编解码 -> Hash识别 -> 知识库检索 -> 联网搜索",
        steps=[
            ToolChainStep("encoding_tool", "尝试各种编解码方式"),
            ToolChainStep("hash_lookup", "识别已知文件", optional=True),
            ToolChainStep("rag_search", "检索 CTF 题解知识库"),
            ToolChainStep("web_search", "搜索相关 CTF writeup"),
        ],
    ),
}


def match_chain(user_query: str, available_tools: set[str]) -> Optional[ToolChain]:
    """Match user query to a tool chain and filter to available tools."""
    query_lower = user_query.lower()

    # Keyword-based matching
    chain_keywords: dict[str, list[str]] = {
        "incident_response": ["应急", "安全事件", "告警处置", "入侵", "失陷", "incident", "响应"],
        "penetration_recon": ["渗透", "扫描", "信息收集", "pentest", "recon", "端口扫描"],
        "threat_hunting": ["威胁狩猎", "威胁情报", "hunting", "狩猎"],
        "forensics": ["取证", "逆向", "恶意样本", "样本分析", "forensics"],
        "pcap_deep_analysis": ["pcap", "流量分析", "抓包", "数据包", "pcapng"],
        "ctf_analysis": ["ctf", "flag", "解题", "密码学", "crypto"],
    }

    best_chain: Optional[str] = None
    best_score = 0
    for chain_name, keywords in chain_keywords.items():
        score = sum(1 for kw in keywords if kw in query_lower)
        if score > best_score:
            best_score = score
            best_chain = chain_name

    if not best_chain or best_score == 0:
        return None

    chain = TOOL_CHAINS.get(best_chain)
    if not chain:
        return None

    filtered = chain.filter_by_available(available_tools)
    if len(filtered.steps) < 2:
        return None  # Not enough tools available

    logger.info("Matched tool chain '%s' (%d/%d tools available)",
                best_chain, len(filtered.steps), len(chain.steps))
    return filtered
