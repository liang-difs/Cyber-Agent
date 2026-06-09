"""Investigation Planner Tool — tiered investigation planning with budget control.

分级调查规划引擎：Mini Planner (2-4步) / Full Planner (6-15步)。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)

# ── 调查预算 ──────────────────────────────────────────────

BUDGET = {
    "mini": {"max_steps": 4, "max_time": 60, "max_tools": 4},
    "full": {"max_steps": 12, "max_time": 120, "max_tools": 10},
}

# ── Mini Planner 模板（2-4 步，简单查询） ─────────────────

MINI_TEMPLATES: dict[str, dict[str, Any]] = {
    "domain_quick": {
        "description": "域名快速查询：威胁情报 + 搜索",
        "steps": [
            {"step": 1, "tool": "ioc_lookup", "action": "查询威胁情报", "required": True},
            {"step": 2, "tool": "web_search", "action": "搜索安全事件", "required": True},
        ],
        "conditional": {"rag_after": "ioc_lookup"},  # 有结果才查 RAG
    },
    "ip_quick": {
        "description": "IP 快速查询：地理位置 + 信誉",
        "steps": [
            {"step": 1, "tool": "ip_threat_analysis", "action": "地理位置 + 信誉评分", "required": True},
            {"step": 2, "tool": "ioc_lookup", "action": "多源情报", "required": True},
        ],
        "conditional": {"rag_after": "ioc_lookup"},
    },
    "hash_quick": {
        "description": "Hash 快速查询：检测率 + 恶意软件家族",
        "steps": [
            {"step": 1, "tool": "hash_lookup", "action": "VT + MalwareBazaar", "required": True},
        ],
        "conditional": {"rag_after": "hash_lookup"},
    },
    "cve_quick": {
        "description": "CVE 快速查询：详情 + 影响",
        "steps": [
            {"step": 1, "tool": "cve_lookup", "action": "CVE 详情", "required": True},
            {"step": 2, "tool": "rag_search", "action": "知识库关联", "required": False},
        ],
    },
}

# ── Full Planner 模板（6-12 步，深度调查） ────────────────

FULL_TEMPLATES: dict[str, dict[str, Any]] = {
    "domain_investigation": {
        "description": "域名深度调查：威胁情报 + WHOIS + DNS + SSL + 安全事件 + 知识图谱",
        "steps": [
            {"step": 1, "tool": "ioc_lookup", "action": "查询威胁情报（VT/OTX）", "required": True},
            {"step": 2, "tool": "whois_lookup", "action": "查询 WHOIS 注册信息（注册商/注册时间/过期时间）", "required": True},
            {"step": 3, "tool": "dns_lookup", "action": "查询 DNS 记录（A/MX/NS/TXT）", "required": True},
            {"step": 4, "tool": "ssl_lookup", "action": "查询 SSL 证书（颁发者/有效期/SAN）", "required": True},
            {"step": 5, "tool": "web_search", "action": "搜索域名关联的安全事件", "required": False},
            {"step": 6, "tool": "knowledge_graph", "action": "查询知识图谱关联实体", "required": False},
            {"step": 7, "tool": "synthesis", "action": "综合证据生成结论", "required": True},
        ],
        "conditional": {"rag_after": "ioc_lookup"},
        "verification": {"check_missing": ["whois", "dns", "ssl"]},
    },
    "alert_investigation": {
        "description": "告警研判：行为链解析 → IoC 提取 → 逐个调查 → ATT&CK 映射 → 处置建议",
        "steps": [
            {"step": 1, "tool": "log_analysis", "action": "解析告警日志，提取行为链和 IoC", "required": True},
            {"step": 2, "tool": "ioc_lookup", "action": "批量查询提取的 IoC", "required": True, "depends_on": 1},
            {"step": 3, "tool": "threat_intel", "action": "深度情报查询关键 IP", "required": False, "depends_on": 2},
            {"step": 4, "tool": "knowledge_graph", "action": "查询关联的 ATT&CK 技术", "required": False},
            {"step": 5, "tool": "rag_search", "action": "查询类似攻击案例", "required": False, "conditional": True},
            {"step": 6, "tool": "synthesis", "action": "综合证据生成研判报告", "required": True},
        ],
        "budget": BUDGET["full"],
    },
    "pcap_investigation": {
        "description": "PCAP 流量分析：协议解析 → 异常检测 → IoC 提取 → 威胁情报 → 攻击链",
        "steps": [
            {"step": 1, "tool": "pcap_analysis", "action": "解析流量包", "required": True},
            {"step": 2, "tool": "ip_threat_analysis", "action": "分析外部 IP", "required": True, "depends_on": 1},
            {"step": 3, "tool": "ioc_lookup", "action": "查询提取的 IoC", "required": True, "depends_on": 1},
            {"step": 4, "tool": "threat_intel", "action": "深度情报关键 IP", "required": False, "depends_on": 2},
            {"step": 5, "tool": "knowledge_graph", "action": "查询 ATT&CK 关联", "required": False},
            {"step": 6, "tool": "synthesis", "action": "生成流量分析报告", "required": True},
        ],
        "budget": BUDGET["full"],
    },
    "ioc_correlation": {
        "description": "多 IoC 关联分析：批量查询 → 交叉关联 → 攻击活动判定",
        "steps": [
            {"step": 1, "tool": "ioc_lookup", "action": "批量查询所有 IoC", "required": True},
            {"step": 2, "tool": "threat_intel", "action": "深度情报关键指标", "required": False, "depends_on": 1},
            {"step": 3, "tool": "knowledge_graph", "action": "查询实体关联", "required": True},
            {"step": 4, "tool": "synthesis", "action": "关联分析结论", "required": True},
        ],
        "budget": BUDGET["mini"],
    },
    "incident_response": {
        "description": "事件响应：态势评估 → IoC 提取 → 情报查询 → 影响评估 → 处置建议",
        "steps": [
            {"step": 1, "tool": "log_analysis", "action": "分析日志提取 IoC", "required": True},
            {"step": 2, "tool": "ioc_lookup", "action": "批量查询 IoC", "required": True, "depends_on": 1},
            {"step": 3, "tool": "threat_intel", "action": "深度情报", "required": False, "depends_on": 2},
            {"step": 4, "tool": "knowledge_graph", "action": "ATT&CK 关联", "required": False},
            {"step": 5, "tool": "response_action", "action": "自动响应建议", "required": False, "depends_on": 2},
            {"step": 6, "tool": "synthesis", "action": "生成事件报告", "required": True},
        ],
        "budget": BUDGET["full"],
    },
}

# ── 目标类型推断 ──────────────────────────────────────────


def _infer_target_type(target: str, context: str = "") -> str:
    import re
    target = target.strip()
    combined = f"{target} {context}".lower()

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32,64}$", target):
        return "hash"
    if re.match(r"^CVE-\d{4}-\d+$", target, re.I):
        return "cve"
    if target.endswith((".pcap", ".pcapng")):
        return "pcap"
    if any(kw in combined for kw in ["告警", "alert", "incident", "入侵", "失陷", "powershell", "certutil"]):
        return "alert"
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", target):
        return "domain"
    if any(kw in combined for kw in ["关联", "correlat", "多个", "批量"]):
        return "ioc_correlation"
    return "domain"


def _should_use_full_planner(target_type: str, context: str) -> bool:
    """判断是否需要 Full Planner（复杂调查）"""
    full_planner_types = {"domain_investigation", "alert", "pcap", "incident_response", "ioc_correlation"}
    if target_type in full_planner_types:
        return True
    # 告警研判上下文复杂时也用 Full
    if target_type == "alert" or any(kw in context.lower() for kw in ["攻击链", "进程链", "powershell", "certutil"]):
        return True
    return False


# ── 工具定义 ──────────────────────────────────────────────


class PlannerInput(ToolInput):
    """Planner Tool input."""

    target: str = Field(..., description="调查目标：域名、IP、哈希、CVE 编号或告警描述")
    target_type: str = Field(default="auto", description="目标类型：auto/domain/ip/hash/cve/alert/pcap/ioc_correlation")
    context: str = Field(default="", description="补充上下文：告警内容、攻击描述等")
    planner_level: str = Field(default="auto", description="规划级别：auto/mini/full")


class PlannerTool:
    """分级调查规划引擎"""

    name = "planner"
    version = "v1"
    input_class = PlannerInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "planner",
                "description": (
                    "调查规划引擎：根据目标类型自动生成分级调查计划。"
                    "Mini Planner (2-4步) 用于简单查询，Full Planner (6-12步) 用于复杂调查。"
                    "支持条件执行（有 IoC 才查 RAG）和调查预算控制。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "调查目标"},
                        "target_type": {
                            "type": "string",
                            "enum": ["auto", "domain", "ip", "hash", "cve", "alert", "pcap", "ioc_correlation"],
                            "description": "目标类型",
                        },
                        "context": {"type": "string", "description": "补充上下文"},
                        "planner_level": {
                            "type": "string",
                            "enum": ["auto", "mini", "full"],
                            "description": "规划级别",
                        },
                    },
                    "required": ["target"],
                },
            },
        }

    async def execute(self, input_data: PlannerInput) -> ToolResult:
        start = time.time()

        target = input_data.target.strip()
        target_type = input_data.target_type
        context = input_data.context
        level = input_data.planner_level

        if target_type == "auto":
            target_type = _infer_target_type(target, context)

        if level == "auto":
            level = "full" if _should_use_full_planner(target_type, context) else "mini"

        # 选择模板
        if level == "mini":
            template_key = f"{target_type}_quick" if f"{target_type}_quick" in MINI_TEMPLATES else "domain_quick"
            template = MINI_TEMPLATES.get(template_key, MINI_TEMPLATES["domain_quick"])
            budget = BUDGET["mini"]
        else:
            template_key = f"{target_type}_investigation" if f"{target_type}_investigation" in FULL_TEMPLATES else target_type
            template = FULL_TEMPLATES.get(template_key, FULL_TEMPLATES.get("domain_investigation"))
            budget = BUDGET["full"]

        # 生成计划
        steps = []
        for step in template["steps"]:
            step_info = {
                "step": step["step"],
                "tool": step["tool"],
                "action": step["action"],
                "required": step.get("required", True),
                "status": "pending",
            }
            if "depends_on" in step:
                step_info["depends_on"] = step["depends_on"]

            # 注入目标到参数
            if target_type in ("domain", "ip", "hash"):
                step_info["params"] = {"query": target}
            elif target_type == "cve":
                step_info["params"] = {"cve_id": target}
            else:
                step_info["params"] = {}

            steps.append(step_info)

        plan = {
            "target": target,
            "target_type": target_type,
            "planner_level": level,
            "description": template["description"],
            "budget": budget,
            "total_steps": len(steps),
            "steps": steps,
            "conditional": template.get("conditional", {}),
            "verification": template.get("verification", {}),
            "instructions": (
                f"请按计划逐步执行。每步结果作为证据编号（E1, E2...）。"
                f"非必需步骤（required: false）可在前置步骤无结果时跳过。"
                f"条件步骤（conditional）仅在前置工具有结果时执行。"
                f"最后一步必须综合所有证据生成结论，引用证据编号。"
            ),
        }

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=plan,
            confidence=1.0,
            evidence_source=["planner"],
            trace_id=input_data.trace_id,
            execution_time_ms=int((time.time() - start) * 1000),
        )


planner_tool = PlannerTool()
