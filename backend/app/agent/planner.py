"""Task Planner — multi-step task decomposition and dynamic replanning.

Enables the ReAct Agent to:
1. Decompose complex security tasks into structured execution plans
2. Select appropriate tool chains per step
3. Re-plan dynamically when a step fails or yields low-confidence results
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    REPLANNED = "replanned"


@dataclass
class PlanStep:
    id: int
    description: str
    tool_hint: str
    purpose: str
    status: StepStatus = StepStatus.PENDING
    result_summary: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "description": self.description,
            "tool_hint": self.tool_hint, "purpose": self.purpose,
            "status": self.status.value, "result_summary": self.result_summary,
            "confidence": self.confidence,
        }


@dataclass
class ExecutionPlan:
    goal: str
    steps: list[PlanStep] = field(default_factory=list)
    current_step_index: int = 0
    strategy: str = "default"
    replan_count: int = 0
    max_replans: int = 2
    scenario_type: str = ""

    def current_step(self) -> Optional[PlanStep]:
        if 0 <= self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None

    def advance(self) -> Optional[PlanStep]:
        for i in range(self.current_step_index + 1, len(self.steps)):
            if self.steps[i].status == StepStatus.PENDING:
                self.current_step_index = i
                return self.steps[i]
        return None

    def mark_current_done(self, summary: str, confidence: float) -> None:
        step = self.current_step()
        if step:
            step.status = StepStatus.DONE
            step.result_summary = summary[:500]
            step.confidence = confidence

    def mark_current_failed(self, reason: str) -> None:
        step = self.current_step()
        if step:
            step.status = StepStatus.FAILED
            step.result_summary = reason[:500]

    def is_complete(self) -> bool:
        return all(s.status in (StepStatus.DONE, StepStatus.SKIPPED) for s in self.steps)

    def needs_replan(self) -> bool:
        step = self.current_step()
        if step and step.status == StepStatus.FAILED:
            return True
        if step and step.status == StepStatus.DONE and step.confidence < 0.3:
            return True
        return False

    def get_progress_summary(self) -> str:
        done = sum(1 for s in self.steps if s.status == StepStatus.DONE)
        total = len(self.steps)
        lines = [f"Progress: {done}/{total} steps complete | Strategy: {self.strategy}"]
        for s in self.steps:
            icons = {"pending":"[ ]","running":"[>]","done":"[x]","failed":"[!]","skipped":"[-]","replanned":"[~]"}
            icon = icons.get(s.status.value, "[?]")
            conf = f" (conf: {s.confidence:.0%})" if s.status == StepStatus.DONE and s.confidence > 0 else ""
            lines.append(f"  {icon} Step {s.id}: {s.description} [{s.tool_hint}]{conf}")
            if s.result_summary and s.status in (StepStatus.DONE, StepStatus.FAILED):
                lines.append(f"       -> {s.result_summary[:120]}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal, "strategy": self.strategy,
            "scenario_type": self.scenario_type, "current_step_index": self.current_step_index,
            "replan_count": self.replan_count,
            "steps": [s.to_dict() for s in self.steps],
            "is_complete": self.is_complete(),
            "progress_summary": self.get_progress_summary(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


# -- Scenario detection --

_SCENARIO_KEYWORDS: dict[str, list[str]] = {
    "incident_response": ["应急响应", "安全事件", "告警", "日志分析", "入侵", "失陷", "应急", "处置", "incident"],
    "penetration_test": ["渗透测试", "渗透", "端口扫描", "漏洞扫描", "信息收集", "目录扫描", "pentest", "recon"],
    "vulnerability_research": ["漏洞挖掘", "漏洞分析", "CVE", "0day", "PoC", "exploit", "漏洞利用"],
    "threat_hunting": ["威胁狩猎", "威胁情报", "IoC", "情报", "溯源", "追踪", "hunting"],
    "forensics": ["取证", "逆向", "恶意样本", "病毒", "木马", "样本分析", "forensics", "reverse"],
    "pcap_analysis": ["pcap", "流量分析", "抓包", "网络流量", "数据包"],
    "ctf": ["CTF", "flag", "解题", "密码", "隐写", "crypto", "steganography"],
}


def detect_scenario(user_query: str) -> str:
    query_lower = user_query.lower()
    scores: dict[str, int] = {}
    for scenario, keywords in _SCENARIO_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw.lower() in query_lower)
        if score > 0:
            scores[scenario] = score
    if not scores:
        return "general"
    return max(scores, key=scores.get)  # type: ignore[arg-type]


# -- Tool chains per scenario --

_TOOL_CHAINS: dict[str, list[dict[str, str]]] = {
    "incident_response": [
        {"description": "分析日志中的异常模式和攻击特征", "tool_hint": "log_analysis", "purpose": "提取攻击痕迹和 IoC"},
        {"description": "查询 IoC 威胁情报", "tool_hint": "ioc_lookup", "purpose": "确认 IoC 是否已知威胁"},
        {"description": "分析相关 IP 的威胁评分", "tool_hint": "ip_threat_analysis", "purpose": "评估攻击源威胁等级"},
        {"description": "检索知识库中的处置方案", "tool_hint": "rag_search", "purpose": "获取修复建议和应急措施"},
    ],
    "penetration_test": [
        {"description": "端口扫描和服务发现", "tool_hint": "nmap_scan", "purpose": "发现开放端口和运行服务"},
        {"description": "漏洞扫描", "tool_hint": "vuln_scan", "purpose": "检测已知漏洞"},
        {"description": "Web 目录枚举", "tool_hint": "dir_scan", "purpose": "发现隐藏路径和敏感文件"},
        {"description": "检索漏洞利用信息", "tool_hint": "rag_search", "purpose": "查找漏洞利用方式和修复建议"},
    ],
    "vulnerability_research": [
        {"description": "查询目标 CVE 详细信息", "tool_hint": "cve_lookup", "purpose": "获取漏洞详情和影响范围"},
        {"description": "搜索相关 CVE 和利用代码", "tool_hint": "cve_catalog", "purpose": "发现关联漏洞"},
        {"description": "检索漏洞原理和利用方法", "tool_hint": "rag_search", "purpose": "获取技术细节"},
        {"description": "联网搜索最新利用信息", "tool_hint": "web_search", "purpose": "获取最新的 PoC 和利用信息"},
    ],
    "threat_hunting": [
        {"description": "分析网络流量中的异常", "tool_hint": "pcap_analysis", "purpose": "从流量层发现威胁"},
        {"description": "分析外联 IP 威胁", "tool_hint": "ip_threat_analysis", "purpose": "评估可疑外联地址"},
        {"description": "查询 IoC 情报关联", "tool_hint": "ioc_lookup", "purpose": "关联已知威胁情报"},
        {"description": "关联 CVE 漏洞信息", "tool_hint": "cve_catalog", "purpose": "发现可能被利用的漏洞"},
    ],
    "forensics": [
        {"description": "查询恶意样本哈希信息", "tool_hint": "hash_lookup", "purpose": "确认样本是否已知恶意软件"},
        {"description": "分析样本中的编码/加密", "tool_hint": "encoding_tool", "purpose": "解码混淆内容"},
        {"description": "检索恶意软件家族信息", "tool_hint": "rag_search", "purpose": "获取恶意软件分析报告"},
        {"description": "查询关联 IoC", "tool_hint": "ioc_lookup", "purpose": "发现 C2 和传播链"},
    ],
    "pcap_analysis": [
        {"description": "分析网络流量包", "tool_hint": "pcap_analysis", "purpose": "提取流记录和异常检测"},
        {"description": "分析可疑外联 IP", "tool_hint": "ip_threat_analysis", "purpose": "评估外部 IP 威胁"},
        {"description": "查询域名/IP IoC", "tool_hint": "ioc_lookup", "purpose": "关联威胁情报"},
        {"description": "生成安全分析报告", "tool_hint": "rag_search", "purpose": "检索相关漏洞和处置建议"},
    ],
    "ctf": [
        {"description": "编解码/密码分析", "tool_hint": "encoding_tool", "purpose": "尝试各种编解码方式"},
        {"description": "哈希查询", "tool_hint": "hash_lookup", "purpose": "识别已知文件"},
        {"description": "检索 CTF 题解知识库", "tool_hint": "rag_search", "purpose": "查找类似题型和解法"},
        {"description": "联网搜索相关 CTF writeup", "tool_hint": "web_search", "purpose": "获取解题思路"},
    ],
}


def generate_plan(
    user_query: str,
    available_tools: list[str],
    context_hint: str = "",
) -> ExecutionPlan:
    """Generate an execution plan based on user query and available tools."""
    scenario = detect_scenario(user_query)
    chain = _TOOL_CHAINS.get(scenario, [])

    steps: list[PlanStep] = []
    step_id = 1
    for entry in chain:
        tool = entry["tool_hint"]
        if tool in available_tools:
            steps.append(PlanStep(
                id=step_id, description=entry["description"],
                tool_hint=tool, purpose=entry["purpose"],
            ))
            step_id += 1

    # Always add a final synthesis step
    steps.append(PlanStep(
        id=step_id,
        description="综合分析所有结果，给出结论和建议",
        tool_hint="synthesis",
        purpose="整合信息形成最终回答",
    ))

    plan = ExecutionPlan(
        goal=user_query[:200], steps=steps,
        strategy=scenario, scenario_type=scenario,
    )
    logger.info("Generated plan: scenario=%s, %d steps, tools=%s",
                scenario, len(steps), [s.tool_hint for s in steps])
    return plan


def build_plan_prompt(plan: ExecutionPlan) -> str:
    """Build a system message fragment describing the current plan for the LLM."""
    lines = [
        "## Current Execution Plan",
        f"Goal: {plan.goal}",
        f"Strategy: {plan.strategy}",
        "",
        plan.get_progress_summary(),
        "",
        "Follow the plan steps above. For each step, use the suggested tool. ",
        "If a tool fails or returns low confidence, try an alternative approach. ",
        "When all steps are complete, synthesize results into a final_answer.",
    ]
    return "\n".join(lines)
