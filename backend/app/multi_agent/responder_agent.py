"""Responder Agent — Generates final responses and reports.

响应Agent：生成最终响应、报告和建议。
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.multi_agent.base_agent import BaseAgent
from app.multi_agent.protocol import (
    AgentRole,
    TaskRequest,
    TaskResult,
)

logger = logging.getLogger(__name__)


class ResponderAgent(BaseAgent):
    """响应Agent — 负责生成最终响应和报告"""

    def __init__(
        self,
        agent_id: str = "responder",
        llm_router: Any = None,
        tool_registry: Any = None,
    ):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.RESPONDER,
            llm_router=llm_router,
            tool_registry=tool_registry,
            capabilities=[
                "report_generation",
                "response_formatting",
                "recommendation_generation",
                "executive_summary",
            ],
        )

    async def execute_task(self, task: TaskRequest) -> TaskResult:
        """执行响应任务"""
        try:
            action = task.task_type
            parameters = task.parameters

            # 根据动作类型分发
            handler = self._get_handler(action)
            if handler:
                result = await handler(parameters)
            else:
                result = await self._generic_response(task)

            return TaskResult(
                task_id=task.task_id,
                success=True,
                result=result,
                agent_id=self.agent_id,
            )

        except Exception as e:
            logger.error("Responder task failed: %s", e)
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e),
                agent_id=self.agent_id,
            )

    def _get_handler(self, action: str):
        """获取动作处理器"""
        handlers = {
            "generate_report": self._generate_report,
            "generate_assessment_report": self._generate_assessment_report,
            "generate_incident_report": self._generate_incident_report,
            "generate_hunting_report": self._generate_hunting_report,
            "generate_malware_report": self._generate_malware_report,
            "generate_vuln_report": self._generate_vuln_report,
            "generate_pentest_report": self._generate_pentest_report,
            "generate_response": self._generic_response,
        }
        return handlers.get(action)

    async def _generate_report(self, params: dict[str, Any]) -> dict[str, Any]:
        """生成通用报告"""
        report_format = params.get("format", "markdown")
        data = params.get("data", {})
        title = params.get("title", "安全分析报告")

        report_content = self._format_report(title, data, report_format)

        return {
            "report_type": "general",
            "format": report_format,
            "content": report_content,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _generate_assessment_report(self, params: dict[str, Any]) -> dict[str, Any]:
        """生成安全评估报告"""
        assessment_data = params.get("assessment", {})
        target = params.get("target", "未知目标")

        report = f"""# 安全评估报告

## 目标
{target}

## 评估时间
{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

## 发现摘要

### 资产发现
- 发现资产数量: {assessment_data.get('asset_count', 'N/A')}

### 漏洞发现
- 关键漏洞: {assessment_data.get('critical_vulns', 0)}
- 高危漏洞: {assessment_data.get('high_vulns', 0)}
- 中危漏洞: {assessment_data.get('medium_vulns', 0)}
- 低危漏洞: {assessment_data.get('low_vulns', 0)}

### 风险评估
- 整体风险等级: {assessment_data.get('risk_level', 'N/A')}
- 风险分数: {assessment_data.get('risk_score', 'N/A')}

## 详细发现

{self._format_findings(assessment_data.get('findings', []))}

## 修复建议

{self._format_recommendations(assessment_data.get('recommendations', []))}

## 结论

{assessment_data.get('conclusion', '评估完成，请查看详细发现。')}
"""

        return {
            "report_type": "security_assessment",
            "format": "markdown",
            "content": report,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _generate_incident_report(self, params: dict[str, Any]) -> dict[str, Any]:
        """生成应急响应报告"""
        incident_data = params.get("incident", {})
        timeline = params.get("timeline", [])
        actions_taken = params.get("actions_taken", [])

        report = f"""# 安全事件响应报告

## 事件概要
- 事件ID: {incident_data.get('id', 'N/A')}
- 事件类型: {incident_data.get('type', 'N/A')}
- 发现时间: {incident_data.get('discovered_at', 'N/A')}
- 响应时间: {incident_data.get('response_time', 'N/A')}
- 当前状态: {incident_data.get('status', 'N/A')}

## 事件时间线

{self._format_timeline(timeline)}

## 影响分析

### 受影响资产
{self._format_affected_assets(incident_data.get('affected_assets', []))}

### 影响范围
- 业务影响: {incident_data.get('business_impact', 'N/A')}
- 数据影响: {incident_data.get('data_impact', 'N/A')}

## 响应行动

{self._format_actions(actions_taken)}

## 根因分析

{incident_data.get('root_cause', '待分析')}

## 修复措施

{self._format_recommendations(incident_data.get('remediation', []))}

## 经验教训

{self._format_lessons_learned(incident_data.get('lessons', []))}

## 附录

### IoC列表
{self._format_iocs(incident_data.get('iocs', []))}

### 参考资料
{self._format_references(incident_data.get('references', []))}
"""

        return {
            "report_type": "incident_response",
            "format": "markdown",
            "content": report,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _generate_hunting_report(self, params: dict[str, Any]) -> dict[str, Any]:
        """生成威胁狩猎报告"""
        hypothesis = params.get("hypothesis", "")
        findings = params.get("findings", [])
        validated = params.get("validated_findings", [])

        report = f"""# 威胁狩猎报告

## 狩猎假设
{hypothesis}

## 执行时间
{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

## 数据源
{self._format_data_sources(params.get('data_sources', []))}

## 发现摘要

### 总体发现
- 检测到的模式: {len(findings)}
- 已验证的发现: {len(validated)}

### 威胁指标
{self._format_hunting_findings(validated)}

## 详细分析

{self._format_hunting_analysis(params.get('analysis', {}))}

## 推荐行动

{self._format_recommendations(params.get('recommendations', []))}

## 后续狩猎建议

{self._format_next_steps(params.get('next_steps', []))}
"""

        return {
            "report_type": "threat_hunting",
            "format": "markdown",
            "content": report,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _generate_malware_report(self, params: dict[str, Any]) -> dict[str, Any]:
        """生成恶意软件分析报告"""
        malware_info = params.get("malware_info", {})
        analysis_results = params.get("analysis_results", {})

        report = f"""# 恶意软件分析报告

## 样本信息
- 文件名: {malware_info.get('filename', 'N/A')}
- 文件类型: {malware_info.get('file_type', 'N/A')}
- 文件大小: {malware_info.get('file_size', 'N/A')}
- MD5: {malware_info.get('md5', 'N/A')}
- SHA1: {malware_info.get('sha1', 'N/A')}
- SHA256: {malware_info.get('sha256', 'N/A')}

## 静态分析

### 文件头
{self._format_file_header(analysis_results.get('header', {}))}

### 字符串
{self._format_strings(analysis_results.get('strings', []))}

### 导入函数
{self._format_imports(analysis_results.get('imports', []))}

## 动态分析

### 行为特征
{self._format_behaviors(analysis_results.get('behaviors', []))}

### 网络通信
{self._format_network_activity(analysis_results.get('network', []))}

### 文件系统操作
{self._format_file_operations(analysis_results.get('file_ops', []))}

## 威胁情报

{self._format_threat_intel(params.get('threat_intel', {}))}

## 恶意软件家族

{malware_info.get('family', '未知')}

## 危害等级

{malware_info.get('severity', 'N/A')}

## 清除建议

{self._format_recommendations(params.get('remediation', []))}
"""

        return {
            "report_type": "malware_analysis",
            "format": "markdown",
            "content": report,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _generate_vuln_report(self, params: dict[str, Any]) -> dict[str, Any]:
        """生成漏洞评估报告"""
        target = params.get("target", "")
        vulnerabilities = params.get("vulnerabilities", [])

        report = f"""# 漏洞评估报告

## 评估目标
{target}

## 评估时间
{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

## 漏洞统计

| 严重等级 | 数量 |
|----------|------|
| 关键 | {sum(1 for v in vulnerabilities if v.get('severity') == 'critical')} |
| 高危 | {sum(1 for v in vulnerabilities if v.get('severity') == 'high')} |
| 中危 | {sum(1 for v in vulnerabilities if v.get('severity') == 'medium')} |
| 低危 | {sum(1 for v in vulnerabilities if v.get('severity') == 'low')} |

## 漏洞详情

{self._format_vulnerabilities(vulnerabilities)}

## 风险评估

- 整体风险等级: {params.get('risk_level', 'N/A')}
- 风险分数: {params.get('risk_score', 'N/A')}

## 修复建议

{self._format_recommendations(params.get('recommendations', []))}

## 优先修复顺序

{self._format_priority_fixes(vulnerabilities)}
"""

        return {
            "report_type": "vulnerability_assessment",
            "format": "markdown",
            "content": report,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _generate_pentest_report(self, params: dict[str, Any]) -> dict[str, Any]:
        """生成渗透测试报告"""
        target = params.get("target", "")
        scope = params.get("scope", "")
        findings = params.get("findings", [])

        report = f"""# 渗透测试报告

## 测试概要
- 测试目标: {target}
- 测试范围: {scope}
- 测试时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
- 测试方法: {params.get('methodology', 'Black Box')}

## 执行摘要

{params.get('executive_summary', '渗透测试已完成，请查看详细发现。')}

## 发现摘要

| 风险等级 | 数量 |
|----------|------|
| 严重 | {sum(1 for f in findings if f.get('risk') == 'critical')} |
| 高危 | {sum(1 for f in findings if f.get('risk') == 'high')} |
| 中危 | {sum(1 for f in findings if f.get('risk') == 'medium')} |
| 低危 | {sum(1 for f in findings if f.get('risk') == 'low')} |

## 详细发现

{self._format_pentest_findings(findings)}

## 攻击路径

{self._format_attack_paths(params.get('attack_paths', []))}

## 修复建议

{self._format_recommendations(params.get('recommendations', []))}

## 结论

{params.get('conclusion', '测试完成，请及时修复发现的漏洞。')}
"""

        return {
            "report_type": "penetration_test",
            "format": "markdown",
            "content": report,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _generic_response(self, task_or_params: TaskRequest | dict[str, Any]) -> dict[str, Any]:
        """????"""
        if isinstance(task_or_params, TaskRequest):
            task_type = task_or_params.task_type
            parameters = task_or_params.parameters
        else:
            task_type = str(task_or_params.get("task_type", "unknown"))
            parameters = task_or_params

        return {
            "response_type": "generic",
            "task_type": task_type,
            "message": f"?? '{task_type}' ???",
            "parameters": parameters,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # 格式化辅助方法

    def _format_report(self, title: str, data: dict, format: str) -> str:
        """格式化报告"""
        if format == "markdown":
            return f"# {title}\n\n{self._dict_to_markdown(data)}"
        return str(data)

    def _dict_to_markdown(self, data: dict, level: int = 2) -> str:
        """字典转Markdown"""
        lines = []
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"\n{'#' * level} {key}\n")
                lines.append(self._dict_to_markdown(value, level + 1))
            elif isinstance(value, list):
                lines.append(f"\n**{key}:**\n")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"- {item}")
                    else:
                        lines.append(f"- {item}")
            else:
                lines.append(f"**{key}:** {value}")
        return "\n".join(lines)

    def _format_findings(self, findings: list) -> str:
        """格式化发现列表"""
        if not findings:
            return "无发现"
        lines = []
        for i, finding in enumerate(findings, 1):
            lines.append(f"{i}. **{finding.get('title', 'N/A')}**")
            lines.append(f"   - 严重程度: {finding.get('severity', 'N/A')}")
            lines.append(f"   - 描述: {finding.get('description', 'N/A')}")
        return "\n".join(lines)

    def _format_recommendations(self, recommendations: list) -> str:
        """格式化建议"""
        if not recommendations:
            return "暂无建议"
        return "\n".join(f"- {rec}" for rec in recommendations)

    def _format_timeline(self, timeline: list) -> str:
        """格式化时间线"""
        if not timeline:
            return "无时间线数据"
        lines = []
        for event in timeline:
            lines.append(f"- **{event.get('time', 'N/A')}**: {event.get('event', 'N/A')}")
        return "\n".join(lines)

    def _format_affected_assets(self, assets: list) -> str:
        """格式化受影响资产"""
        if not assets:
            return "无受影响资产"
        return "\n".join(f"- {asset}" for asset in assets)

    def _format_actions(self, actions: list) -> str:
        """格式化行动"""
        if not actions:
            return "无行动记录"
        lines = []
        for i, action in enumerate(actions, 1):
            lines.append(f"{i}. {action.get('action', 'N/A')}")
            lines.append(f"   - 时间: {action.get('time', 'N/A')}")
            lines.append(f"   - 结果: {action.get('result', 'N/A')}")
        return "\n".join(lines)

    def _format_lessons_learned(self, lessons: list) -> str:
        """格式化经验教训"""
        if not lessons:
            return "待总结"
        return "\n".join(f"- {lesson}" for lesson in lessons)

    def _format_iocs(self, iocs: list) -> str:
        """格式化IoC"""
        if not iocs:
            return "无IoC"
        return "\n".join(f"- `{ioc}`" for ioc in iocs)

    def _format_references(self, references: list) -> str:
        """格式化参考资料"""
        if not references:
            return "无参考资料"
        return "\n".join(f"- {ref}" for ref in references)

    def _format_data_sources(self, sources: list) -> str:
        """格式化数据源"""
        if not sources:
            return "未指定数据源"
        return "\n".join(f"- {source}" for source in sources)

    def _format_hunting_findings(self, findings: list) -> str:
        """格式化狩猎发现"""
        if not findings:
            return "无验证的发现"
        lines = []
        for finding in findings:
            lines.append(f"- **{finding.get('type', 'N/A')}**: {finding.get('description', 'N/A')}")
        return "\n".join(lines)

    def _format_hunting_analysis(self, analysis: dict) -> str:
        """格式化狩猎分析"""
        if not analysis:
            return "无详细分析"
        return self._dict_to_markdown(analysis)

    def _format_next_steps(self, steps: list) -> str:
        """格式化后续步骤"""
        if not steps:
            return "暂无后续步骤"
        return "\n".join(f"- {step}" for step in steps)

    def _format_file_header(self, header: dict) -> str:
        """格式化文件头"""
        if not header:
            return "无法解析文件头"
        return self._dict_to_markdown(header)

    def _format_strings(self, strings: list) -> str:
        """格式化字符串"""
        if not strings:
            return "无显著字符串"
        return "\n".join(f"- `{s}`" for s in strings[:20])

    def _format_imports(self, imports: list) -> str:
        """格式化导入"""
        if not imports:
            return "无导入信息"
        return "\n".join(f"- {imp}" for imp in imports[:20])

    def _format_behaviors(self, behaviors: list) -> str:
        """格式化行为"""
        if not behaviors:
            return "未检测到行为"
        lines = []
        for behavior in behaviors:
            lines.append(f"- **{behavior.get('type', 'N/A')}**: {behavior.get('description', 'N/A')}")
        return "\n".join(lines)

    def _format_network_activity(self, activity: list) -> str:
        """格式化网络活动"""
        if not activity:
            return "无网络活动"
        return "\n".join(f"- {act}" for act in activity)

    def _format_file_operations(self, ops: list) -> str:
        """格式化文件操作"""
        if not ops:
            return "无文件操作"
        return "\n".join(f"- {op}" for op in ops)

    def _format_threat_intel(self, intel: dict) -> str:
        """格式化威胁情报"""
        if not intel:
            return "无威胁情报"
        return self._dict_to_markdown(intel)

    def _format_vulnerabilities(self, vulns: list) -> str:
        """格式化漏洞列表"""
        if not vulns:
            return "未发现漏洞"
        lines = []
        for vuln in vulns:
            lines.append(f"### {vuln.get('id', 'N/A')}")
            lines.append(f"- 严重程度: {vuln.get('severity', 'N/A')}")
            lines.append(f"- 描述: {vuln.get('description', 'N/A')}")
            lines.append(f"- CVSS: {vuln.get('cvss', 'N/A')}")
            lines.append("")
        return "\n".join(lines)

    def _format_priority_fixes(self, vulns: list) -> str:
        """格式化优先修复顺序"""
        sorted_vulns = sorted(vulns, key=lambda v: v.get('cvss', 0), reverse=True)
        lines = []
        for i, vuln in enumerate(sorted_vulns[:10], 1):
            lines.append(f"{i}. {vuln.get('id', 'N/A')} (CVSS: {vuln.get('cvss', 'N/A')})")
        return "\n".join(lines)

    def _format_pentest_findings(self, findings: list) -> str:
        """格式化渗透测试发现"""
        if not findings:
            return "未发现漏洞"
        lines = []
        for finding in findings:
            lines.append(f"### {finding.get('title', 'N/A')}")
            lines.append(f"- 风险等级: {finding.get('risk', 'N/A')}")
            lines.append(f"- 描述: {finding.get('description', 'N/A')}")
            lines.append(f"- 复现步骤: {finding.get('steps', 'N/A')}")
            lines.append(f"- 修复建议: {finding.get('fix', 'N/A')}")
            lines.append("")
        return "\n".join(lines)

    def _format_attack_paths(self, paths: list) -> str:
        """格式化攻击路径"""
        if not paths:
            return "无攻击路径"
        lines = []
        for i, path in enumerate(paths, 1):
            lines.append(f"**路径 {i}:**")
            for step in path:
                lines.append(f"  → {step}")
        return "\n".join(lines)
