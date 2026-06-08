"""
Task Planner Engine — 任务规划引擎。

基于输入类型自动生成执行计划，支持多步骤任务分解和工具编排。
"""

import time
import logging
from typing import Any, Optional
from enum import Enum

from pydantic import BaseModel, Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)


class TaskType(str, Enum):
    """任务类型枚举"""
    FILE_ANALYSIS = "file_analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    PENETRATION_TEST = "penetration_test"
    INCIDENT_RESPONSE = "incident_response"
    MALWARE_ANALYSIS = "malware_analysis"
    NETWORK_RECON = "network_recon"
    CODE_AUDIT = "code_audit"
    API_SECURITY = "api_security"
    CONFIGURATION_AUDIT = "configuration_audit"
    THREAT_INTELLIGENCE = "threat_intelligence"
    GENERAL = "general"


class TaskPriority(str, Enum):
    """任务优先级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TaskStep(BaseModel):
    """任务步骤"""
    step_id: int
    tool_name: str
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[int] = Field(default_factory=list)
    priority: TaskPriority = TaskPriority.MEDIUM
    estimated_time_seconds: int = 60
    optional: bool = False


class TaskPlan(BaseModel):
    """任务计划"""
    task_id: str
    task_type: TaskType
    description: str
    steps: list[TaskStep]
    total_steps: int
    estimated_total_time_seconds: int
    required_tools: list[str]
    optional_tools: list[str]
    risk_level: str = "medium"
    notes: list[str] = Field(default_factory=list)


class TaskPlannerInput(ToolInput):
    """Task Planner 输入"""

    task_description: str = Field(..., description="任务描述（自然语言）")
    input_files: list[str] = Field(default_factory=list, description="输入文件路径列表")
    task_type: Optional[str] = Field(default=None, description="任务类型（可选，自动推断）")
    constraints: list[str] = Field(default_factory=list, description="约束条件")
    available_tools: list[str] = Field(default_factory=list, description="可用工具列表")


class TaskPlannerTool:
    """任务规划引擎 - 基于输入自动生成执行计划"""

    name = "task_planner"
    version = "v1"
    input_class = TaskPlannerInput

    # 文件类型到工具的映射
    FILE_TYPE_TOOLS = {
        "pcap": ["pcap_analysis", "ip_threat_analysis", "ioc_lookup"],
        "pcapng": ["pcap_analysis", "ip_threat_analysis", "ioc_lookup"],
        "zip": ["archive_analysis"],
        "rar": ["archive_analysis"],
        "7z": ["archive_analysis"],
        "tar": ["archive_analysis"],
        "gz": ["archive_analysis"],
        "json": ["config_parser"],
        "yaml": ["config_parser"],
        "yml": ["config_parser"],
        "xml": ["config_parser"],
        "csv": ["config_parser"],
        "env": ["config_parser"],
        "ini": ["config_parser"],
        "exe": ["binary_analysis", "hash_lookup"],
        "dll": ["binary_analysis", "hash_lookup"],
        "so": ["binary_analysis", "hash_lookup"],
        "elf": ["binary_analysis", "hash_lookup"],
        "py": ["vuln_scan"],
        "js": ["vuln_scan"],
        "java": ["vuln_scan"],
        "c": ["vuln_scan"],
        "cpp": ["vuln_scan"],
        "php": ["vuln_scan"],
        "sh": ["vuln_scan"],
        "swagger": ["api_doc_parser"],
        "openapi": ["api_doc_parser"],
        "postman_collection": ["api_doc_parser"],
    }

    # 任务类型到工具链的映射
    TASK_TYPE_CHAINS = {
        TaskType.VULNERABILITY_SCAN: [
            {"tool": "nmap_scan", "description": "端口扫描和服务发现"},
            {"tool": "vuln_scan", "description": "漏洞扫描"},
            {"tool": "web_search", "description": "搜索漏洞利用信息"},
        ],
        TaskType.PENETRATION_TEST: [
            {"tool": "nmap_scan", "description": "目标侦察"},
            {"tool": "dir_scan", "description": "目录枚举"},
            {"tool": "vuln_scan", "description": "漏洞识别"},
            {"tool": "web_search", "description": "搜索漏洞利用代码"},
        ],
        TaskType.INCIDENT_RESPONSE: [
            {"tool": "log_analysis", "description": "日志分析"},
            {"tool": "ioc_lookup", "description": "IoC 验证"},
            {"tool": "ip_threat_analysis", "description": "IP 威胁分析"},
            {"tool": "hash_lookup", "description": "恶意文件识别"},
        ],
        TaskType.MALWARE_ANALYSIS: [
            {"tool": "binary_analysis", "description": "二进制分析"},
            {"tool": "hash_lookup", "description": "哈希信誉查询"},
            {"tool": "config_parser", "description": "配置提取"},
        ],
        TaskType.NETWORK_RECON: [
            {"tool": "nmap_scan", "description": "端口扫描"},
            {"tool": "ip_threat_analysis", "description": "IP 信息收集"},
            {"tool": "web_search", "description": "公开信息搜索"},
        ],
        TaskType.CODE_AUDIT: [
            {"tool": "vuln_scan", "description": "静态代码分析"},
            {"tool": "config_parser", "description": "配置文件审查"},
        ],
        TaskType.API_SECURITY: [
            {"tool": "api_doc_parser", "description": "API 文档解析"},
            {"tool": "dir_scan", "description": "端点发现"},
            {"tool": "vuln_scan", "description": "API 漏洞扫描"},
        ],
        TaskType.THREAT_INTELLIGENCE: [
            {"tool": "ioc_lookup", "description": "IoC 查询"},
            {"tool": "ip_threat_analysis", "description": "IP 威胁分析"},
            {"tool": "cve_lookup", "description": "CVE 查询"},
            {"tool": "web_search", "description": "威胁情报搜索"},
        ],
    }

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "task_planner",
                "description": (
                    "任务规划引擎 - 基于输入自动生成执行计划。"
                    "支持多步骤任务分解和工具编排。"
                    "\n\n支持的任务类型："
                    "- 文件分析（自动识别文件类型并选择工具）"
                    "- 漏洞扫描（端口扫描→漏洞识别→利用信息）"
                    "- 渗透测试（侦察→枚举→漏洞→利用）"
                    "- 应急响应（日志分析→IoC验证→威胁分析）"
                    "- 恶意软件分析（二进制分析→哈希查询→配置提取）"
                    "- 网络侦察（端口扫描→信息收集）"
                    "- 代码审计（静态分析→配置审查）"
                    "- API 安全（文档解析→端点发现→漏洞扫描）"
                    "- 威胁情报（IoC查询→IP分析→CVE查询）"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "task_description": {
                            "type": "string",
                            "description": "任务描述（自然语言）",
                        },
                        "input_files": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "输入文件路径列表",
                        },
                        "task_type": {
                            "type": "string",
                            "enum": [t.value for t in TaskType],
                            "description": "任务类型（可选，自动推断）",
                        },
                        "constraints": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "约束条件（如时间限制、工具限制等）",
                        },
                        "available_tools": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "可用工具列表（为空则使用所有注册工具）",
                        },
                    },
                    "required": ["task_description"],
                },
            },
        }

    async def execute(self, input_data: TaskPlannerInput) -> ToolResult:
        start = time.time()

        # Infer task type if not provided
        task_type = input_data.task_type or self._infer_task_type(
            input_data.task_description, input_data.input_files
        )

        # Generate task plan
        try:
            plan = self._generate_plan(
                task_type=task_type,
                task_description=input_data.task_description,
                input_files=input_data.input_files,
                constraints=input_data.constraints,
                available_tools=input_data.available_tools,
            )
        except Exception as e:
            logger.error(f"Task planning failed: {e}")
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"任务规划失败: {e}",
                confidence=0.0,
                evidence_source=["task_planner"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        execution_time_ms = int((time.time() - start) * 1000)

        # Build result
        result = {
            "task_id": plan.task_id,
            "task_type": plan.task_type.value,
            "description": plan.description,
            "total_steps": plan.total_steps,
            "estimated_total_time_seconds": plan.estimated_total_time_seconds,
            "risk_level": plan.risk_level,
            "steps": [step.model_dump() for step in plan.steps],
            "required_tools": plan.required_tools,
            "optional_tools": plan.optional_tools,
            "notes": plan.notes,
        }

        # Build summary
        summary_parts = [
            f"任务类型: {plan.task_type.value}",
            f"任务描述: {plan.description}",
            f"执行步骤: {plan.total_steps} 步",
            f"预计时间: {plan.estimated_total_time_seconds} 秒",
            f"风险等级: {plan.risk_level}",
        ]

        summary_parts.append("执行计划:")
        for step in plan.steps:
            deps = f" (依赖步骤 {step.depends_on})" if step.depends_on else ""
            optional = " [可选]" if step.optional else ""
            summary_parts.append(f"  {step.step_id}. {step.description}{deps}{optional}")
            summary_parts.append(f"     工具: {step.tool_name}")

        if plan.notes:
            summary_parts.append("注意事项:")
            for note in plan.notes:
                summary_parts.append(f"  - {note}")

        result["summary_text"] = "；".join(summary_parts)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result,
            error=None,
            confidence=0.85,
            evidence_source=["task_planner"],
            trace_id=input_data.trace_id,
            execution_time_ms=execution_time_ms,
        )

    def _infer_task_type(self, description: str, input_files: list[str]) -> str:
        """Infer task type from description and input files."""
        description_lower = description.lower()

        # Check description keywords
        if any(kw in description_lower for kw in ["漏洞扫描", "vulnerability", "vuln scan"]):
            return TaskType.VULNERABILITY_SCAN.value
        elif any(kw in description_lower for kw in ["渗透", "penetration", "pentest"]):
            return TaskType.PENETRATION_TEST.value
        elif any(kw in description_lower for kw in ["应急", "incident", "响应", "response"]):
            return TaskType.INCIDENT_RESPONSE.value
        elif any(kw in description_lower for kw in ["恶意软件", "malware", "病毒", "木马"]):
            return TaskType.MALWARE_ANALYSIS.value
        elif any(kw in description_lower for kw in ["网络侦察", "recon", "扫描", "scan"]):
            return TaskType.NETWORK_RECON.value
        elif any(kw in description_lower for kw in ["代码审计", "code audit", "源码"]):
            return TaskType.CODE_AUDIT.value
        elif any(kw in description_lower for kw in ["api", "接口", "endpoint"]):
            return TaskType.API_SECURITY.value
        elif any(kw in description_lower for kw in ["威胁情报", "threat intelligence", "ioc"]):
            return TaskType.THREAT_INTELLIGENCE.value

        # Check file types
        if input_files:
            file_extensions = set()
            for file_path in input_files:
                ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
                file_extensions.add(ext)

            # Check for specific file types
            if "pcap" in file_extensions or "pcapng" in file_extensions:
                return TaskType.INCIDENT_RESPONSE.value
            elif file_extensions & {"exe", "dll", "so", "elf"}:
                return TaskType.MALWARE_ANALYSIS.value
            elif file_extensions & {"py", "js", "java", "c", "cpp", "php"}:
                return TaskType.CODE_AUDIT.value
            elif file_extensions & {"swagger", "openapi", "postman_collection"}:
                return TaskType.API_SECURITY.value

        return TaskType.FILE_ANALYSIS.value

    def _generate_plan(
        self,
        task_type: str,
        task_description: str,
        input_files: list[str],
        constraints: list[str],
        available_tools: list[str],
    ) -> TaskPlan:
        """Generate task plan based on type and inputs."""
        import uuid

        task_id = f"task_{uuid.uuid4().hex[:8]}"
        
        # Parse task type
        try:
            task_type_enum = TaskType(task_type)
        except ValueError:
            task_type_enum = TaskType.GENERAL

        steps = []
        required_tools = []
        optional_tools = []
        notes = []

        # Generate steps based on task type
        if task_type_enum == TaskType.FILE_ANALYSIS:
            steps, required_tools, optional_tools = self._plan_file_analysis(input_files)
        elif task_type_enum in self.TASK_TYPE_CHAINS:
            chain = self.TASK_TYPE_CHAINS[task_type_enum]
            for i, tool_info in enumerate(chain):
                step = TaskStep(
                    step_id=i + 1,
                    tool_name=tool_info["tool"],
                    description=tool_info["description"],
                    depends_on=[i] if i > 0 else [],
                    priority=TaskPriority.HIGH if i == 0 else TaskPriority.MEDIUM,
                    estimated_time_seconds=60,
                )
                steps.append(step)
                required_tools.append(tool_info["tool"])
        else:
            # Generic plan
            steps.append(TaskStep(
                step_id=1,
                tool_name="web_search",
                description="搜索相关信息",
                priority=TaskPriority.MEDIUM,
            ))
            required_tools.append("web_search")

        # Add file-specific steps
        if input_files:
            file_steps = self._generate_file_steps(input_files, len(steps))
            steps.extend(file_steps)
            for step in file_steps:
                if step.optional:
                    optional_tools.append(step.tool_name)
                else:
                    required_tools.append(step.tool_name)

        # Calculate total time
        total_time = sum(step.estimated_time_seconds for step in steps)

        # Risk assessment
        risk_level = self._assess_risk(task_type_enum, input_files)

        # Add notes based on constraints
        if constraints:
            for constraint in constraints:
                notes.append(f"约束: {constraint}")

        # Add general notes
        if task_type_enum in [TaskType.PENETRATION_TEST, TaskType.VULNERABILITY_SCAN]:
            notes.append("注意: 仅在授权范围内进行测试")
            notes.append("建议: 先进行侦察，再进行深入测试")

        if any(f.endswith((".exe", ".dll", ".so")) for f in input_files):
            notes.append("注意: 二进制文件分析可能需要较长时间")
            notes.append("建议: 先进行哈希查询，检查是否已知样本")

        return TaskPlan(
            task_id=task_id,
            task_type=task_type_enum,
            description=task_description,
            steps=steps,
            total_steps=len(steps),
            estimated_total_time_seconds=total_time,
            required_tools=list(set(required_tools)),
            optional_tools=list(set(optional_tools)),
            risk_level=risk_level,
            notes=notes,
        )

    def _plan_file_analysis(self, input_files: list[str]) -> tuple[list[TaskStep], list[str], list[str]]:
        """Plan for file analysis task."""
        steps = []
        required_tools = []
        optional_tools = []

        step_id = 1

        for file_path in input_files:
            ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
            
            # Get tools for file type
            tools = self.FILE_TYPE_TOOLS.get(ext, [])
            
            if not tools:
                # Unknown file type - try binary analysis
                tools = ["binary_analysis"]

            for tool_name in tools:
                step = TaskStep(
                    step_id=step_id,
                    tool_name=tool_name,
                    description=f"分析文件 {file_path} ({ext})",
                    parameters={"file_path": file_path},
                    depends_on=[step_id - 1] if step_id > 1 else [],
                    priority=TaskPriority.HIGH,
                    estimated_time_seconds=60,
                )
                steps.append(step)
                required_tools.append(tool_name)
                step_id += 1

        return steps, required_tools, optional_tools

    def _generate_file_steps(self, input_files: list[str], start_id: int) -> list[TaskStep]:
        """Generate steps for input files."""
        steps = []
        step_id = start_id + 1

        for file_path in input_files:
            ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
            
            # Get tools for file type
            tools = self.FILE_TYPE_TOOLS.get(ext, [])
            
            for tool_name in tools:
                step = TaskStep(
                    step_id=step_id,
                    tool_name=tool_name,
                    description=f"分析 {file_path}",
                    parameters={"file_path": file_path},
                    depends_on=[step_id - 1] if step_id > start_id + 1 else [],
                    priority=TaskPriority.HIGH,
                    estimated_time_seconds=60,
                    optional=True,
                )
                steps.append(step)
                step_id += 1

        return steps

    def _assess_risk(self, task_type: TaskType, input_files: list[str]) -> str:
        """Assess task risk level."""
        high_risk_tasks = [
            TaskType.PENETRATION_TEST,
            TaskType.VULNERABILITY_SCAN,
            TaskType.MALWARE_ANALYSIS,
        ]

        if task_type in high_risk_tasks:
            return "high"

        # Check for potentially dangerous files
        dangerous_extensions = {"exe", "dll", "so", "elf", "sh", "bat", "ps1"}
        for file_path in input_files:
            ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
            if ext in dangerous_extensions:
                return "high"

        return "medium"


task_planner_tool = TaskPlannerTool()
