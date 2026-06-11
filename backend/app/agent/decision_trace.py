"""
Decision Trace Module — 决策可解释性追踪。

记录完整的推理链路，支持决策回放和审计报告导出。
"""

from __future__ import annotations

import json
import time
import logging
from typing import Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class DecisionType(str, Enum):
    """决策类型"""
    THOUGHT = "thought"          # LLM 思考
    ACTION = "action"            # 工具调用
    OBSERVATION = "observation"  # 工具返回
    FINAL_ANSWER = "final_answer"  # 最终答案
    ERROR = "error"              # 错误
    RETRY = "retry"              # 重试
    COMPRESS = "compress"        # 上下文压缩


class ConfidenceLevel(str, Enum):
    """置信度等级"""
    VERY_HIGH = "very_high"  # 0.9-1.0
    HIGH = "high"            # 0.7-0.9
    MEDIUM = "medium"        # 0.5-0.7
    LOW = "low"              # 0.3-0.5
    VERY_LOW = "very_low"    # 0.0-0.3


@dataclass
class EvidenceItem:
    """证据项"""
    source: str                  # 数据来源
    source_type: str             # 来源类型 (tool, rag, web, user)
    content: str                 # 证据内容
    confidence: float            # 置信度 0.0-1.0
    timestamp: str               # 时间戳
    tool_name: Optional[str] = None  # 关联的工具名
    tool_input: Optional[dict] = None  # 工具输入
    tool_output: Optional[dict] = None  # 工具输出


@dataclass
class DecisionStep:
    """决策步骤"""
    step_id: int                 # 步骤 ID
    turn: int                    # 轮次
    decision_type: DecisionType  # 决策类型
    content: str                 # 内容
    timestamp: str               # 时间戳
    duration_ms: int = 0         # 耗时毫秒
    confidence: float = 0.0      # 置信度
    evidence: list[EvidenceItem] = field(default_factory=list)  # 关联证据
    metadata: dict[str, Any] = field(default_factory=dict)  # 元数据


@dataclass
class DecisionTrace:
    """决策追踪记录"""
    trace_id: str                # 追踪 ID
    session_id: str              # 会话 ID
    user_id: str                 # 用户 ID
    tenant_id: str               # 租户 ID
    query: str                   # 用户查询
    start_time: str              # 开始时间
    end_time: Optional[str] = None  # 结束时间
    total_duration_ms: int = 0   # 总耗时
    steps: list[DecisionStep] = field(default_factory=list)  # 决策步骤
    final_answer: Optional[str] = None  # 最终答案
    final_confidence: float = 0.0  # 最终置信度
    final_evidence: list[EvidenceItem] = field(default_factory=list)  # 最终证据
    success: bool = False        # 是否成功
    error: Optional[str] = None  # 错误信息
    metadata: dict[str, Any] = field(default_factory=dict)  # 元数据


class DecisionTracker:
    """决策追踪器"""

    MAX_TRACES = 500  # Maximum traces to keep in memory

    def __init__(self):
        self._traces: dict[str, DecisionTrace] = {}
        self._step_counter: dict[str, int] = {}
        self._trace_order: list[str] = []  # For LRU eviction

    def start_trace(
        self,
        trace_id: str,
        session_id: str,
        user_id: str,
        tenant_id: str,
        query: str,
    ) -> DecisionTrace:
        """开始新的决策追踪"""
        # Evict oldest traces if at capacity
        while len(self._traces) >= self.MAX_TRACES:
            oldest_id = self._trace_order.pop(0)
            self._traces.pop(oldest_id, None)
            self._step_counter.pop(oldest_id, None)

        trace = DecisionTrace(
            trace_id=trace_id,
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            query=query,
            start_time=datetime.now().isoformat(),
        )
        self._traces[trace_id] = trace
        self._step_counter[trace_id] = 0
        self._trace_order.append(trace_id)
        return trace

    def get_trace(self, trace_id: str) -> Optional[DecisionTrace]:
        """获取决策追踪记录（内存 → 数据库）"""
        trace = self._traces.get(trace_id)
        if trace:
            return trace

        # 从数据库加载
        return self._load_trace_from_db(trace_id)

    def _load_trace_from_db(self, trace_id: str) -> Optional[DecisionTrace]:
        """从数据库加载追踪记录"""
        try:
            from app.models.base import get_session_factory
            from app.models.models import DecisionTraceRecord
            from sqlalchemy import select
            import asyncio

            factory = get_session_factory()
            if factory is None:
                return None

            async def _do_load():
                async with factory() as session:
                    result = await session.execute(
                        select(DecisionTraceRecord).where(DecisionTraceRecord.id == trace_id)
                    )
                    record = result.scalar_one_or_none()
                    if not record:
                        return None

                    # Reconstruct DecisionTrace from DB record
                    trace = DecisionTrace(
                        trace_id=record.id,
                        session_id=record.session_id,
                        user_id=record.user_id,
                        tenant_id=record.tenant_id,
                        query=record.query,
                        start_time=record.start_time.isoformat() if record.start_time else "",
                        end_time=record.end_time.isoformat() if record.end_time else None,
                        total_duration_ms=record.total_duration_ms,
                        success=record.success,
                        error=record.error,
                        final_answer=record.final_answer,
                        final_confidence=record.final_confidence,
                    )

                    # Reconstruct steps
                    if record.steps_json:
                        for step_data in record.steps_json:
                            step = DecisionStep(
                                step_id=step_data.get("step_id", 0),
                                turn=step_data.get("turn", 0),
                                decision_type=DecisionType(step_data.get("type", "thought")),
                                content=step_data.get("content", ""),
                                timestamp=step_data.get("timestamp", ""),
                                duration_ms=step_data.get("duration_ms", 0),
                                confidence=step_data.get("confidence", 0.0),
                                metadata=step_data.get("metadata", {}),
                            )
                            trace.steps.append(step)

                    return trace

            try:
                loop = asyncio.get_running_loop()
                # We're in an async context — schedule as a task and return None
                # The caller should await if needed
                logger.debug("Cannot sync-load trace %s in running loop", trace_id)
                return None
            except RuntimeError:
                # No running loop — safe to use run_until_complete
                return asyncio.run(_do_load())

        except Exception as e:
            logger.debug("Failed to load trace %s from DB: %s", trace_id, e)
            return None

    def add_step(
        self,
        trace_id: str,
        turn: int,
        decision_type: DecisionType,
        content: str,
        confidence: float = 0.0,
        evidence: Optional[list[EvidenceItem]] = None,
        metadata: Optional[dict[str, Any]] = None,
        duration_ms: int = 0,
    ) -> Optional[DecisionStep]:
        """添加决策步骤"""
        trace = self._traces.get(trace_id)
        if not trace:
            return None

        self._step_counter[trace_id] = self._step_counter.get(trace_id, 0) + 1
        step = DecisionStep(
            step_id=self._step_counter[trace_id],
            turn=turn,
            decision_type=decision_type,
            content=content,
            timestamp=datetime.now().isoformat(),
            duration_ms=duration_ms,
            confidence=confidence,
            evidence=evidence or [],
            metadata=metadata or {},
        )
        trace.steps.append(step)
        return step

    def add_thought(
        self,
        trace_id: str,
        turn: int,
        thought: str,
        confidence: float = 0.0,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[DecisionStep]:
        """添加思考步骤"""
        return self.add_step(
            trace_id=trace_id,
            turn=turn,
            decision_type=DecisionType.THOUGHT,
            content=thought,
            confidence=confidence,
            metadata=metadata,
        )

    def add_action(
        self,
        trace_id: str,
        turn: int,
        tool_name: str,
        tool_input: dict[str, Any],
        confidence: float = 0.0,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[DecisionStep]:
        """添加动作步骤"""
        content = f"调用工具: {tool_name}"
        evidence = EvidenceItem(
            source=tool_name,
            source_type="tool",
            content=json.dumps(tool_input, ensure_ascii=False),
            confidence=confidence,
            timestamp=datetime.now().isoformat(),
            tool_name=tool_name,
            tool_input=tool_input,
        )
        return self.add_step(
            trace_id=trace_id,
            turn=turn,
            decision_type=DecisionType.ACTION,
            content=content,
            confidence=confidence,
            evidence=[evidence],
            metadata={**(metadata or {}), "tool_name": tool_name, "tool_input": tool_input},
        )

    def add_observation(
        self,
        trace_id: str,
        turn: int,
        tool_name: str,
        tool_output: dict[str, Any],
        confidence: float = 0.0,
        duration_ms: int = 0,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[DecisionStep]:
        """添加观察步骤"""
        success = tool_output.get("success", False)
        content = f"工具返回: {tool_name} ({'成功' if success else '失败'})"
        
        evidence = EvidenceItem(
            source=tool_name,
            source_type="tool",
            content=json.dumps(tool_output.get("data", {}), ensure_ascii=False)[:500],
            confidence=tool_output.get("confidence", confidence),
            timestamp=datetime.now().isoformat(),
            tool_name=tool_name,
            tool_output=tool_output,
        )
        return self.add_step(
            trace_id=trace_id,
            turn=turn,
            decision_type=DecisionType.OBSERVATION,
            content=content,
            confidence=tool_output.get("confidence", confidence),
            evidence=[evidence],
            duration_ms=duration_ms,
            metadata={**(metadata or {}), "tool_name": tool_name, "success": success},
        )

    def add_final_answer(
        self,
        trace_id: str,
        answer: str,
        confidence: float = 0.0,
        evidence: Optional[list[EvidenceItem]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[DecisionStep]:
        """添加最终答案"""
        trace = self._traces.get(trace_id)
        if trace:
            trace.final_answer = answer
            trace.final_confidence = confidence
            trace.final_evidence = evidence or []
            trace.end_time = datetime.now().isoformat()
            trace.success = True

        return self.add_step(
            trace_id=trace_id,
            turn=0,  # 最终答案不在特定轮次
            decision_type=DecisionType.FINAL_ANSWER,
            content=answer,
            confidence=confidence,
            evidence=evidence,
            metadata=metadata,
        )

    def add_error(
        self,
        trace_id: str,
        turn: int,
        error: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[DecisionStep]:
        """添加错误步骤"""
        trace = self._traces.get(trace_id)
        if trace:
            trace.error = error
            trace.end_time = datetime.now().isoformat()

        return self.add_step(
            trace_id=trace_id,
            turn=turn,
            decision_type=DecisionType.ERROR,
            content=error,
            confidence=0.0,
            metadata=metadata,
        )

    def end_trace(self, trace_id: str, success: bool = True, error: Optional[str] = None):
        """结束决策追踪"""
        trace = self._traces.get(trace_id)
        if trace:
            trace.end_time = datetime.now().isoformat()
            trace.success = success
            if error:
                trace.error = error

            # 计算总耗时
            if trace.start_time:
                try:
                    start = datetime.fromisoformat(trace.start_time)
                    end = datetime.fromisoformat(trace.end_time)
                    trace.total_duration_ms = int((end - start).total_seconds() * 1000)
                except Exception:
                    pass

            # 持久化到数据库
            self._persist_trace(trace)

    def _persist_trace(self, trace: DecisionTrace) -> None:
        """Persist trace to database (best-effort, non-blocking)."""
        try:
            from app.models.base import get_session_factory
            from app.models.models import DecisionTraceRecord
            import asyncio

            factory = get_session_factory()
            if factory is None:
                return

            # Serialize steps to JSON
            steps_data = []
            for step in trace.steps:
                step_dict = {
                    "step_id": step.step_id,
                    "turn": step.turn,
                    "type": step.decision_type.value,
                    "content": step.content,
                    "timestamp": step.timestamp,
                    "duration_ms": step.duration_ms,
                    "confidence": step.confidence,
                    "metadata": step.metadata,
                    "evidence": [
                        {
                            "source": e.source,
                            "source_type": e.source_type,
                            "content": e.content[:500] if e.content else "",
                            "confidence": e.confidence,
                            "tool_name": e.tool_name,
                        }
                        for e in step.evidence
                    ],
                }
                steps_data.append(step_dict)

            async def _do_persist():
                try:
                    async with factory() as session:
                        record = DecisionTraceRecord(
                            id=trace.trace_id,
                            session_id=trace.session_id,
                            user_id=trace.user_id,
                            tenant_id=trace.tenant_id,
                            query=trace.query[:2000],
                            start_time=trace.start_time,
                            end_time=trace.end_time,
                            total_duration_ms=trace.total_duration_ms,
                            success=trace.success,
                            error=trace.error,
                            final_answer=trace.final_answer[:5000] if trace.final_answer else None,
                            final_confidence=trace.final_confidence,
                            steps_json=steps_data,
                        )
                        session.add(record)
                        await session.commit()
                except Exception as e:
                    logger.debug("Persist trace %s failed: %s", trace.trace_id, e)

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_do_persist())
            except RuntimeError:
                # No running loop — skip persistence
                pass

        except Exception as e:
            logger.debug("Failed to persist decision trace %s: %s", trace.trace_id, e)

    def get_decision_chain(self, trace_id: str) -> list[dict[str, Any]]:
        """获取决策链（用于回放）"""
        trace = self._traces.get(trace_id)
        if not trace:
            return []

        chain = []
        for step in trace.steps:
            chain.append({
                "step_id": step.step_id,
                "turn": step.turn,
                "type": step.decision_type.value,
                "content": step.content,
                "timestamp": step.timestamp,
                "duration_ms": step.duration_ms,
                "confidence": step.confidence,
                "evidence_count": len(step.evidence),
                "metadata": step.metadata,
            })
        return chain

    def get_evidence_summary(self, trace_id: str) -> list[dict[str, Any]]:
        """获取证据摘要"""
        trace = self._traces.get(trace_id)
        if not trace:
            return []

        evidence_summary = []
        for step in trace.steps:
            for evidence in step.evidence:
                evidence_summary.append({
                    "step_id": step.step_id,
                    "turn": step.turn,
                    "source": evidence.source,
                    "source_type": evidence.source_type,
                    "confidence": evidence.confidence,
                    "tool_name": evidence.tool_name,
                    "content_preview": evidence.content[:200] if evidence.content else "",
                })
        return evidence_summary

    def export_audit_report(
        self,
        trace_id: str,
        fmt: str = "json",
    ) -> Optional[str]:
        """导出审计报告"""
        trace = self._traces.get(trace_id)
        if not trace:
            return None

        if fmt == "json":
            return self._export_json(trace)
        elif fmt == "markdown":
            return self._export_markdown(trace)
        else:
            return None

    def _export_json(self, trace: DecisionTrace) -> str:
        """导出 JSON 格式报告"""
        report = {
            "trace_id": trace.trace_id,
            "session_id": trace.session_id,
            "user_id": trace.user_id,
            "tenant_id": trace.tenant_id,
            "query": trace.query,
            "start_time": trace.start_time,
            "end_time": trace.end_time,
            "total_duration_ms": trace.total_duration_ms,
            "success": trace.success,
            "error": trace.error,
            "final_answer": trace.final_answer,
            "final_confidence": trace.final_confidence,
            "steps": [],
            "evidence": [],
        }

        for step in trace.steps:
            step_data = {
                "step_id": step.step_id,
                "turn": step.turn,
                "type": step.decision_type.value,
                "content": step.content,
                "timestamp": step.timestamp,
                "duration_ms": step.duration_ms,
                "confidence": step.confidence,
                "metadata": step.metadata,
            }
            report["steps"].append(step_data)

            for evidence in step.evidence:
                evidence_data = {
                    "step_id": step.step_id,
                    "source": evidence.source,
                    "source_type": evidence.source_type,
                    "content": evidence.content,
                    "confidence": evidence.confidence,
                    "tool_name": evidence.tool_name,
                    "tool_input": evidence.tool_input,
                    "tool_output": evidence.tool_output,
                }
                report["evidence"].append(evidence_data)

        return json.dumps(report, ensure_ascii=False, indent=2)

    def _export_markdown(self, trace: DecisionTrace) -> str:
        """导出 Markdown 格式报告"""
        lines = [
            "# 决策审计报告",
            "",
            "## 基本信息",
            "",
            f"- **追踪 ID**: {trace.trace_id}",
            f"- **会话 ID**: {trace.session_id}",
            f"- **用户 ID**: {trace.user_id}",
            f"- **租户 ID**: {trace.tenant_id}",
            f"- **开始时间**: {trace.start_time}",
            f"- **结束时间**: {trace.end_time}",
            f"- **总耗时**: {trace.total_duration_ms}ms",
            f"- **状态**: {'成功' if trace.success else '失败'}",
            "",
            "## 用户查询",
            "",
            f"```",
            trace.query,
            f"```",
            "",
            "## 决策链",
            "",
        ]

        for step in trace.steps:
            confidence_level = self._get_confidence_level(step.confidence)
            lines.append(f"### 步骤 {step.step_id} (轮次 {step.turn})")
            lines.append("")
            lines.append(f"- **类型**: {step.decision_type.value}")
            lines.append(f"- **时间**: {step.timestamp}")
            lines.append(f"- **耗时**: {step.duration_ms}ms")
            lines.append(f"- **置信度**: {step.confidence:.2f} ({confidence_level})")
            lines.append("")
            lines.append("**内容**:")
            lines.append("```")
            lines.append(step.content)
            lines.append("```")
            lines.append("")

            if step.evidence:
                lines.append("**关联证据**:")
                lines.append("")
                for evidence in step.evidence:
                    lines.append(f"- 来源: {evidence.source} ({evidence.source_type})")
                    lines.append(f"  置信度: {evidence.confidence:.2f}")
                    if evidence.tool_name:
                        lines.append(f"  工具: {evidence.tool_name}")
                    lines.append("")

        if trace.final_answer:
            lines.extend([
                "## 最终答案",
                "",
                "```",
                trace.final_answer,
                "```",
                "",
                f"**最终置信度**: {trace.final_confidence:.2f}",
                "",
            ])

        if trace.error:
            lines.extend([
                "## 错误信息",
                "",
                "```",
                trace.error,
                "```",
                "",
            ])

        lines.extend([
            "## 证据汇总",
            "",
            "| 来源 | 类型 | 置信度 | 工具 | 内容预览 |",
            "|------|------|--------|------|----------|",
        ])

        for step in trace.steps:
            for evidence in step.evidence:
                content_preview = evidence.content[:50] + "..." if len(evidence.content) > 50 else evidence.content
                lines.append(
                    f"| {evidence.source} | {evidence.source_type} | {evidence.confidence:.2f} | {evidence.tool_name or '-'} | {content_preview} |"
                )

        return "\n".join(lines)

    def _get_confidence_level(self, confidence: float) -> str:
        """获取置信度等级"""
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH.value
        elif confidence >= 0.7:
            return ConfidenceLevel.HIGH.value
        elif confidence >= 0.5:
            return ConfidenceLevel.MEDIUM.value
        elif confidence >= 0.3:
            return ConfidenceLevel.LOW.value
        else:
            return ConfidenceLevel.VERY_LOW.value


# Global decision tracker instance
decision_tracker = DecisionTracker()
