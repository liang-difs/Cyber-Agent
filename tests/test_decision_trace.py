"""Tests for Decision Trace Module."""

import json
import pytest
import uuid

from app.agent.decision_trace import (
    DecisionTracker,
    DecisionType,
    ConfidenceLevel,
    EvidenceItem,
    decision_tracker,
)


@pytest.fixture
def tracker():
    """Create a fresh decision tracker for each test."""
    return DecisionTracker()


@pytest.fixture
def trace_id():
    return str(uuid.uuid4())


@pytest.fixture
def sample_trace(tracker, trace_id):
    """Create a sample decision trace."""
    return tracker.start_trace(
        trace_id=trace_id,
        session_id="session_123",
        user_id="user_123",
        tenant_id="tenant_123",
        query="分析这个 IP 地址的威胁",
    )


class TestDecisionTracker:
    """Tests for DecisionTracker class."""

    def test_start_trace(self, tracker, trace_id):
        """Test starting a new trace."""
        trace = tracker.start_trace(
            trace_id=trace_id,
            session_id="session_123",
            user_id="user_123",
            tenant_id="tenant_123",
            query="测试查询",
        )

        assert trace.trace_id == trace_id
        assert trace.session_id == "session_123"
        assert trace.user_id == "user_123"
        assert trace.tenant_id == "tenant_123"
        assert trace.query == "测试查询"
        assert trace.start_time is not None
        assert trace.success is False

    def test_get_trace(self, tracker, trace_id):
        """Test getting a trace."""
        tracker.start_trace(
            trace_id=trace_id,
            session_id="session_123",
            user_id="user_123",
            tenant_id="tenant_123",
            query="测试查询",
        )

        trace = tracker.get_trace(trace_id)
        assert trace is not None
        assert trace.trace_id == trace_id

    def test_get_nonexistent_trace(self, tracker):
        """Test getting a nonexistent trace."""
        trace = tracker.get_trace("nonexistent")
        assert trace is None

    def test_add_thought(self, tracker, trace_id, sample_trace):
        """Test adding a thought step."""
        step = tracker.add_thought(
            trace_id=trace_id,
            turn=1,
            thought="我需要分析这个 IP",
            confidence=0.8,
        )

        assert step is not None
        assert step.step_id == 1
        assert step.turn == 1
        assert step.decision_type == DecisionType.THOUGHT
        assert step.content == "我需要分析这个 IP"
        assert step.confidence == 0.8

    def test_add_action(self, tracker, trace_id, sample_trace):
        """Test adding an action step."""
        step = tracker.add_action(
            trace_id=trace_id,
            turn=1,
            tool_name="ip_threat_analysis",
            tool_input={"ip": "192.168.1.1"},
            confidence=0.9,
        )

        assert step is not None
        assert step.step_id == 1
        assert step.turn == 1
        assert step.decision_type == DecisionType.ACTION
        assert "ip_threat_analysis" in step.content
        assert len(step.evidence) == 1
        assert step.evidence[0].tool_name == "ip_threat_analysis"

    def test_add_observation(self, tracker, trace_id, sample_trace):
        """Test adding an observation step."""
        tool_output = {
            "success": True,
            "data": {"ip": "192.168.1.1", "threat_score": 75},
            "confidence": 0.85,
        }

        step = tracker.add_observation(
            trace_id=trace_id,
            turn=1,
            tool_name="ip_threat_analysis",
            tool_output=tool_output,
            duration_ms=1500,
        )

        assert step is not None
        assert step.step_id == 1
        assert step.turn == 1
        assert step.decision_type == DecisionType.OBSERVATION
        assert step.duration_ms == 1500
        assert len(step.evidence) == 1
        assert step.evidence[0].tool_name == "ip_threat_analysis"

    def test_add_final_answer(self, tracker, trace_id, sample_trace):
        """Test adding a final answer."""
        evidence = [
            EvidenceItem(
                source="ip_threat_analysis",
                source_type="tool",
                content="IP 威胁评分 75/100",
                confidence=0.85,
                timestamp="2024-01-01T00:00:00",
                tool_name="ip_threat_analysis",
            )
        ]

        step = tracker.add_final_answer(
            trace_id=trace_id,
            answer="该 IP 存在中等威胁",
            confidence=0.85,
            evidence=evidence,
        )

        assert step is not None
        assert step.decision_type == DecisionType.FINAL_ANSWER

        trace = tracker.get_trace(trace_id)
        assert trace.final_answer == "该 IP 存在中等威胁"
        assert trace.final_confidence == 0.85
        assert trace.success is True

    def test_add_error(self, tracker, trace_id, sample_trace):
        """Test adding an error step."""
        step = tracker.add_error(
            trace_id=trace_id,
            turn=1,
            error="工具执行失败",
        )

        assert step is not None
        assert step.decision_type == DecisionType.ERROR
        assert step.content == "工具执行失败"
        assert step.confidence == 0.0

        trace = tracker.get_trace(trace_id)
        assert trace.error == "工具执行失败"

    def test_end_trace(self, tracker, trace_id, sample_trace):
        """Test ending a trace."""
        tracker.end_trace(trace_id, success=True)

        trace = tracker.get_trace(trace_id)
        assert trace.end_time is not None
        assert trace.success is True

    def test_end_trace_with_error(self, tracker, trace_id, sample_trace):
        """Test ending a trace with error."""
        tracker.end_trace(trace_id, success=False, error="测试错误")

        trace = tracker.get_trace(trace_id)
        assert trace.end_time is not None
        assert trace.success is False
        assert trace.error == "测试错误"

    def test_get_decision_chain(self, tracker, trace_id, sample_trace):
        """Test getting decision chain."""
        tracker.add_thought(trace_id=trace_id, turn=1, thought="思考1")
        tracker.add_action(trace_id=trace_id, turn=1, tool_name="tool1", tool_input={"key": "value"})
        tracker.add_observation(trace_id=trace_id, turn=1, tool_name="tool1", tool_output={"success": True})
        tracker.add_final_answer(trace_id=trace_id, answer="最终答案")

        chain = tracker.get_decision_chain(trace_id)
        assert len(chain) == 4
        assert chain[0]["type"] == "thought"
        assert chain[1]["type"] == "action"
        assert chain[2]["type"] == "observation"
        assert chain[3]["type"] == "final_answer"

    def test_get_evidence_summary(self, tracker, trace_id, sample_trace):
        """Test getting evidence summary."""
        tracker.add_action(
            trace_id=trace_id,
            turn=1,
            tool_name="tool1",
            tool_input={"key": "value"},
        )
        tracker.add_observation(
            trace_id=trace_id,
            turn=1,
            tool_name="tool1",
            tool_output={"success": True, "data": {"result": "test"}},
        )

        evidence = tracker.get_evidence_summary(trace_id)
        assert len(evidence) >= 1

    def test_export_json(self, tracker, trace_id, sample_trace):
        """Test exporting JSON report."""
        tracker.add_thought(trace_id=trace_id, turn=1, thought="思考1")
        tracker.add_final_answer(trace_id=trace_id, answer="最终答案", confidence=0.9)
        tracker.end_trace(trace_id, success=True)

        report = tracker.export_audit_report(trace_id, fmt="json")
        assert report is not None

        report_data = json.loads(report)
        assert report_data["trace_id"] == trace_id
        assert report_data["success"] is True
        assert len(report_data["steps"]) >= 2

    def test_export_markdown(self, tracker, trace_id, sample_trace):
        """Test exporting Markdown report."""
        tracker.add_thought(trace_id=trace_id, turn=1, thought="思考1")
        tracker.add_final_answer(trace_id=trace_id, answer="最终答案", confidence=0.9)
        tracker.end_trace(trace_id, success=True)

        report = tracker.export_audit_report(trace_id, fmt="markdown")
        assert report is not None
        assert "# 决策审计报告" in report
        assert "最终答案" in report


class TestConfidenceLevel:
    """Tests for confidence level classification."""

    def test_very_high_confidence(self):
        """Test very high confidence level."""
        tracker = DecisionTracker()
        level = tracker._get_confidence_level(0.95)
        assert level == ConfidenceLevel.VERY_HIGH.value

    def test_high_confidence(self):
        """Test high confidence level."""
        tracker = DecisionTracker()
        level = tracker._get_confidence_level(0.8)
        assert level == ConfidenceLevel.HIGH.value

    def test_medium_confidence(self):
        """Test medium confidence level."""
        tracker = DecisionTracker()
        level = tracker._get_confidence_level(0.6)
        assert level == ConfidenceLevel.MEDIUM.value

    def test_low_confidence(self):
        """Test low confidence level."""
        tracker = DecisionTracker()
        level = tracker._get_confidence_level(0.4)
        assert level == ConfidenceLevel.LOW.value

    def test_very_low_confidence(self):
        """Test very low confidence level."""
        tracker = DecisionTracker()
        level = tracker._get_confidence_level(0.2)
        assert level == ConfidenceLevel.VERY_LOW.value


class TestEvidenceItem:
    """Tests for EvidenceItem class."""

    def test_evidence_creation(self):
        """Test creating an evidence item."""
        evidence = EvidenceItem(
            source="test_source",
            source_type="tool",
            content="test content",
            confidence=0.8,
            timestamp="2024-01-01T00:00:00",
            tool_name="test_tool",
            tool_input={"key": "value"},
            tool_output={"result": "test"},
        )

        assert evidence.source == "test_source"
        assert evidence.source_type == "tool"
        assert evidence.content == "test content"
        assert evidence.confidence == 0.8
        assert evidence.tool_name == "test_tool"


class TestIntegration:
    """Integration tests for decision trace."""

    def test_full_decision_flow(self, tracker, trace_id):
        """Test a complete decision flow."""
        # Start trace
        tracker.start_trace(
            trace_id=trace_id,
            session_id="session_123",
            user_id="user_123",
            tenant_id="tenant_123",
            query="分析 IP 192.168.1.1 的威胁",
        )

        # Add thought
        tracker.add_thought(
            trace_id=trace_id,
            turn=1,
            thought="用户要求分析 IP 威胁，我需要调用 ip_threat_analysis 工具",
            confidence=0.9,
        )

        # Add action
        tracker.add_action(
            trace_id=trace_id,
            turn=1,
            tool_name="ip_threat_analysis",
            tool_input={"ip": "192.168.1.1"},
            confidence=0.9,
        )

        # Add observation
        tracker.add_observation(
            trace_id=trace_id,
            turn=1,
            tool_name="ip_threat_analysis",
            tool_output={
                "success": True,
                "data": {"ip": "192.168.1.1", "threat_score": 75, "country": "CN"},
                "confidence": 0.85,
            },
            duration_ms=1500,
        )

        # Add final answer
        tracker.add_final_answer(
            trace_id=trace_id,
            answer="IP 192.168.1.1 存在中等威胁，威胁评分 75/100，位于中国",
            confidence=0.85,
        )

        # End trace
        tracker.end_trace(trace_id, success=True)

        # Verify trace
        trace = tracker.get_trace(trace_id)
        assert trace.success is True
        assert trace.final_answer is not None
        assert len(trace.steps) == 4

        # Verify decision chain
        chain = tracker.get_decision_chain(trace_id)
        assert len(chain) == 4
        assert chain[0]["type"] == "thought"
        assert chain[1]["type"] == "action"
        assert chain[2]["type"] == "observation"
        assert chain[3]["type"] == "final_answer"

        # Verify JSON export
        json_report = tracker.export_audit_report(trace_id, fmt="json")
        assert json_report is not None
        report_data = json.loads(json_report)
        assert report_data["success"] is True

        # Verify Markdown export
        md_report = tracker.export_audit_report(trace_id, fmt="markdown")
        assert md_report is not None
        assert "# 决策审计报告" in md_report
