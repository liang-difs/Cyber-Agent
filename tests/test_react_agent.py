"""Tests for ReAct agent loop."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from app.agent.react import ReActAgent, ReActResult, _extract_json_string_prefix
from app.governance.tool_protocol import ToolResult
from app.tools.web_search_tool import WebSearchInput
from app.tools.cve_catalog_tool import CVECatalogInput
from app.tools.registry import ToolRegistry


def make_mock_llm(responses: list[str]):
    """Create a mock LLM router that returns sequential responses."""
    call_count = 0

    async def mock_complete(request):
        nonlocal call_count
        resp_text = responses[call_count]
        call_count += 1
        mock_resp = MagicMock()
        mock_resp.content = resp_text
        mock_resp.tool_calls = []
        mock_resp.model = "test-model"
        mock_resp.usage = {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}
        mock_resp.latency_ms = 100
        mock_resp.trace_id = request.trace_id
        mock_resp.reasoning_content = None
        return mock_resp

    router = MagicMock()
    router.complete = AsyncMock(side_effect=mock_complete)
    return router


def make_streaming_llm(chunks: list[str]):
    async def mock_stream(request):
        for chunk in chunks:
            yield {"content": chunk, "reasoning_content": "", "model": "test-model"}

    router = MagicMock()
    router.stream = mock_stream
    return router


@pytest.fixture
def registry():
    reg = ToolRegistry()
    from app.tools.echo_tool import echo_tool
    reg.register(echo_tool)
    return reg


@pytest.fixture
def registry_with_web_search():
    class MockWebSearchTool:
        name = "web_search"
        version = "v1"
        input_class = WebSearchInput

        def get_schema(self):
            return {
                "type": "function",
                "function": {
                    "name": "web_search",
                    "description": "mock web search",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "max_results": {"type": "integer"},
                        },
                        "required": ["query"],
                    },
                },
            }

        async def execute(self, input_data):
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data={
                    "query": input_data.query,
                    "count": 2,
                    "results": [
                        {
                            "title": "CTU-13: A Perspective on Network Traffic Datasets for Classification",
                            "snippet": "A widely cited benchmark paper for network traffic classification datasets.",
                            "url": "https://example.org/ctu-13",
                        },
                        {
                            "title": "ISCX VPN-nonVPN Traffic Dataset",
                            "snippet": "A common benchmark used in traffic classification research.",
                            "url": "https://example.org/iscx",
                        },
                    ],
                },
                confidence=0.9,
                evidence_source=["ddg://mock"],
                trace_id=input_data.trace_id,
                execution_time_ms=10,
            )

    reg = ToolRegistry()
    reg.register(MockWebSearchTool())
    return reg


@pytest.fixture
def registry_with_irrelevant_web_search():
    class MockWebSearchTool:
        name = "web_search"
        version = "v1"
        input_class = WebSearchInput

        def get_schema(self):
            return {
                "type": "function",
                "function": {
                    "name": "web_search",
                    "description": "mock irrelevant web search",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "max_results": {"type": "integer"},
                        },
                        "required": ["query"],
                    },
                },
            }

        async def execute(self, input_data):
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data={
                    "query": input_data.query,
                    "count": 3,
                    "results": [
                        {
                            "title": "Microsoft account | Sign In or Create Your Account Today",
                            "snippet": "Access and manage your Microsoft account, subscriptions, and settings.",
                            "url": "https://account.microsoft.com/account",
                        },
                        {
                            "title": "Sign in to your account — Microsoft",
                            "snippet": "Access and manage your account settings all in one place.",
                            "url": "https://myaccount.microsoft.com/",
                        },
                        {
                            "title": "Office 365 login — Microsoft",
                            "snippet": "Collaborate with online versions of Word, PowerPoint, Excel, and OneNote.",
                            "url": "https://www.office.com/",
                        },
                    ],
                },
                confidence=0.9,
                evidence_source=["ddg://mock"],
                trace_id=input_data.trace_id,
                execution_time_ms=10,
            )

    reg = ToolRegistry()
    reg.register(MockWebSearchTool())
    return reg


@pytest.fixture
def registry_with_cve_catalog():
    class MockCVECatalogTool:
        name = "cve_catalog"
        version = "v1"
        input_class = CVECatalogInput

        def get_schema(self):
            return {
                "type": "function",
                "function": {
                    "name": "cve_catalog",
                    "description": "mock cve catalog",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "year": {"type": "integer"},
                            "cvss_score": {"type": "number"},
                            "kev_only": {"type": "boolean"},
                            "limit": {"type": "integer"},
                        },
                        "required": [],
                    },
                },
            }

        async def execute(self, input_data):
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data={
                    "query": input_data.query or "2024 CVSS 10.0 KEV",
                    "filters": {
                        "query": input_data.query or "2024 CVSS 10.0 KEV",
                        "year": input_data.year,
                        "cvss_score": input_data.cvss_score,
                        "kev_only": input_data.kev_only,
                        "severity": input_data.severity,
                        "keyword": input_data.keyword,
                    },
                    "summary_text": "筛选条件: year=2024, cvss=10.0, kev_only=True；CVE 总数 3，KEV 总数 2，命中 2 条。",
                    "total_cve_docs": 3,
                    "total_kev_docs": 2,
                    "matched_count": 2,
                    "kev_count": 2,
                    "returned_count": 2,
                    "returned_kev_count": 2,
                    "evidence": [
                        {
                            "cve_id": "CVE-2024-0001",
                            "source_type": "cve",
                            "source_path": "corpus/nvd_full/nvd_high.jsonl",
                            "doc_id": "cve-1",
                            "key_dates": {"published": "2024-01-10T00:00:00Z"},
                            "note": "CVE one",
                        },
                        {
                            "cve_id": "CVE-2024-0001",
                            "source_type": "kev",
                            "source_path": "attack/intel_raw/kev.csv",
                            "doc_id": "kev-1",
                            "key_dates": {"kev_date": "2024-04-01"},
                            "note": "Vendor A",
                        },
                    ],
                    "stats": {
                        "matched_count": 2,
                        "kev_count": 2,
                        "kev_hit_rate": 1.0,
                        "by_year": {"2024": 2},
                        "by_severity": {"CRITICAL": 2},
                        "kev_by_year": {"2024": 2},
                        "kev_by_severity": {"CRITICAL": 2},
                        "coverage": {"total_cve_docs": 3, "total_kev_docs": 2, "kev_doc_coverage": 0.6667},
                    },
                    "items": [
                        {
                            "cve_id": "CVE-2024-0001",
                            "title": "CVE one",
                            "published": "2024-01-10T00:00:00Z",
                            "cvss_score": 10.0,
                            "severity": "CRITICAL",
                            "is_kev": True,
                            "kev_date": "2024-04-01",
                            "vendor": "Vendor A",
                            "product": "Product A",
                            "source_path": "corpus/nvd_full/nvd_high.jsonl",
                        },
                    ],
                },
                confidence=0.95,
                evidence_source=["kb_public_all_v1", "source_type:cve", "source_type:kev"],
                trace_id=input_data.trace_id,
                execution_time_ms=10,
            )

    reg = ToolRegistry()
    reg.register(MockCVECatalogTool())
    return reg


@pytest.mark.anyio
async def test_react_direct_answer(registry):
    """Agent gives direct answer without tool calls."""
    llm = make_mock_llm([
        json.dumps({"final_answer": "Hello!", "confidence": 0.95, "evidence": ["direct"]}),
    ])

    agent = ReActAgent(llm_router=llm, tool_registry=registry, max_turns=5)
    result = await agent.run(
        messages=[{"role": "user", "content": "Hi"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.success is True
    assert "Hello!" in result.final_answer
    assert result.turns_used == 1


def test_extract_json_string_prefix_from_incomplete_json():
    partial = '{"final_answer": "第一段内容'
    assert _extract_json_string_prefix(partial, "final_answer") == "第一段内容"


def test_extract_json_string_prefix_decodes_escapes():
    partial = '{"final_answer": "line1\\nline2 \\u4f60\\u597d'
    assert _extract_json_string_prefix(partial, "final_answer") == "line1\nline2 你好"


@pytest.mark.anyio
async def test_run_streaming_emits_final_answer_before_json_complete(registry):
    chunks = [
        '{"final_answer": "第一段',
        '，第二段',
        '，第三段", "confidence": 0.9, "evidence": []}',
    ]
    llm = make_streaming_llm(chunks)
    agent = ReActAgent(llm_router=llm, tool_registry=registry, max_turns=2)

    emitted: list[str] = []
    async for event in agent.run_streaming(
        messages=[{"role": "user", "content": "测试流式输出"}],
        tenant_id="test",
        trace_id="stream-trace",
    ):
        if event.type == "answer_token":
            emitted.append(event.content)

    assert emitted == ["第一段", "，第二段", "，第三段"]


@pytest.mark.anyio
async def test_run_streaming_emits_usage_event(registry):
    llm = make_streaming_llm([
        '{"final_answer": "完成", "confidence": 0.9, "evidence": []}',
    ])
    agent = ReActAgent(llm_router=llm, tool_registry=registry, max_turns=2)

    usage_events = []
    async for event in agent.run_streaming(
        messages=[{"role": "user", "content": "统计 token"}],
        tenant_id="test",
        trace_id="usage-trace",
    ):
        if event.type == "usage":
            usage_events.append(event.content)

    assert usage_events
    assert usage_events[-1]["total_tokens"] > 0


@pytest.mark.anyio
async def test_react_tool_call_then_answer(registry):
    """Agent calls a tool then gives final answer."""
    llm = make_mock_llm([
        json.dumps({"thought": "I should echo", "action": "echo", "action_input": {"message": "test"}}),
        json.dumps({"final_answer": "Echoed: test", "confidence": 1.0, "evidence": ["echo_tool"]}),
    ])

    agent = ReActAgent(llm_router=llm, tool_registry=registry, max_turns=5)
    result = await agent.run(
        messages=[{"role": "user", "content": "Echo test"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.success is True
    assert result.turns_used == 2
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["tool"] == "echo"


@pytest.mark.anyio
async def test_react_max_turns(registry):
    """Agent stops at max turns when LLM keeps calling different tools."""
    # Use different inputs each turn to avoid dedup
    tool_calls = [
        json.dumps({"thought": "loop1", "action": "echo", "action_input": {"message": f"x{i}"}})
        for i in range(10)
    ]
    llm = make_mock_llm(tool_calls)

    agent = ReActAgent(llm_router=llm, tool_registry=registry, max_turns=3)
    result = await agent.run(
        messages=[{"role": "user", "content": "loop"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.turns_used == 3
    assert result.success is True


@pytest.mark.anyio
async def test_react_handles_malformed_json(registry):
    """Agent handles LLM output that isn't clean JSON."""
    llm = make_mock_llm([
        "Sure! Let me think...\n```json\n{\"thought\": \"analyzing\", \"action\": \"echo\", \"action_input\": {\"message\": \"hi\"}}\n```",
        json.dumps({"final_answer": "Done", "confidence": 0.8, "evidence": []}),
    ])

    agent = ReActAgent(llm_router=llm, tool_registry=registry, max_turns=5)
    result = await agent.run(
        messages=[{"role": "user", "content": "test"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.success is True
    assert result.turns_used == 2


@pytest.mark.anyio
async def test_react_web_search_single_shot_fallback(registry_with_web_search):
    """Agent should stop repeated web_search loops and synthesize from the first result."""
    llm = make_mock_llm([
        json.dumps({"thought": "先联网搜索", "action": "web_search", "action_input": {"query": "network traffic classification datasets"}}),
        json.dumps({"thought": "我想继续搜", "action": "web_search", "action_input": {"query": "best benchmark datasets 2026"}}),
    ])

    agent = ReActAgent(llm_router=llm, tool_registry=registry_with_web_search, max_turns=5)
    result = await agent.run(
        messages=[{"role": "user", "content": "网络流量分类领域最新的权威数据集有哪些"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.success is True
    assert result.turns_used == 2
    assert len(result.tool_calls) == 1
    assert "联网搜索结果摘要" in result.final_answer
    assert "CTU-13" in result.final_answer


@pytest.mark.anyio
async def test_react_web_search_irrelevant_results_short_circuit(registry_with_irrelevant_web_search):
    """Agent should not summarize obviously irrelevant web search results as evidence."""
    llm = make_mock_llm([
        json.dumps({"thought": "先联网搜索", "action": "web_search", "action_input": {"query": "个人开发的软件是否能申请软件著作权"}}),
        json.dumps({"final_answer": "这不该被用到", "confidence": 0.9, "evidence": []}),
    ])

    agent = ReActAgent(llm_router=llm, tool_registry=registry_with_irrelevant_web_search, max_turns=5)
    result = await agent.run(
        messages=[{"role": "user", "content": "个人开发的网络安全Agent项目是否能够申请软著？"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.success is True
    assert result.turns_used == 1
    assert len(result.tool_calls) == 1
    assert "相关性不足" in result.final_answer
    assert "Microsoft" not in result.final_answer


@pytest.mark.anyio
async def test_react_cve_catalog_single_shot_fallback(registry_with_cve_catalog):
    """Agent should synthesize structured catalog results when the same query repeats."""
    llm = make_mock_llm([
        json.dumps({"thought": "先查 catalog", "action": "cve_catalog", "action_input": {"query": "2024 CVSS 10.0 KEV", "year": 2024, "cvss_score": 10.0, "kev_only": True}}),
        json.dumps({"thought": "我再查一次", "action": "cve_catalog", "action_input": {"query": "2024 CVSS 10.0 KEV", "year": 2024, "cvss_score": 10.0, "kev_only": True}}),
    ])

    agent = ReActAgent(llm_router=llm, tool_registry=registry_with_cve_catalog, max_turns=5)
    result = await agent.run(
        messages=[{"role": "user", "content": "帮我找出 2024 年 CVSS 10.0 且进入 KEV 的漏洞"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.success is True
    assert result.turns_used == 2
    assert len(result.tool_calls) == 1
    assert "CVE / KEV 结构化查询结果" in result.final_answer
    assert "| CVE | doc_id | 披露时间 | CVSS | 严重级别 | KEV | KEV 日期 | 厂商 | 产品 | 来源 |" in result.final_answer
    assert "## 证据" in result.final_answer
    assert "来源类型" in result.final_answer
    assert "命中总数：2" in result.final_answer
    assert "KEV 命中率：1.0" in result.final_answer


@pytest.mark.anyio
async def test_react_cve_catalog_handles_string_data_gracefully(registry_with_cve_catalog):
    llm = make_mock_llm([
        json.dumps({"thought": "先查 catalog", "action": "cve_catalog", "action_input": {"query": "2024 CVSS 10.0 KEV", "year": 2024, "cvss_score": 10.0, "kev_only": True}}),
        json.dumps({"final_answer": "Recovered", "confidence": 0.8, "evidence": ["safe_fallback"]}),
    ])

    class BrokenCVECatalogTool:
        name = "cve_catalog"
        version = "v1"
        input_class = CVECatalogInput

        def get_schema(self):
            return registry_with_cve_catalog.get("cve_catalog").get_schema()

    reg = ToolRegistry()
    reg.register(BrokenCVECatalogTool())
    reg.execute = AsyncMock(return_value={
        "success": True,
        "tool_name": "cve_catalog",
        "tool_version": "v1",
        "data": "unexpected string payload",
        "confidence": 0.0,
        "evidence_source": [],
        "trace_id": "test-trace",
        "execution_time_ms": 1,
    })

    agent = ReActAgent(llm_router=llm, tool_registry=reg, max_turns=3)
    result = await agent.run(
        messages=[{"role": "user", "content": "帮我查 2024 年 CVSS 10.0 且 KEV 的漏洞"}],
        tenant_id="test",
        trace_id="test-trace",
    )

    assert result.success is True
    assert result.turns_used == 2
    assert result.final_answer == "Recovered"
