"""Tests for context compression."""

import pytest

from app.agent.context_compressor import (
    compact_tool_observation,
    truncate_observation,
    should_compress,
    compress_history,
    estimate_tokens,
)


class TestTruncateObservation:
    def test_short_observation_unchanged(self):
        obs = '{"result": "ok"}'
        result = truncate_observation(obs, max_tokens=100)
        assert result == obs

    def test_long_observation_truncated(self):
        obs = "x " * 5000  # ~5000 tokens
        result = truncate_observation(obs, max_tokens=100)
        assert len(result) < len(obs)
        assert "[TRUNCATED]" in result

    def test_preserves_structure_on_truncation(self):
        obs = '{"data": "' + "x" * 10000 + '", "summary": "test"}'
        result = truncate_observation(obs, max_tokens=50)
        assert "[TRUNCATED]" in result


class TestCompactToolObservation:
    def test_pcap_observation_preserves_all_anomalies_without_truncated_marker(self):
        tool_result = {
            "success": True,
            "tool_name": "pcap_analysis",
            "tool_version": "v1",
            "confidence": 0.7,
            "evidence_source": ["tshark_pcap_analysis"],
            "execution_time_ms": 100,
            "data": {
                "source_path": "/tmp/e924c952d6234783a5ba19e86b4a201f.pcap",
                "display_filename": "e924c952d6234783a5ba19e86b4a201f.pcap",
                "summary": {"total_packets": 10000, "anomaly_count": 7},
                "anomalies": [
                    {"type": "port_scan", "severity": "high", "detail": f"异常 {i}"}
                    for i in range(7)
                ],
                "flows": [{"src_ip": "10.0.0.1", "payload": "x" * 1000} for _ in range(100)],
                "timeline": [{"detail": "x" * 1000} for _ in range(100)],
                "external_ips_for_lookup": ["23.227.199.38"],
                "domains_for_lookup": ["example.com"],
            },
        }

        result = compact_tool_observation(tool_result, max_tokens=800)

        assert "[TRUNCATED]" not in result
        assert "e924c952d6234783a5ba19e86b4a201f.pcap" in result
        assert '"anomalies_complete": true' in result
        assert result.count('"type": "port_scan"') == 7
        assert "不得声称异常列表被截断" in result
        assert '"time_basis": "unknown"' in result
        assert "不得编造未在工具结果中出现的主机 IP" in result
        assert "必须区分已确认事实与推断" in result

    def test_cve_catalog_observation_is_structured(self):
        tool_result = {
            "success": True,
            "tool_name": "cve_catalog",
            "tool_version": "v1",
            "confidence": 0.95,
            "evidence_source": ["kb_public_all_v1", "source_type:cve", "source_type:kev"],
            "execution_time_ms": 42,
            "data": {
                "query": "2024 CVSS 10.0 KEV",
                "filters": {"year": 2024, "cvss_score": 10.0, "kev_only": True},
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
                    }
                ],
            },
        }

        result = compact_tool_observation(tool_result, max_tokens=800)

        assert "\"tool_name\": \"cve_catalog\"" in result
        assert "\"summary_text\": \"筛选条件: year=2024" in result
        assert "\"kev_hit_rate\": 1.0" in result
        assert "CVE-2024-0001" in result
        assert "\"evidence\"" in result
        assert "必须优先使用 summary_text 和 stats 总结结果" in result

    def test_cve_catalog_observation_handles_string_data(self):
        tool_result = {
            "success": True,
            "tool_name": "cve_catalog",
            "tool_version": "v1",
            "confidence": 0.0,
            "evidence_source": [],
            "execution_time_ms": 1,
            "data": "unexpected string payload",
        }

        result = compact_tool_observation(tool_result, max_tokens=500)

        assert "unexpected string payload" not in result
        assert "\"tool_name\": \"cve_catalog\"" in result

    def test_non_pcap_observation_uses_generic_truncation(self):
        tool_result = {
            "success": True,
            "tool_name": "echo",
            "data": {"payload": "x" * 2000},
        }

        result = compact_tool_observation(tool_result, max_tokens=50)

        assert "[TRUNCATED]" in result


class TestShouldCompress:
    def test_below_threshold(self):
        assert should_compress(message_count=3, interval=4) is False

    def test_at_threshold(self):
        assert should_compress(message_count=8, interval=4) is True

    def test_boundary(self):
        assert should_compress(message_count=4, interval=4) is True


class TestEstimateTokens:
    def test_empty(self):
        assert estimate_tokens("") == 0

    def test_english(self):
        tokens = estimate_tokens("hello world")
        assert 1 <= tokens <= 3

    def test_json(self):
        tokens = estimate_tokens('{"key": "value"}')
        assert tokens > 0


class TestCompressHistory:
    def test_compress_preserves_leading_system_prompt(self):
        messages = [
            {"role": "system", "content": "SYSTEM PROMPT"},
            {"role": "user", "content": "q1"},
            {"role": "assistant", "content": "a1"},
            {"role": "user", "content": "q2"},
            {"role": "assistant", "content": "a2"},
            {"role": "user", "content": "q3"},
            {"role": "assistant", "content": "a3"},
        ]

        result = compress_history(messages, keep_recent=2)

        assert result[0] == {"role": "system", "content": "SYSTEM PROMPT"}
        assert result[1]["role"] == "assistant"
        assert "历史对话摘要" in result[1]["content"]
        assert result[-2]["content"] == "q3"
        assert result[-1]["content"] == "a3"

    def test_compress_preserves_recent(self):
        messages = [
            {"role": "user", "content": "q1"},
            {"role": "assistant", "content": "a1"},
            {"role": "user", "content": "q2"},
            {"role": "assistant", "content": "a2"},
            {"role": "user", "content": "q3"},
            {"role": "assistant", "content": "a3"},
        ]
        result = compress_history(messages, keep_recent=2)
        # Should have summary + last 2 messages
        assert len(result) >= 2
        assert result[-1]["content"] == "a3"
        assert result[-2]["content"] == "q3"

    def test_compress_short_list_unchanged(self):
        messages = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]
        result = compress_history(messages, keep_recent=4)
        assert len(result) == 2
