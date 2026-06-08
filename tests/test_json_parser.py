"""Tests for 5-level fallback JSON parser."""

import pytest

from app.agent.json_parser import parse_llm_json


class TestParseLLMJson:
    """Test the 5-level fallback chain."""

    def test_level1_direct_json(self):
        raw = '{"thought": "test", "action": "echo"}'
        result = parse_llm_json(raw)
        assert result["thought"] == "test"
        assert result["action"] == "echo"

    def test_level2_code_block(self):
        raw = 'Here is my response:\n```json\n{"thought": "test", "action": "echo"}\n```\nDone.'
        result = parse_llm_json(raw)
        assert result["thought"] == "test"

    def test_level3_loose_braces(self):
        raw = 'Sure! {"thought": "analyzing", "action": "lookup"} is my plan.'
        result = parse_llm_json(raw)
        assert result["thought"] == "analyzing"

    def test_level4_fix_trailing_comma(self):
        raw = '{"thought": "test", "action": "echo",}'
        result = parse_llm_json(raw)
        assert result["action"] == "echo"

    def test_level4_fix_single_quotes(self):
        raw = "{'thought': 'test', 'action': 'echo'}"
        result = parse_llm_json(raw)
        assert result["thought"] == "test"

    def test_level4_fix_chinese_comments(self):
        raw = '{"thought": "test" /* 这是注释 */, "action": "echo"}'
        result = parse_llm_json(raw)
        assert result["action"] == "echo"

    def test_level5_fallback_error(self):
        raw = "This is not JSON at all, just plain text."
        result = parse_llm_json(raw)
        assert result["error"] == "parse_failed"
        assert "raw" in result

    def test_nested_json(self):
        raw = '{"thought": "test", "action_input": {"key": "value"}}'
        result = parse_llm_json(raw)
        assert result["action_input"]["key"] == "value"

    def test_final_answer_format(self):
        raw = '{"final_answer": "The IP is malicious", "confidence": 0.9}'
        result = parse_llm_json(raw)
        assert result["final_answer"] == "The IP is malicious"
        assert result["confidence"] == 0.9
