"""Tests for IoC Lookup Tool."""

import json
import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock

from app.tools.ioc_tool import IoCLookupTool, IoCInput, detect_ioc_type


@pytest.fixture
def tool():
    return IoCLookupTool()


def test_tool_properties(tool):
    assert tool.name == "ioc_lookup"
    assert tool.version == "v1"


def test_tool_schema(tool):
    schema = tool.get_schema()
    assert schema["function"]["name"] == "ioc_lookup"
    params = schema["function"]["parameters"]
    assert "value" in params["properties"]
    assert "value" in params["required"]
    assert "type" in params["properties"]


def test_input_class(tool):
    assert tool.input_class == IoCInput


def test_detect_type_ip():
    assert detect_ioc_type("192.168.1.1") == "ip"
    assert detect_ioc_type("8.8.8.8") == "ip"
    assert detect_ioc_type("2001:db8::1") == "ip"


def test_detect_type_domain():
    assert detect_ioc_type("evil.example.com") == "domain"
    assert detect_ioc_type("malware.org") == "domain"


def test_detect_type_hash():
    assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"  # MD5
    assert detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"  # SHA256


def test_detect_type_url():
    assert detect_ioc_type("https://evil.example.com/malware") == "url"
    assert detect_ioc_type("http://192.168.1.1/payload") == "url"


def test_detect_type_explicit():
    """Explicit type overrides auto-detection."""
    assert detect_ioc_type("192.168.1.1", explicit_type="ip") == "ip"
    assert detect_ioc_type("evil.com", explicit_type="domain") == "domain"


@pytest.mark.anyio
async def test_execute_with_otx_only(tool):
    """Test with only OTX configured (VT key empty)."""
    mock_otx_response = {
        "pulse_info": {"count": 5, "pulses": [{"name": "Malware C2", "tags": ["botnet"]}]},
        "reputation": 0,
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_otx_response
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", return_value=mock_response), \
         patch("app.tools.ioc_tool._get_redis", return_value=None), \
         patch("app.tools.ioc_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            otx_api_key="test-otx-key",
            vt_api_key="",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IoCInput(
            value="1.2.3.4",
            type="ip",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["ioc_value"] == "1.2.3.4"
    assert result.data["ioc_type"] == "ip"
    assert result.data["found"] is True
    assert len(result.data["sources"]) == 1
    assert result.data["sources"][0]["source"] == "otx"
    assert result.data["risk_score"] > 0


@pytest.mark.anyio
async def test_execute_with_both_sources(tool):
    """Test with both OTX and VT configured."""
    mock_otx = {
        "pulse_info": {"count": 10, "pulses": [{"name": "APT28", "tags": ["apt"]}]},
        "reputation": 0,
    }
    mock_vt = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 5,
                    "undetected": 50,
                    "harmless": 0,
                }
            }
        }
    }

    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        if "alienvault" in url:
            resp.json.return_value = mock_otx
        else:
            resp.json.return_value = mock_vt
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("app.tools.ioc_tool._get_redis", return_value=None), \
         patch("app.tools.ioc_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            otx_api_key="test-otx-key",
            vt_api_key="test-vt-key",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IoCInput(
            value="1.2.3.4",
            type="ip",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert len(result.data["sources"]) == 2
    assert result.data["risk_score"] > 0
    sources = {s["source"]: s for s in result.data["sources"]}
    assert "otx" in sources
    assert "virustotal" in sources


@pytest.mark.anyio
async def test_execute_with_timeout(tool):
    """Test graceful degradation when source times out."""
    with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("timeout")), \
         patch("app.tools.ioc_tool._get_redis", return_value=None), \
         patch("app.tools.ioc_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            otx_api_key="test-key",
            vt_api_key="test-key",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IoCInput(
            value="1.2.3.4",
            type="ip",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["found"] is False
    assert result.data["risk_score"] == 0


@pytest.mark.anyio
async def test_execute_with_cache_hit(tool):
    """Test Redis cache hit."""
    cached_data = json.dumps({
        "ioc_value": "1.2.3.4",
        "ioc_type": "ip",
        "risk_score": 72,
        "risk_level": "high",
        "sources": [{"source": "otx", "score": 72, "tags": [], "raw": {}}],
        "found": True,
    })

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=cached_data)

    with patch("app.tools.ioc_tool._get_redis", return_value=mock_redis):
        result = await tool.execute(IoCInput(
            value="1.2.3.4",
            type="ip",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["risk_score"] == 72
    assert "cache" in result.evidence_source


def test_risk_level_mapping(tool):
    """Test risk level thresholds."""
    assert tool._risk_level(90) == "critical"
    assert tool._risk_level(70) == "high"
    assert tool._risk_level(50) == "medium"
    assert tool._risk_level(30) == "low"
    assert tool._risk_level(10) == "safe"


@pytest.mark.anyio
async def test_execute_cache_provides_structured_evidence(tool):
    """Cached IoC results should include structured evidence entries."""
    cached_data = json.dumps({
        "ioc_value": "1.2.3.4",
        "ioc_type": "ip",
        "risk_score": 72,
        "risk_level": "high",
        "sources": [{"source": "otx", "score": 72, "tags": [], "raw": {}}],
        "found": True,
    })

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=cached_data)

    with patch("app.tools.ioc_tool._get_redis", return_value=mock_redis):
        result = await tool.execute(IoCInput(
            value="1.2.3.4",
            type="ip",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert isinstance(result.data.get("evidence"), list)
    ev = result.data.get("evidence")[0]
    assert ev.get("source_type") == "cache"
    assert ev.get("doc_id")
    assert ev.get("source_path")
    assert isinstance(ev.get("key_dates"), dict)
