"""Tests for IP Threat Analysis Tool."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.tools.ip_tool import IPThreatTool, IPThreatInput


@pytest.fixture
def tool():
    return IPThreatTool()


def test_tool_properties(tool):
    assert tool.name == "ip_threat_analysis"
    assert tool.version == "v1"


def test_tool_schema(tool):
    schema = tool.get_schema()
    assert schema["function"]["name"] == "ip_threat_analysis"
    params = schema["function"]["parameters"]
    assert "ip" in params["properties"]
    assert "ip" in params["required"]


def test_input_class(tool):
    assert tool.input_class == IPThreatInput


@pytest.mark.anyio
async def test_execute_with_geoip_only(tool):
    """Test with only GeoIP (no AbuseIPDB key)."""
    mock_geo = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "city": "New York",
        "isp": "Google LLC",
        "as": "AS15169 Google LLC",
        "lat": 40.7128,
        "lon": -74.006,
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_geo
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", return_value=mock_response), \
         patch("app.tools.ip_tool._get_redis", return_value=None), \
         patch("app.tools.ip_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            abuseipdb_api_key="",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IPThreatInput(
            ip="8.8.8.8",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["ip"] == "8.8.8.8"
    assert result.data["geo"]["country"] == "United States"
    assert result.data["geo"]["isp"] == "Google LLC"
    assert result.data["risk_score"] == 0
    assert result.data["found"] is True


@pytest.mark.anyio
async def test_execute_with_both_sources(tool):
    """Test with both GeoIP and AbuseIPDB."""
    mock_geo = {
        "status": "success",
        "country": "Russia",
        "countryCode": "RU",
        "city": "Moscow",
        "isp": "Evil Corp",
        "as": "AS12345 Evil Corp",
        "lat": 55.7558,
        "lon": 37.6173,
    }
    mock_abuse = {
        "data": {
            "abuseConfidenceScore": 85,
            "totalReports": 1234,
            "lastReportedAt": "2024-01-15T10:30:00Z",
            "usageType": "Data Center/Web Hosting",
            "isWhitelisted": False,
        }
    }

    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        if "ip-api" in url:
            resp.json.return_value = mock_geo
        else:
            resp.json.return_value = mock_abuse
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("app.tools.ip_tool._get_redis", return_value=None), \
         patch("app.tools.ip_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            abuseipdb_api_key="test-key",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IPThreatInput(
            ip="1.2.3.4",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["abuse"]["abuse_confidence_score"] == 85
    assert result.data["risk_score"] > 0
    assert result.data["risk_level"] in ["critical", "high", "medium", "low", "safe"]


@pytest.mark.anyio
async def test_execute_with_timeout(tool):
    """Test graceful degradation on timeout."""
    import httpx as httpx_mod

    with patch("httpx.AsyncClient.get", side_effect=httpx_mod.TimeoutException("timeout")), \
         patch("app.tools.ip_tool._get_redis", return_value=None), \
         patch("app.tools.ip_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            abuseipdb_api_key="test-key",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IPThreatInput(
            ip="1.2.3.4",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is False
    assert result.error is not None


@pytest.mark.anyio
async def test_execute_with_cache_hit(tool):
    """Test Redis cache hit."""
    cached_data = json.dumps({
        "ip": "1.2.3.4",
        "geo": {"country": "US"},
        "abuse": {},
        "risk_score": 50,
        "risk_level": "medium",
        "found": True,
    })

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=cached_data)

    with patch("app.tools.ip_tool._get_redis", return_value=mock_redis):
        result = await tool.execute(IPThreatInput(
            ip="1.2.3.4",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["risk_score"] == 50
    assert "cache" in result.evidence_source


def test_risk_level(tool):
    assert tool._risk_level(90) == "critical"
    assert tool._risk_level(70) == "high"
    assert tool._risk_level(50) == "medium"
    assert tool._risk_level(30) == "low"
    assert tool._risk_level(10) == "safe"


@pytest.mark.anyio
async def test_execute_cache_provides_structured_evidence(tool):
    """Cached data should be augmented with structured evidence entries."""
    cached_data = json.dumps({
        "ip": "1.2.3.4",
        "geo": {"country": "US"},
        "abuse": {},
        "risk_score": 50,
        "risk_level": "medium",
        "found": True,
    })

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=cached_data)

    with patch("app.tools.ip_tool._get_redis", return_value=mock_redis):
        result = await tool.execute(IPThreatInput(
            ip="1.2.3.4",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert isinstance(result.data.get("evidence"), list)
    ev = result.data.get("evidence")[0]
    assert ev.get("source_type") == "cache"
    assert "doc_id" in ev and ev.get("doc_id")
    assert "source_path" in ev and ev.get("source_path")
    assert isinstance(ev.get("key_dates"), dict)
