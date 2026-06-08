"""Tests for CVE Lookup Tool."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.tools.cve_tool import CVELookupTool, CVEInput


@pytest.fixture
def tool():
    return CVELookupTool()


def test_tool_properties(tool):
    assert tool.name == "cve_lookup"
    assert tool.version == "v1"


def test_tool_schema(tool):
    schema = tool.get_schema()
    assert schema["function"]["name"] == "cve_lookup"
    params = schema["function"]["parameters"]
    assert "cve_id" in params["properties"]
    assert "cve_id" in params["required"]


def test_input_class(tool):
    assert tool.input_class == CVEInput


@pytest.mark.anyio
async def test_execute_with_valid_cve(tool):
    """Test with mocked NVD API response."""
    mock_nvd_response = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-3400",
                "descriptions": [{
                    "lang": "en",
                    "value": "A critical vulnerability in Palo Alto Networks PAN-OS software."
                }],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 10.0,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                        }
                    }]
                },
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{
                            "criteria": "cpe:2.3:o:paloaltonetworks:pan-os:11.1.0:*:*:*:*:*:*:*",
                            "vulnerable": True
                        }]
                    }]
                }],
                "references": [
                    {"url": "https://security.paloaltonetworks.com/CVE-2024-3400"}
                ]
            }
        }]
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_nvd_response
    mock_response.raise_for_status = MagicMock()

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    with patch("app.tools.cve_tool._get_redis", return_value=mock_redis), \
         patch("httpx.AsyncClient.get", return_value=mock_response):
        result = await tool.execute(CVEInput(
            cve_id="CVE-2024-3400",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["cve_id"] == "CVE-2024-3400"
    assert result.data["cvss_score"] == 10.0
    assert result.data["severity"] == "CRITICAL"
    assert "Palo Alto" in result.data["description"]
    assert result.confidence == 1.0
    assert "nvd.nist.gov" in result.evidence_source


@pytest.mark.anyio
async def test_execute_with_not_found(tool):
    """Test CVE not found in NVD."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"vulnerabilities": []}
    mock_response.raise_for_status = MagicMock()

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    with patch("app.tools.cve_tool._get_redis", return_value=mock_redis), \
         patch("httpx.AsyncClient.get", return_value=mock_response):
        result = await tool.execute(CVEInput(
            cve_id="CVE-9999-99999",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["found"] is False
    assert result.confidence == 0.0


@pytest.mark.anyio
async def test_execute_with_api_error(tool):
    """Test NVD API error handling."""
    import httpx

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    with patch("app.tools.cve_tool._get_redis", return_value=mock_redis), \
         patch("httpx.AsyncClient.get", side_effect=httpx.HTTPStatusError(
             "Server Error", request=MagicMock(), response=MagicMock(status_code=503)
         )):
        result = await tool.execute(CVEInput(
            cve_id="CVE-2024-3400",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is False
    assert result.error is not None


@pytest.mark.anyio
async def test_execute_with_cache_hit(tool):
    """Test Redis cache hit."""
    cached_data = json.dumps({
        "cve_id": "CVE-2024-3400",
        "description": "Cached result",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected_products": [],
        "references": [],
        "found": True,
    })

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=cached_data)

    with patch("app.tools.cve_tool._get_redis", return_value=mock_redis):
        result = await tool.execute(CVEInput(
            cve_id="CVE-2024-3400",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["description"] == "Cached result"
    assert "cache" in result.evidence_source
