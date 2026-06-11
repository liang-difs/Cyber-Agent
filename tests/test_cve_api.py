"""Tests for CVE REST API."""

from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def mock_bm25():
    """Mock BM25Search with sample data."""
    mock = MagicMock()
    mock.count = 2
    mock.list_all.return_value = {
        "items": [
            {"id": "CVE-2024-0001", "cve_id": "CVE-2024-0001", "severity": "CRITICAL", "cvss_score": 9.8, "document": "RCE vuln"},
            {"id": "CVE-2024-0002", "cve_id": "CVE-2024-0002", "severity": "HIGH", "cvss_score": 7.5, "document": "SQL injection"},
        ],
        "total": 2,
        "page": 1,
        "page_size": 20,
    }
    mock.get_by_id.return_value = {
        "id": "CVE-2024-0001",
        "cve_id": "CVE-2024-0001",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "document": "Remote code execution vulnerability",
    }
    mock.stats.return_value = {
        "total": 2,
        "by_severity": {"CRITICAL": 1, "HIGH": 1},
        "recent": [
            {"id": "CVE-2024-0001", "severity": "CRITICAL", "cvss_score": 9.8, "published": "2024-01-01"},
        ],
    }
    return mock


@pytest.fixture
def client(mock_bm25):
    """Test client with mocked BM25."""
    with patch("app.api.cve._get_bm25", return_value=mock_bm25):
        from app.main import app
        yield TestClient(app)


class TestCveListAPI:
    def test_list_default(self, client):
        resp = client.get("/api/v1/cve/list")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert data["page"] == 1

    def test_list_with_severity_filter(self, client, mock_bm25):
        resp = client.get("/api/v1/cve/list?severity=CRITICAL")
        assert resp.status_code == 200
        mock_bm25.list_all.assert_called_once_with(page=1, page_size=20, severity="CRITICAL", keyword=None)

    def test_list_with_pagination(self, client, mock_bm25):
        resp = client.get("/api/v1/cve/list?page=2&page_size=10")
        assert resp.status_code == 200
        mock_bm25.list_all.assert_called_once_with(page=2, page_size=10, severity=None, keyword=None)


class TestCveDetailAPI:
    def test_get_existing_cve(self, client):
        resp = client.get("/api/v1/cve/CVE-2024-0001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2024-0001"
        assert data["severity"] == "CRITICAL"

    def test_get_nonexistent_cve(self, client, mock_bm25):
        mock_bm25.get_by_id.return_value = None
        resp = client.get("/api/v1/cve/CVE-9999-9999")
        assert resp.status_code == 404


class TestCveStatsAPI:
    def test_stats(self, client):
        resp = client.get("/api/v1/cve/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "by_severity" in data
        assert "recent" in data
