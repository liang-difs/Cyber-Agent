"""Tests for Phase 5-A multimodal tools."""

import os
import json
import tempfile
import zipfile
import pytest
import uuid
import asyncio

from app.tools.archive_tool import ArchiveAnalysisTool, ArchiveToolInput
from app.tools.api_doc_parser_tool import ApiDocParserTool, ApiDocParserInput
from app.tools.config_parser_tool import ConfigParserTool, ConfigParserInput
from app.tools.binary_analysis_tool import BinaryAnalysisTool, BinaryAnalysisInput
from app.tools.task_planner_tool import TaskPlannerTool, TaskPlannerInput


def run_async(coro):
    """Helper to run async functions in sync tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture
def trace_id():
    return str(uuid.uuid4())


@pytest.fixture
def tenant_id():
    return "test_tenant"


# ==========================================
# Archive Tool Tests
# ==========================================

class TestArchiveTool:
    """Tests for archive_analysis tool."""

    def test_zip_extraction(self, trace_id, tenant_id):
        """Test ZIP file extraction."""
        # Create a test ZIP file
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as zf:
                zf.writestr("test.txt", "Hello, World!")
                zf.writestr("config.json", '{"key": "value"}')
            
            tool = ArchiveAnalysisTool()
            input_data = ArchiveToolInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert result.data["archive_type"] == "zip"
            assert result.data["total_files"] == 2
            assert "test.txt" in [f["path"] for f in result.data["files"]]
            
            # Cleanup
            os.unlink(tmp.name)

    def test_invalid_file(self, trace_id, tenant_id):
        """Test with invalid file."""
        tool = ArchiveAnalysisTool()
        input_data = ArchiveToolInput(
            file_path="/nonexistent/file.zip",
            trace_id=trace_id,
            tenant_id=tenant_id,
        )
        
        result = run_async(tool.execute(input_data))
        assert result.success is False
        assert "不存在" in result.error

    def test_unsupported_format(self, trace_id, tenant_id):
        """Test with unsupported format."""
        with tempfile.NamedTemporaryFile(suffix=".xyz", delete=False) as tmp:
            tmp.write(b"not an archive")
            
            tool = ArchiveAnalysisTool()
            input_data = ArchiveToolInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            assert result.success is False
            
            os.unlink(tmp.name)

    def test_path_traversal_detection(self, trace_id, tenant_id):
        """Test path traversal detection."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as zf:
                zf.writestr("../../../etc/passwd", "malicious")
            
            tool = ArchiveAnalysisTool()
            input_data = ArchiveToolInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            # Should detect suspicious files
            assert len(result.data.get("suspicious_files", [])) > 0
            
            os.unlink(tmp.name)

    def test_file_type_detection(self, trace_id, tenant_id):
        """Test file type detection."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as zf:
                zf.writestr("script.py", "print('hello')")
                zf.writestr("data.json", '{"key": "value"}')
                zf.writestr("readme.md", "# Test")
            
            tool = ArchiveAnalysisTool()
            input_data = ArchiveToolInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            type_stats = result.data.get("type_statistics", {})
            assert "Python" in type_stats or "JSON" in type_stats
            
            os.unlink(tmp.name)


# ==========================================
# API Doc Parser Tests
# ==========================================

class TestApiDocParser:
    """Tests for api_doc_parser tool."""

    def test_openapi_parsing(self, trace_id, tenant_id):
        """Test OpenAPI document parsing."""
        openapi_doc = {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0",
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "parameters": [
                            {"name": "limit", "in": "query", "type": "integer"}
                        ],
                        "responses": {"200": {"description": "Success"}}
                    }
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user by ID",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "type": "string"}
                        ],
                        "responses": {"200": {"description": "Success"}}
                    }
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(openapi_doc, tmp)
            tmp.flush()
            
            tool = ApiDocParserTool()
            input_data = ApiDocParserInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert result.data["format"] == "openapi"
            assert result.data["total_endpoints"] == 2
            assert result.data["title"] == "Test API"
            
            os.unlink(tmp.name)

    def test_swagger_parsing(self, trace_id, tenant_id):
        """Test Swagger 2.0 document parsing."""
        swagger_doc = {
            "swagger": "2.0",
            "info": {
                "title": "Test Swagger API",
                "version": "1.0.0",
            },
            "basePath": "/api/v1",
            "paths": {
                "/items": {
                    "get": {
                        "summary": "Get items",
                        "responses": {"200": {"description": "Success"}}
                    }
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(swagger_doc, tmp)
            tmp.flush()
            
            tool = ApiDocParserTool()
            input_data = ApiDocParserInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert result.data["format"] == "swagger"
            assert result.data["base_path"] == "/api/v1"
            
            os.unlink(tmp.name)

    def test_postman_collection(self, trace_id, tenant_id):
        """Test Postman Collection parsing."""
        postman_doc = {
            "info": {
                "name": "Test Collection",
                "version": "1.0.0",
            },
            "item": [
                {
                    "name": "Users",
                    "item": [
                        {
                            "name": "Get Users",
                            "request": {
                                "method": "GET",
                                "url": {
                                    "path": ["api", "users"],
                                    "query": [
                                        {"key": "page", "value": "1"}
                                    ]
                                }
                            }
                        }
                    ]
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(postman_doc, tmp)
            tmp.flush()
            
            tool = ApiDocParserTool()
            input_data = ApiDocParserInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert result.data["format"] == "postman"
            assert result.data["total_endpoints"] >= 1
            
            os.unlink(tmp.name)

    def test_security_analysis(self, trace_id, tenant_id):
        """Test security analysis."""
        openapi_doc = {
            "openapi": "3.0.0",
            "info": {"title": "Insecure API", "version": "1.0.0"},
            "paths": {
                "/admin": {
                    "get": {
                        "summary": "Admin endpoint",
                        "responses": {"200": {"description": "Success"}}
                    }
                },
                "/login": {
                    "post": {
                        "summary": "Login",
                        "responses": {"200": {"description": "Success"}}
                    }
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(openapi_doc, tmp)
            tmp.flush()
            
            tool = ApiDocParserTool()
            input_data = ApiDocParserInput(
                file_path=tmp.name,
                analyze_security=True,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert "security_analysis" in result.data
            
            os.unlink(tmp.name)


# ==========================================
# Config Parser Tests
# ==========================================

class TestConfigParser:
    """Tests for config_parser tool."""

    def test_json_parsing(self, trace_id, tenant_id):
        """Test JSON config parsing."""
        config = {
            "database": {
                "host": "localhost",
                "port": 5432,
                "password": "secret123"
            },
            "debug": True
        }
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(config, tmp)
            tmp.flush()
            
            tool = ConfigParserTool()
            input_data = ConfigParserInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert result.data["format"] == "json"
            assert "database" in result.data["parsed_data"]
            
            os.unlink(tmp.name)

    def test_yaml_parsing(self, trace_id, tenant_id):
        """Test YAML config parsing."""
        yaml_content = """
database:
  host: localhost
  port: 5432
  password: secret123
debug: true
"""
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            tmp.write(yaml_content)
            tmp.flush()
            
            tool = ConfigParserTool()
            input_data = ConfigParserInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert result.data["format"] == "yaml"
            
            os.unlink(tmp.name)

    def test_env_parsing(self, trace_id, tenant_id):
        """Test .env file parsing."""
        env_content = """
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=sk-1234567890
DEBUG=true
"""
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as tmp:
            tmp.write(env_content)
            tmp.flush()
            
            tool = ConfigParserTool()
            input_data = ConfigParserInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert result.data["format"] == "env"
            assert "DATABASE_URL" in result.data["parsed_data"]
            
            os.unlink(tmp.name)

    def test_secret_detection(self, trace_id, tenant_id):
        """Test secret detection."""
        config = {
            "api_key": "sk-1234567890abcdef",
            "password": "supersecret",
            "database_url": "postgresql://user:pass@localhost/db"
        }
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(config, tmp)
            tmp.flush()
            
            tool = ConfigParserTool()
            input_data = ConfigParserInput(
                file_path=tmp.name,
                extract_secrets=True,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert len(result.data.get("secrets", [])) > 0
            
            os.unlink(tmp.name)

    def test_csv_parsing(self, trace_id, tenant_id):
        """Test CSV parsing."""
        csv_content = """name,age,email
Alice,30,alice@example.com
Bob,25,bob@example.com
"""
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp:
            tmp.write(csv_content)
            tmp.flush()
            
            tool = ConfigParserTool()
            input_data = ConfigParserInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert result.data["format"] == "csv"
            assert len(result.data["parsed_data"]) == 2
            
            os.unlink(tmp.name)


# ==========================================
# Binary Analysis Tests
# ==========================================

class TestBinaryAnalysis:
    """Tests for binary_analysis tool."""

    def test_pe_detection(self, trace_id, tenant_id):
        """Test PE file detection."""
        # Create minimal PE header
        pe_header = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"  # PE offset at 0x80
        pe_header += b"\x00" * (0x80 - len(pe_header))
        pe_header += b"PE\x00\x00"  # PE signature
        pe_header += b"\x64\x86"  # Machine: AMD64
        pe_header += b"\x01\x00"  # NumberOfSections: 1
        pe_header += b"\x00" * 12  # Padding
        
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(pe_header + b"\x00" * 100)
            tmp.flush()
            
            tool = BinaryAnalysisTool()
            input_data = BinaryAnalysisInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert result.data["binary_type"] == "PE"
            assert result.data["architecture"] == "AMD64"
            
            os.unlink(tmp.name)

    def test_elf_detection(self, trace_id, tenant_id):
        """Test ELF file detection."""
        # Create minimal ELF header
        elf_header = b"\x7fELF"  # Magic
        elf_header += b"\x02"  # EI_CLASS: 64-bit
        elf_header += b"\x01"  # EI_DATA: Little endian
        elf_header += b"\x01"  # EI_VERSION
        elf_header += b"\x00"  # EI_OSABI
        elf_header += b"\x00" * 8  # Padding
        elf_header += b"\x02\x00"  # ET_EXEC
        elf_header += b"\x3e\x00"  # Machine: AMD64
        elf_header += b"\x01\x00\x00\x00"  # Version
        elf_header += b"\x00" * 8  # Entry point
        elf_header += b"\x00" * 8  # PHOFF
        elf_header += b"\x00" * 8  # SHOFF
        
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tmp:
            tmp.write(elf_header + b"\x00" * 100)
            tmp.flush()
            
            tool = BinaryAnalysisTool()
            input_data = BinaryAnalysisInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is True
            assert result.data["binary_type"] == "ELF"
            assert result.data["architecture"] == "AMD64"
            
            os.unlink(tmp.name)

    def test_unknown_file(self, trace_id, tenant_id):
        """Test unknown file type."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"unknown format")
            tmp.flush()
            
            tool = BinaryAnalysisTool()
            input_data = BinaryAnalysisInput(
                file_path=tmp.name,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            
            result = run_async(tool.execute(input_data))
            
            assert result.success is False
            assert "无法识别" in result.error
            
            os.unlink(tmp.name)


# ==========================================
# Task Planner Tests
# ==========================================

class TestTaskPlanner:
    """Tests for task_planner tool."""

    def test_vulnerability_scan_planning(self, trace_id, tenant_id):
        """Test vulnerability scan task planning."""
        tool = TaskPlannerTool()
        input_data = TaskPlannerInput(
            task_description="对目标进行漏洞扫描",
            trace_id=trace_id,
            tenant_id=tenant_id,
        )
        
        result = run_async(tool.execute(input_data))
        
        assert result.success is True
        assert result.data["task_type"] == "vulnerability_scan"
        assert result.data["total_steps"] >= 2
        assert "nmap_scan" in result.data["required_tools"]

    def test_file_analysis_planning(self, trace_id, tenant_id):
        """Test file analysis task planning."""
        tool = TaskPlannerTool()
        input_data = TaskPlannerInput(
            task_description="分析文件",
            input_files=["/tmp/test.pcap", "/tmp/config.json"],
            trace_id=trace_id,
            tenant_id=tenant_id,
        )
        
        result = run_async(tool.execute(input_data))
        
        assert result.success is True
        assert result.data["total_steps"] >= 2

    def test_task_type_inference(self, trace_id, tenant_id):
        """Test task type inference."""
        tool = TaskPlannerTool()
        
        # Test with keywords
        input_data = TaskPlannerInput(
            task_description="进行渗透测试",
            trace_id=trace_id,
            tenant_id=tenant_id,
        )
        
        result = run_async(tool.execute(input_data))
        assert result.data["task_type"] == "penetration_test"

    def test_malware_analysis_planning(self, trace_id, tenant_id):
        """Test malware analysis task planning."""
        tool = TaskPlannerTool()
        input_data = TaskPlannerInput(
            task_description="分析恶意软件样本",
            input_files=["/tmp/malware.exe"],
            trace_id=trace_id,
            tenant_id=tenant_id,
        )
        
        result = run_async(tool.execute(input_data))
        
        assert result.success is True
        assert result.data["task_type"] == "malware_analysis"
        assert "binary_analysis" in result.data["required_tools"]

    def test_api_security_planning(self, trace_id, tenant_id):
        """Test API security task planning."""
        tool = TaskPlannerTool()
        input_data = TaskPlannerInput(
            task_description="测试 API 安全性",
            input_files=["/tmp/api.json"],
            trace_id=trace_id,
            tenant_id=tenant_id,
        )
        
        result = run_async(tool.execute(input_data))
        
        assert result.success is True
        assert "api_doc_parser" in result.data["required_tools"] or \
               "api_doc_parser" in result.data.get("optional_tools", [])


# ==========================================
# Integration Tests
# ==========================================

class TestToolIntegration:
    """Integration tests for tool registry."""

    def test_all_tools_registered(self):
        """Test that all tools are registered."""
        from app.agent.tool_executor import tool_registry
        
        expected_tools = [
            "echo", "cve_lookup", "cve_catalog", "ioc_lookup",
            "ip_threat_analysis", "rag_search", "web_search",
            "pcap_analysis", "nmap_scan", "vuln_scan", "dir_scan",
            "log_analysis", "hash_lookup", "encoding",
            "archive_analysis", "api_doc_parser", "config_parser",
            "binary_analysis", "task_planner"
        ]
        
        registered = tool_registry.list_names()
        
        for tool_name in expected_tools:
            assert tool_name in registered, f"Tool '{tool_name}' not registered"

    def test_tool_schemas_valid(self):
        """Test that all tool schemas are valid."""
        from app.agent.tool_executor import tool_registry
        
        schemas = tool_registry.get_schemas()
        
        for schema in schemas:
            assert "type" in schema
            assert "function" in schema
            assert "name" in schema["function"]
            assert "description" in schema["function"]
            assert "parameters" in schema["function"]
