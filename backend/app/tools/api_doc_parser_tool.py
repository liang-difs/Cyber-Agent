"""
API Documentation Parser Tool — 解析接口文档（Swagger/OpenAPI/Postman Collection）。

支持自动解析 API 端点、参数、认证方式等信息。
可用于自动化测试、API 安全分析。
"""

import os
import time
import json
import hashlib
import logging
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)


class ApiDocParserInput(ToolInput):
    """API Documentation Parser 输入"""

    file_path: Optional[str] = Field(default=None, description="API 文档文件路径")
    url: Optional[str] = Field(default=None, description="Swagger/OpenAPI 文档 URL")
    format: Optional[str] = Field(default=None, description="文档格式: swagger, openapi, postman")
    analyze_security: bool = Field(default=True, description="是否分析安全配置")


class ApiDocParserTool:
    """解析 API 文档，提取端点、参数、认证信息"""

    name = "api_doc_parser"
    version = "v1"
    input_class = ApiDocParserInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "api_doc_parser",
                "description": (
                    "解析 API 接口文档（Swagger 2.0/OpenAPI 3.x/Postman Collection）。"
                    "提取所有端点、HTTP 方法、参数、认证方式等信息。"
                    "支持文件路径或 URL 输入。"
                    "\n\n分析完成后，建议按以下顺序串联其他工具："
                    "1. 对发现的端点使用 vuln_scan 进行漏洞扫描"
                    "2. 对认证配置进行安全分析"
                    "3. 使用 dir_scan 发现未文档化的端点"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "API 文档文件路径（JSON/YAML）",
                        },
                        "url": {
                            "type": "string",
                            "description": "Swagger/OpenAPI 文档 URL",
                        },
                        "format": {
                            "type": "string",
                            "enum": ["swagger", "openapi", "postman"],
                            "description": "文档格式（可选，自动检测）",
                        },
                        "analyze_security": {
                            "type": "boolean",
                            "description": "是否分析安全配置，默认 true",
                        },
                    },
                },
            },
        }

    async def execute(self, input_data: ApiDocParserInput) -> ToolResult:
        start = time.time()

        # Validate input
        if not input_data.file_path and not input_data.url:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="请提供 file_path 或 url 参数",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Load document
        try:
            if input_data.url:
                doc_content = await self._fetch_from_url(input_data.url)
                doc_source = input_data.url
            else:
                doc_content = self._load_from_file(input_data.file_path)
                doc_source = input_data.file_path
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"加载文档失败: {e}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Detect format
        doc_format = input_data.format or self._detect_format(doc_content)
        if doc_format == "unknown":
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="无法识别文档格式",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Parse document
        try:
            if doc_format == "postman":
                result = self._parse_postman(doc_content)
            else:
                result = self._parse_openapi(doc_content, doc_format)
        except Exception as e:
            logger.error(f"API doc parsing failed: {e}")
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"文档解析失败: {e}",
                confidence=0.0,
                evidence_source=["api_doc_parser"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Security analysis
        if input_data.analyze_security:
            result["security_analysis"] = self._analyze_security(result)

        # Build result
        execution_time_ms = int((time.time() - start) * 1000)

        result.update({
            "source": doc_source,
            "format": doc_format,
            "total_endpoints": len(result.get("endpoints", [])),
        })

        # Build summary
        summary_parts = [
            f"API 文档格式: {doc_format.upper()}",
            f"来源: {doc_source}",
            f"共发现 {result['total_endpoints']} 个端点",
        ]

        # Endpoint statistics
        endpoints = result.get("endpoints", [])
        method_stats = {}
        for ep in endpoints:
            method = ep.get("method", "UNKNOWN")
            method_stats[method] = method_stats.get(method, 0) + 1
        
        if method_stats:
            stats_str = ", ".join([f"{k}: {v}" for k, v in method_stats.items()])
            summary_parts.append(f"HTTP 方法分布: {stats_str}")

        # Security summary
        security = result.get("security_analysis", {})
        if security:
            issues = security.get("issues", [])
            if issues:
                summary_parts.append(f"发现 {len(issues)} 个安全问题:")
                for issue in issues[:3]:
                    summary_parts.append(f"  - [{issue['severity']}] {issue['description']}")

        # Auth methods
        auth_methods = result.get("authentication", [])
        if auth_methods:
            summary_parts.append(f"认证方式: {', '.join(auth_methods)}")

        result["summary_text"] = "；".join(summary_parts)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result,
            error=None,
            confidence=0.9,
            evidence_source=["api_doc_parser"],
            trace_id=input_data.trace_id,
            execution_time_ms=execution_time_ms,
        )

    async def _fetch_from_url(self, url: str) -> dict:
        """Fetch API doc from URL."""
        import httpx

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()

    def _load_from_file(self, file_path: str) -> dict:
        """Load API doc from file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Try JSON first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # Try YAML
        try:
            import yaml
            return yaml.safe_load(content)
        except Exception:
            pass

        raise ValueError("无法解析文件内容（尝试 JSON 和 YAML 格式）")

    def _detect_format(self, doc: dict) -> str:
        """Detect API doc format."""
        # OpenAPI 3.x
        if "openapi" in doc:
            return "openapi"
        
        # Swagger 2.0
        if "swagger" in doc:
            return "swagger"
        
        # Postman Collection
        if "info" in doc and "item" in doc:
            return "postman"
        
        return "unknown"

    def _parse_openapi(self, doc: dict, format: str) -> dict:
        """Parse OpenAPI/Swagger document."""
        result = {
            "title": "",
            "version": "",
            "description": "",
            "base_path": "",
            "endpoints": [],
            "authentication": [],
            "models": [],
        }

        # Extract info
        info = doc.get("info", {})
        result["title"] = info.get("title", "")
        result["version"] = info.get("version", "")
        result["description"] = info.get("description", "")

        # Extract base path
        if format == "swagger":
            result["base_path"] = doc.get("basePath", "")
        else:
            servers = doc.get("servers", [])
            if servers:
                result["base_path"] = servers[0].get("url", "")

        # Extract authentication
        result["authentication"] = self._extract_auth_openapi(doc, format)

        # Extract endpoints
        paths = doc.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    endpoint = self._parse_endpoint_openapi(path, method, details, format)
                    result["endpoints"].append(endpoint)

        # Extract models/schemas
        result["models"] = self._extract_models_openapi(doc, format)

        return result

    def _extract_auth_openapi(self, doc: dict, format: str) -> list[str]:
        """Extract authentication methods."""
        auth_methods = []

        if format == "swagger":
            security_defs = doc.get("securityDefinitions", {})
            for name, scheme in security_defs.items():
                auth_type = scheme.get("type", "")
                if auth_type == "apiKey":
                    auth_methods.append(f"API Key ({name})")
                elif auth_type == "oauth2":
                    auth_methods.append(f"OAuth2 ({name})")
                elif auth_type == "basic":
                    auth_methods.append(f"Basic Auth ({name})")
        else:
            security_schemes = doc.get("components", {}).get("securitySchemes", {})
            for name, scheme in security_schemes.items():
                auth_type = scheme.get("type", "")
                if auth_type == "apiKey":
                    auth_methods.append(f"API Key ({name})")
                elif auth_type == "oauth2":
                    auth_methods.append(f"OAuth2 ({name})")
                elif auth_type == "http":
                    scheme_type = scheme.get("scheme", "")
                    auth_methods.append(f"HTTP {scheme_type} ({name})")
                elif auth_type == "openIdConnect":
                    auth_methods.append(f"OpenID Connect ({name})")

        return auth_methods

    def _parse_endpoint_openapi(self, path: str, method: str, details: dict, format: str) -> dict:
        """Parse single endpoint."""
        endpoint = {
            "path": path,
            "method": method.upper(),
            "summary": details.get("summary", ""),
            "description": details.get("description", ""),
            "operation_id": details.get("operationId", ""),
            "tags": details.get("tags", []),
            "parameters": [],
            "request_body": None,
            "responses": [],
            "security": details.get("security", []),
        }

        # Parse parameters
        for param in details.get("parameters", []):
            endpoint["parameters"].append({
                "name": param.get("name", ""),
                "in": param.get("in", ""),
                "required": param.get("required", False),
                "type": param.get("schema", {}).get("type", param.get("type", "")),
                "description": param.get("description", ""),
            })

        # Parse request body (OpenAPI 3.x)
        request_body = details.get("requestBody", {})
        if request_body:
            content = request_body.get("content", {})
            for media_type, schema in content.items():
                endpoint["request_body"] = {
                    "media_type": media_type,
                    "schema": schema.get("schema", {}),
                    "required": request_body.get("required", False),
                }
                break

        # Parse responses
        for status_code, response in details.get("responses", {}).items():
            endpoint["responses"].append({
                "status_code": status_code,
                "description": response.get("description", ""),
            })

        return endpoint

    def _extract_models_openapi(self, doc: dict, format: str) -> list[dict]:
        """Extract data models/schemas."""
        models = []

        if format == "swagger":
            definitions = doc.get("definitions", {})
            for name, schema in definitions.items():
                models.append({
                    "name": name,
                    "type": schema.get("type", "object"),
                    "properties": list(schema.get("properties", {}).keys()),
                    "required": schema.get("required", []),
                })
        else:
            schemas = doc.get("components", {}).get("schemas", {})
            for name, schema in schemas.items():
                models.append({
                    "name": name,
                    "type": schema.get("type", "object"),
                    "properties": list(schema.get("properties", {}).keys()),
                    "required": schema.get("required", []),
                })

        return models

    def _parse_postman(self, doc: dict) -> dict:
        """Parse Postman Collection."""
        result = {
            "title": "",
            "version": "",
            "description": "",
            "base_path": "",
            "endpoints": [],
            "authentication": [],
            "models": [],
        }

        # Extract info
        info = doc.get("info", {})
        result["title"] = info.get("name", "")
        result["version"] = info.get("version", {}).get("major", "1.0")
        result["description"] = info.get("description", "")

        # Extract authentication
        auth = doc.get("auth", {})
        if auth:
            auth_type = auth.get("type", "")
            result["authentication"].append(f"{auth_type}")

        # Extract variables
        variables = doc.get("variable", [])
        for var in variables:
            if var.get("key") == "baseUrl":
                result["base_path"] = var.get("value", "")

        # Extract endpoints
        items = doc.get("item", [])
        self._parse_postman_items(items, result["endpoints"], [])

        return result

    def _parse_postman_items(self, items: list, endpoints: list, tags: list[str]):
        """Recursively parse Postman items."""
        for item in items:
            # Check if it's a folder
            if "item" in item:
                folder_tags = tags + [item.get("name", "")]
                self._parse_postman_items(item["item"], endpoints, folder_tags)
                continue

            # Parse request
            request = item.get("request", {})
            if not request:
                continue

            url = request.get("url", {})
            if isinstance(url, str):
                path = url
            else:
                path = "/".join(url.get("path", []))
                if path:
                    path = "/" + path

            method = request.get("method", "GET").upper()

            endpoint = {
                "path": path,
                "method": method,
                "summary": item.get("name", ""),
                "description": request.get("description", ""),
                "operation_id": "",
                "tags": tags,
                "parameters": [],
                "request_body": None,
                "responses": [],
                "security": [],
            }

            # Parse query parameters
            query = url.get("query", []) if isinstance(url, dict) else []
            for param in query:
                endpoint["parameters"].append({
                    "name": param.get("key", ""),
                    "in": "query",
                    "required": not param.get("disabled", False),
                    "type": "string",
                    "description": param.get("description", ""),
                })

            # Parse headers
            headers = request.get("header", [])
            for header in headers:
                endpoint["parameters"].append({
                    "name": header.get("key", ""),
                    "in": "header",
                    "required": True,
                    "type": "string",
                    "description": header.get("description", ""),
                })

            # Parse request body
            body = request.get("body", {})
            if body:
                mode = body.get("mode", "")
                if mode == "raw":
                    endpoint["request_body"] = {
                        "media_type": "application/json",
                        "schema": {},
                        "required": True,
                    }
                elif mode == "formdata":
                    endpoint["request_body"] = {
                        "media_type": "multipart/form-data",
                        "schema": {},
                        "required": True,
                    }

            endpoints.append(endpoint)

    def _analyze_security(self, result: dict) -> dict:
        """Analyze security configuration."""
        analysis = {
            "issues": [],
            "recommendations": [],
        }

        endpoints = result.get("endpoints", [])
        auth_methods = result.get("authentication", [])

        # Check for endpoints without authentication
        no_auth_endpoints = []
        for ep in endpoints:
            if not ep.get("security") and not auth_methods:
                no_auth_endpoints.append(f"{ep['method']} {ep['path']}")

        if no_auth_endpoints:
            analysis["issues"].append({
                "severity": "high",
                "type": "missing_auth",
                "description": f"发现 {len(no_auth_endpoints)} 个端点可能缺少认证",
                "endpoints": no_auth_endpoints[:5],
            })

        # Check for sensitive endpoints
        sensitive_patterns = [
            "/admin", "/user", "/password", "/token", "/key",
            "/secret", "/config", "/setting", "/auth", "/login",
        ]

        sensitive_endpoints = []
        for ep in endpoints:
            path_lower = ep["path"].lower()
            for pattern in sensitive_patterns:
                if pattern in path_lower:
                    sensitive_endpoints.append({
                        "endpoint": f"{ep['method']} {ep['path']}",
                        "pattern": pattern,
                    })
                    break

        if sensitive_endpoints:
            analysis["issues"].append({
                "severity": "medium",
                "type": "sensitive_endpoints",
                "description": f"发现 {len(sensitive_endpoints)} 个敏感端点需要特别关注",
                "endpoints": [e["endpoint"] for e in sensitive_endpoints[:5]],
            })

        # Check for POST/PUT/DELETE without request body validation
        for ep in endpoints:
            if ep["method"] in ["POST", "PUT", "PATCH"]:
                if not ep.get("request_body"):
                    analysis["issues"].append({
                        "severity": "low",
                        "type": "missing_validation",
                        "description": f"端点 {ep['method']} {ep['path']} 可能缺少请求体验证",
                    })

        # Recommendations
        if not auth_methods:
            analysis["recommendations"].append("建议添加认证机制（API Key、OAuth2 等）")

        analysis["recommendations"].append("建议对所有敏感端点实施速率限制")
        analysis["recommendations"].append("建议使用 HTTPS 并验证所有输入参数")

        return analysis


api_doc_parser_tool = ApiDocParserTool()
