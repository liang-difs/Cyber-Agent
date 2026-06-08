"""
Config/Structured File Parser Tool — 解析结构化配置文件。

支持 JSON、YAML、XML、CSV、ENV、INI 等格式。
自动识别格式并提取关键信息，检测敏感信息和安全问题。
"""

import os
import re
import time
import json
import csv
import hashlib
import logging
from pathlib import Path
from typing import Any, Optional
from io import StringIO

from pydantic import BaseModel, Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)


class ConfigParserInput(ToolInput):
    """Config Parser Tool 输入"""

    file_path: str = Field(..., description="配置文件路径")
    format: Optional[str] = Field(default=None, description="文件格式: json, yaml, xml, csv, env, ini, auto")
    extract_secrets: bool = Field(default=True, description="是否提取敏感信息")
    analyze_security: bool = Field(default=True, description="是否进行安全分析")


class ConfigParserTool:
    """解析结构化配置文件，提取关键信息并检测安全问题"""

    name = "config_parser"
    version = "v1"
    input_class = ConfigParserInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "config_parser",
                "description": (
                    "解析结构化配置文件（JSON/YAML/XML/CSV/ENV/INI）。"
                    "自动识别格式并提取关键信息，检测敏感信息和安全问题。"
                    "\n\n支持的功能："
                    "1. 自动识别文件格式"
                    "2. 提取配置项和值"
                    "3. 检测敏感信息（密码、密钥、令牌等）"
                    "4. 安全配置分析"
                    "5. 结构化输出"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "配置文件路径",
                        },
                        "format": {
                            "type": "string",
                            "enum": ["json", "yaml", "xml", "csv", "env", "ini", "auto"],
                            "description": "文件格式（默认自动检测）",
                        },
                        "extract_secrets": {
                            "type": "boolean",
                            "description": "是否提取敏感信息，默认 true",
                        },
                        "analyze_security": {
                            "type": "boolean",
                            "description": "是否进行安全分析，默认 true",
                        },
                    },
                    "required": ["file_path"],
                },
            },
        }

    async def execute(self, input_data: ConfigParserInput) -> ToolResult:
        start = time.time()

        # Validate file exists
        if not os.path.exists(input_data.file_path):
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"文件不存在: {input_data.file_path}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Read file content
        try:
            with open(input_data.file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            # Try binary mode for some formats
            with open(input_data.file_path, "rb") as f:
                content = f.read()
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"读取文件失败: {e}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Detect format
        file_format = input_data.format or self._detect_format(input_data.file_path, content)
        if file_format == "unknown":
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="无法识别文件格式",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Parse content
        try:
            parsed_data = self._parse_content(content, file_format)
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"解析失败: {e}",
                confidence=0.0,
                evidence_source=["config_parser"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Extract secrets if requested
        secrets = []
        if input_data.extract_secrets:
            secrets = self._extract_secrets(content, parsed_data, file_format)

        # Security analysis
        security_analysis = {}
        if input_data.analyze_security:
            security_analysis = self._analyze_security(parsed_data, secrets, file_format)

        # Get file info
        file_size = os.path.getsize(input_data.file_path)
        file_hash = hashlib.sha256(content.encode() if isinstance(content, str) else content).hexdigest()

        # Build result
        execution_time_ms = int((time.time() - start) * 1000)

        result = {
            "file_path": input_data.file_path,
            "file_name": os.path.basename(input_data.file_path),
            "format": file_format,
            "file_size": file_size,
            "sha256": file_hash,
            "parsed_data": parsed_data,
            "structure": self._analyze_structure(parsed_data),
            "secrets": secrets,
            "security_analysis": security_analysis,
        }

        # Build summary
        summary_parts = [
            f"配置文件: {os.path.basename(input_data.file_path)} ({file_format.upper()})",
            f"文件大小: {file_size} 字节",
        ]

        # Structure summary
        structure = result["structure"]
        summary_parts.append(f"数据结构: {structure.get('type', 'unknown')}")
        if structure.get("depth"):
            summary_parts.append(f"嵌套深度: {structure['depth']}")
        if structure.get("keys_count"):
            summary_parts.append(f"配置项数量: {structure['keys_count']}")

        # Secrets summary
        if secrets:
            summary_parts.append(f"发现 {len(secrets)} 个敏感信息:")
            for secret in secrets[:5]:
                summary_parts.append(f"  - [{secret['severity']}] {secret['type']}: {secret['location']}")

        # Security summary
        issues = security_analysis.get("issues", [])
        if issues:
            summary_parts.append(f"发现 {len(issues)} 个安全问题:")
            for issue in issues[:3]:
                summary_parts.append(f"  - [{issue['severity']}] {issue['description']}")

        result["summary_text"] = "；".join(summary_parts)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result,
            error=None,
            confidence=0.95,
            evidence_source=["config_parser"],
            trace_id=input_data.trace_id,
            execution_time_ms=execution_time_ms,
        )

    def _detect_format(self, file_path: str, content: Any) -> str:
        """Detect file format."""
        # Check extension first
        ext = Path(file_path).suffix.lower()
        ext_map = {
            ".json": "json",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".xml": "xml",
            ".csv": "csv",
            ".env": "env",
            ".ini": "ini",
            ".conf": "ini",
            ".cfg": "ini",
            ".properties": "ini",
            ".toml": "toml",
        }

        if ext in ext_map:
            return ext_map[ext]

        # Check content
        if isinstance(content, str):
            content_stripped = content.strip()
            
            # JSON
            if content_stripped.startswith(("{", "[")):
                try:
                    json.loads(content_stripped)
                    return "json"
                except json.JSONDecodeError:
                    pass

            # XML
            if content_stripped.startswith("<?xml") or content_stripped.startswith("<"):
                return "xml"

            # YAML (check for common patterns)
            if re.search(r"^[a-zA-Z_]+\s*:", content_stripped, re.MULTILINE):
                return "yaml"

            # ENV
            if re.search(r"^[A-Z_]+=", content_stripped, re.MULTILINE):
                return "env"

            # INI
            if re.search(r"^\[.+\]", content_stripped, re.MULTILINE):
                return "ini"

        return "unknown"

    def _parse_content(self, content: Any, format: str) -> Any:
        """Parse content based on format."""
        if format == "json":
            return json.loads(content)
        
        elif format == "yaml":
            import yaml
            return yaml.safe_load(content)
        
        elif format == "xml":
            return self._parse_xml(content)
        
        elif format == "csv":
            return self._parse_csv(content)
        
        elif format == "env":
            return self._parse_env(content)
        
        elif format == "ini":
            return self._parse_ini(content)
        
        elif format == "toml":
            return self._parse_toml(content)
        
        else:
            raise ValueError(f"不支持的格式: {format}")

    def _parse_xml(self, content: str) -> dict:
        """Parse XML content."""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            return self._xml_to_dict(root)
        except Exception as e:
            raise ValueError(f"XML 解析失败: {e}")

    def _xml_to_dict(self, element) -> dict:
        """Convert XML element to dictionary."""
        result = {}
        
        # Add attributes
        if element.attrib:
            result["@attributes"] = element.attrib
        
        # Add children
        for child in element:
            child_data = self._xml_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        
        # Add text
        if element.text and element.text.strip():
            if result:
                result["@text"] = element.text.strip()
            else:
                return element.text.strip()
        
        return result

    def _parse_csv(self, content: str) -> list[dict]:
        """Parse CSV content."""
        reader = csv.DictReader(StringIO(content))
        return list(reader)

    def _parse_env(self, content: str) -> dict:
        """Parse .env file."""
        result = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                # Remove quotes
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]
                result[key] = value
        return result

    def _parse_ini(self, content: str) -> dict:
        """Parse INI file."""
        import configparser
        config = configparser.ConfigParser()
        config.read_string(content)
        
        result = {}
        for section in config.sections():
            result[section] = dict(config[section])
        return result

    def _parse_toml(self, content: str) -> dict:
        """Parse TOML file."""
        try:
            import tomllib
            return tomllib.loads(content)
        except ImportError:
            # Fallback for Python < 3.11
            raise ValueError("TOML 解析需要 Python 3.11+ 或安装 tomli 包")

    def _analyze_structure(self, data: Any) -> dict:
        """Analyze data structure."""
        structure = {
            "type": type(data).__name__,
            "depth": 0,
            "keys_count": 0,
        }

        if isinstance(data, dict):
            structure["keys_count"] = len(data)
            structure["depth"] = self._get_depth(data)
            structure["top_keys"] = list(data.keys())[:10]
        elif isinstance(data, list):
            structure["length"] = len(data)
            if data:
                structure["item_type"] = type(data[0]).__name__

        return structure

    def _get_depth(self, data: Any, current_depth: int = 0) -> int:
        """Get nesting depth of data structure."""
        if isinstance(data, dict):
            if not data:
                return current_depth
            return max(self._get_depth(v, current_depth + 1) for v in data.values())
        elif isinstance(data, list):
            if not data:
                return current_depth
            return max(self._get_depth(item, current_depth + 1) for item in data)
        else:
            return current_depth

    def _extract_secrets(self, content: str, parsed_data: Any, format: str) -> list[dict]:
        """Extract sensitive information."""
        secrets = []

        # Patterns for sensitive information
        patterns = [
            (r"(?i)(password|passwd|pwd)\s*[:=]\s*(.+)", "password", "high"),
            (r"(?i)(secret|secret_key|secret_token)\s*[:=]\s*(.+)", "secret", "high"),
            (r"(?i)(api_key|apikey|api_token)\s*[:=]\s*(.+)", "api_key", "high"),
            (r"(?i)(access_key|access_token)\s*[:=]\s*(.+)", "access_key", "high"),
            (r"(?i)(private_key|priv_key)\s*[:=]\s*(.+)", "private_key", "critical"),
            (r"(?i)(token|bearer|jwt)\s*[:=]\s*(.+)", "token", "high"),
            (r"(?i)(auth|authorization)\s*[:=]\s*(.+)", "auth", "medium"),
            (r"(?i)(credential|cred)\s*[:=]\s*(.+)", "credential", "high"),
            (r"(?i)(connection_string|conn_str|database_url)\s*[:=]\s*(.+)", "connection_string", "high"),
            (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*(.+)", "aws_credential", "critical"),
            (r"(?i)(docker_password|registry_password)\s*[:=]\s*(.+)", "docker_credential", "high"),
        ]

        # Search in raw content
        for pattern, secret_type, severity in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                key = match.group(1)
                value = match.group(2).strip()
                
                # Mask value for security
                masked_value = self._mask_value(value)
                
                secrets.append({
                    "type": secret_type,
                    "key": key,
                    "value_masked": masked_value,
                    "location": f"line {content[:match.start()].count(chr(10)) + 1}",
                    "severity": severity,
                })

        # Search in parsed data
        if isinstance(parsed_data, dict):
            self._extract_secrets_from_dict(parsed_data, secrets, "")

        return secrets

    def _extract_secrets_from_dict(self, data: dict, secrets: list, path: str):
        """Recursively extract secrets from dictionary."""
        sensitive_keys = [
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "token", "access_key", "private_key", "credential", "auth",
        ]

        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            # Check if key is sensitive
            if any(s in key.lower() for s in sensitive_keys):
                if isinstance(value, str) and value:
                    secrets.append({
                        "type": "sensitive_key",
                        "key": key,
                        "value_masked": self._mask_value(value),
                        "location": current_path,
                        "severity": "high",
                    })
            
            # Recurse into nested structures
            if isinstance(value, dict):
                self._extract_secrets_from_dict(value, secrets, current_path)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        self._extract_secrets_from_dict(item, secrets, f"{current_path}[{i}]")

    def _mask_value(self, value: str) -> str:
        """Mask sensitive value."""
        if len(value) <= 4:
            return "****"
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    def _analyze_security(self, parsed_data: Any, secrets: list, format: str) -> dict:
        """Analyze security configuration."""
        analysis = {
            "issues": [],
            "recommendations": [],
        }

        # Check for secrets
        if secrets:
            analysis["issues"].append({
                "severity": "high",
                "type": "secrets_found",
                "description": f"发现 {len(secrets)} 个敏感信息，建议使用环境变量或密钥管理服务",
            })

        # Check for common security issues
        if isinstance(parsed_data, dict):
            # Check for debug mode
            if parsed_data.get("debug") or parsed_data.get("DEBUG"):
                analysis["issues"].append({
                    "severity": "medium",
                    "type": "debug_enabled",
                    "description": "检测到调试模式已启用，生产环境应禁用",
                })

            # Check for insecure configurations
            insecure_configs = [
                ("ssl", False, "SSL 可能被禁用"),
                ("verify", False, "证书验证可能被禁用"),
                ("https", False, "HTTPS 可能被禁用"),
            ]

            for key, dangerous_value, description in insecure_configs:
                for data_key, data_value in parsed_data.items():
                    if key in str(data_key).lower() and data_value == dangerous_value:
                        analysis["issues"].append({
                            "severity": "medium",
                            "type": "insecure_config",
                            "description": description,
                        })

        # General recommendations
        analysis["recommendations"].append("建议使用环境变量存储敏感配置")
        analysis["recommendations"].append("建议定期轮换密钥和令牌")
        analysis["recommendations"].append("建议对配置文件进行版本控制，但排除敏感信息")

        return analysis


config_parser_tool = ConfigParserTool()
