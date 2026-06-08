"""Input Format Auto-Detector — 自动检测输入格式并路由到正确的工具链。

根据文件魔数、扩展名、内容启发式判断输入类型，
返回推荐的工具调用序列，供 Agent 或 Coordinator 使用。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class InputDetection:
    """输入格式检测结果"""
    input_type: str          # 检测到的类型
    confidence: float        # 置信度 0.0-1.0
    suggested_tool: str      # 推荐的首要工具
    tool_chain: list[str]    # 推荐的工具链
    metadata: dict           # 附加信息（文件类型、大小等）


# 扩展名 → 类型映射
EXTENSION_MAP: dict[str, tuple[str, str, list[str]]] = {
    # (input_type, primary_tool, tool_chain)
    ".pcap": ("pcap", "pcap_analysis", ["pcap_analysis", "ip_threat_analysis", "ioc_lookup"]),
    ".pcapng": ("pcap", "pcap_analysis", ["pcap_analysis", "ip_threat_analysis", "ioc_lookup"]),
    ".zip": ("archive", "archive_analysis", ["archive_analysis"]),
    ".rar": ("archive", "archive_analysis", ["archive_analysis"]),
    ".7z": ("archive", "archive_analysis", ["archive_analysis"]),
    ".tar": ("archive", "archive_analysis", ["archive_analysis"]),
    ".gz": ("archive", "archive_analysis", ["archive_analysis"]),
    ".bz2": ("archive", "archive_analysis", ["archive_analysis"]),
    ".exe": ("binary", "binary_analysis", ["binary_analysis", "hash_lookup"]),
    ".dll": ("binary", "binary_analysis", ["binary_analysis", "hash_lookup"]),
    ".elf": ("binary", "binary_analysis", ["binary_analysis", "hash_lookup"]),
    ".so": ("binary", "binary_analysis", ["binary_analysis", "hash_lookup"]),
    ".sys": ("binary", "binary_analysis", ["binary_analysis", "hash_lookup"]),
    ".json": ("config", "config_parser", ["config_parser"]),
    ".yaml": ("config", "config_parser", ["config_parser"]),
    ".yml": ("config", "config_parser", ["config_parser"]),
    ".xml": ("config", "config_parser", ["config_parser"]),
    ".env": ("config", "config_parser", ["config_parser"]),
    ".ini": ("config", "config_parser", ["config_parser"]),
    ".csv": ("config", "config_parser", ["config_parser"]),
    ".log": ("log", "log_analysis", ["log_analysis"]),
    ".txt": ("text", "log_analysis", ["log_analysis"]),
}

# 魔数 → 类型映射
MAGIC_MAP: list[tuple[bytes, str, str, list[str]]] = [
    # (magic_bytes, input_type, primary_tool, tool_chain)
    (b"\xd4\xc3\xb2\xa1", "pcap", "pcap_analysis", ["pcap_analysis", "ip_threat_analysis", "ioc_lookup"]),
    (b"\xa1\xb2\xc3\xd4", "pcap", "pcap_analysis", ["pcap_analysis", "ip_threat_analysis", "ioc_lookup"]),
    (b"\x0a\x0d\x0d\x0a", "pcapng", "pcap_analysis", ["pcap_analysis", "ip_threat_analysis", "ioc_lookup"]),
    (b"PK\x03\x04", "archive", "archive_analysis", ["archive_analysis"]),
    (b"Rar!\x1a\x07", "archive", "archive_analysis", ["archive_analysis"]),
    (b"7z\xbc\xaf\x27\x1c", "archive", "archive_analysis", ["archive_analysis"]),
    (b"\x1f\x8b", "archive", "archive_analysis", ["archive_analysis"]),
    (b"MZ", "binary", "binary_analysis", ["binary_analysis", "hash_lookup"]),
    (b"\x7fELF", "binary", "binary_analysis", ["binary_analysis", "hash_lookup"]),
    (b"\xfe\xed\xfa", "binary", "binary_analysis", ["binary_analysis", "hash_lookup"]),
    (b"\xca\xfe\xba\xbe", "binary", "binary_analysis", ["binary_analysis", "hash_lookup"]),
]

# Swagger/OpenAPI 关键字
SWAGGER_KEYWORDS = [
    '"swagger"', '"openapi"', '"paths"', '"info"',
    '"swagger":', '"openapi":', '/api/', '"definitions"',
]

# 日志格式特征
LOG_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",  # 时间戳
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}",  # syslog
    r"\w+\[\d+\]:",  # syslog 进程
    r"(ERROR|WARN|INFO|DEBUG|FATAL)",  # 日志级别
    r"(SRC=|DST=|PROTO=|DPT=)",  # 防火墙日志
    r"(Failed password|Accepted|authentication failure)",  # SSH 日志
    r"(GET|POST|PUT|DELETE)\s+/",  # HTTP 日志
]


def detect_input_type(
    content: Optional[str] = None,
    file_path: Optional[str] = None,
    filename: Optional[str] = None,
) -> InputDetection:
    """检测输入格式并返回路由建议。

    Args:
        content: 文本内容（用于内容启发式检测）
        file_path: 文件路径（用于魔数检测）
        filename: 文件名（用于扩展名检测）

    Returns:
        InputDetection 包含类型、置信度、推荐工具链
    """
    # 优先级：魔数 > 扩展名 > 内容启发式

    # 1. 魔数检测（最可靠）
    if file_path:
        magic_result = _detect_by_magic(file_path)
        if magic_result:
            return magic_result

    # 2. 扩展名检测
    name = filename or file_path
    if name:
        ext_result = _detect_by_extension(name)
        if ext_result:
            return ext_result

    # 3. 内容启发式检测
    if content:
        content_result = _detect_by_content(content)
        if content_result:
            return content_result

    # 4. 默认：通用分析
    return InputDetection(
        input_type="unknown",
        confidence=0.3,
        suggested_tool="rag_search",
        tool_chain=["rag_search"],
        metadata={},
    )


def _detect_by_magic(file_path: str) -> Optional[InputDetection]:
    """通过文件魔数检测类型"""
    try:
        path = Path(file_path)
        if not path.exists():
            return None

        with open(path, "rb") as f:
            header = f.read(16)

        for magic, input_type, tool, chain in MAGIC_MAP:
            if header.startswith(magic):
                return InputDetection(
                    input_type=input_type,
                    confidence=0.95,
                    suggested_tool=tool,
                    tool_chain=chain,
                    metadata={"file_size": path.stat().st_size, "magic": magic.hex()},
                )
    except Exception as e:
        logger.debug("Magic detection failed for %s: %s", file_path, e)

    return None


def _detect_by_extension(name: str) -> Optional[InputDetection]:
    """通过扩展名检测类型"""
    ext = Path(name).suffix.lower()

    if ext in EXTENSION_MAP:
        input_type, tool, chain = EXTENSION_MAP[ext]
        return InputDetection(
            input_type=input_type,
            confidence=0.8,
            suggested_tool=tool,
            tool_chain=chain,
            metadata={"extension": ext},
        )

    return None


def _detect_by_content(content: str) -> Optional[InputDetection]:
    """通过内容启发式检测类型"""
    stripped = content.strip()

    # JSON 检测
    if stripped.startswith("{") or stripped.startswith("["):
        # 检查是否是 Swagger/OpenAPI
        if any(kw in stripped for kw in SWAGGER_KEYWORDS):
            return InputDetection(
                input_type="api_doc",
                confidence=0.85,
                suggested_tool="api_doc_parser",
                tool_chain=["api_doc_parser", "vuln_scan"],
                metadata={"format": "swagger/openapi"},
            )
        # 普通 JSON 配置
        return InputDetection(
            input_type="config",
            confidence=0.7,
            suggested_tool="config_parser",
            tool_chain=["config_parser"],
            metadata={"format": "json"},
        )

    # Sigma 规则检测（必须在 YAML 之前，因为 Sigma 也是 YAML 格式）
    if "title:" in content and "detection:" in content and "logsource:" in content:
        return InputDetection(
            input_type="sigma_rule",
            confidence=0.9,
            suggested_tool="rule_match",
            tool_chain=["rule_match"],
            metadata={"format": "sigma_yaml"},
        )

    # YARA 规则检测（必须在通用文本之前）
    if re.search(r"rule\s+\w+\s*[:{]", content) and "strings:" in content and "condition:" in content:
        return InputDetection(
            input_type="yara_rule",
            confidence=0.9,
            suggested_tool="rule_match",
            tool_chain=["rule_match"],
            metadata={"format": "yara"},
        )

    # YAML 检测
    if stripped.startswith("---") or re.match(r"^[a-zA-Z_]+:\s", stripped):
        return InputDetection(
            input_type="config",
            confidence=0.7,
            suggested_tool="config_parser",
            tool_chain=["config_parser"],
            metadata={"format": "yaml"},
        )

    # 日志检测
    log_score = sum(1 for p in LOG_PATTERNS if re.search(p, content[:2000]))
    if log_score >= 2:
        return InputDetection(
            input_type="log",
            confidence=min(0.6 + log_score * 0.1, 0.95),
            suggested_tool="log_analysis",
            tool_chain=["log_analysis"],
            metadata={"log_patterns_matched": log_score},
        )

    # IoC 批量检测（多行 IP/域名/哈希）
    lines = [l.strip() for l in stripped.split("\n") if l.strip()]
    if len(lines) >= 3:
        ip_count = sum(1 for l in lines if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", l))
        hash_count = sum(1 for l in lines if re.match(r"^[0-9a-fA-F]{32,64}$", l))
        if ip_count >= 3 or hash_count >= 3:
            return InputDetection(
                input_type="ioc_list",
                confidence=0.85,
                suggested_tool="ioc_lookup",
                tool_chain=["ioc_lookup"],
                metadata={"ip_count": ip_count, "hash_count": hash_count},
            )

    return None


def get_tool_description() -> str:
    """返回输入格式检测器的工具描述（供 SYSTEM_PROMPT 使用）"""
    return (
        "输入格式自动检测：系统会自动识别输入类型（pcap/压缩包/二进制/配置文件/"
        "API文档/日志/Sigma规则/YARA规则/IoC列表）并路由到正确的工具链。"
        "用户无需手动指定工具，直接提供文件或内容即可。"
    )
