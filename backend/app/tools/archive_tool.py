"""
Archive Analysis Tool — 解析压缩文件（ZIP/RAR/7Z/TAR）。

支持自动解压、文件类型识别、内容分析。
可串联其他工具进行深度分析。
"""

import os
import time
import hashlib
import zipfile
import tarfile
import tempfile
import logging
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)

# Magic bytes for archive formats
ZIP_MAGIC = b"PK\x03\x04"
RAR_MAGIC = b"Rar!\x1a\x07\x01\x00"
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"
GZIP_MAGIC = b"\x1f\x8b"
BZIP2_MAGIC = b"BZ"
TAR_MAGIC_OFFSET = 257  # tar magic at offset 257
TAR_MAGIC = b"ustar"

# Allowed base directories for file access
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_BACKEND_DATA = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
_ALLOWED_DIRS = [
    os.path.join(_PROJECT_ROOT, "data"),
    _BACKEND_DATA,
    "/tmp",
    tempfile.gettempdir(),
]

# Dangerous file patterns
DANGEROUS_PATTERNS = [
    "..",  # Path traversal
    "~",   # Backup files
    ".exe", ".bat", ".cmd", ".com", ".scr", ".ps1", ".vbs", ".js",  # Executables
]

# Maximum extraction size (500MB)
MAX_EXTRACT_SIZE = 500 * 1024 * 1024


def _validate_file_path(file_path: str) -> Optional[str]:
    """Validate that file_path is within allowed directories."""
    try:
        resolved = os.path.realpath(os.path.abspath(file_path))
    except (ValueError, OSError) as e:
        return f"无效路径: {e}"

    for allowed in _ALLOWED_DIRS:
        if resolved.startswith(os.path.abspath(allowed) + os.sep) or resolved == os.path.abspath(allowed):
            return None

    return f"路径不在允许的目录范围内: {file_path}"


def _detect_archive_type(file_path: str) -> str:
    """Detect archive type by magic bytes."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
        
        if header.startswith(ZIP_MAGIC):
            return "zip"
        elif header.startswith(RAR_MAGIC):
            return "rar"
        elif header.startswith(SEVENZ_MAGIC):
            return "7z"
        elif header.startswith(GZIP_MAGIC):
            return "gzip"
        elif header.startswith(BZIP2_MAGIC):
            return "bzip2"
        
        # Check for tar at offset 257
        with open(file_path, "rb") as f:
            f.seek(TAR_MAGIC_OFFSET)
            tar_header = f.read(5)
            if tar_header.startswith(TAR_MAGIC):
                return "tar"
        
        # Check file extension as fallback
        ext = Path(file_path).suffix.lower()
        if ext in [".zip"]:
            return "zip"
        elif ext in [".rar"]:
            return "rar"
        elif ext in [".7z"]:
            return "7z"
        elif ext in [".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2"]:
            return "tar"
        elif ext in [".gz"]:
            return "gzip"
        elif ext in [".bz2"]:
            return "bzip2"
        
        return "unknown"
    except Exception:
        return "unknown"


def _is_safe_path(member_path: str) -> bool:
    """Check if a member path is safe (no path traversal)."""
    # Normalize path
    normalized = os.path.normpath(member_path)
    
    # Check for path traversal
    if normalized.startswith("..") or ".." in normalized.split(os.sep):
        return False
    
    # Check for absolute paths
    if os.path.isabs(normalized):
        return False
    
    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if pattern in normalized.lower():
            return False
    
    return True


def _sha256_file(path: str) -> str:
    """Calculate SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _format_size(size_bytes: int) -> str:
    """Format file size to human readable."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


class ArchiveToolInput(ToolInput):
    """Archive Analysis Tool 输入"""

    file_path: str = Field(..., description="压缩文件的服务器路径")
    extract_to: Optional[str] = Field(default=None, description="解压目标目录（默认为临时目录）")
    max_files: int = Field(default=1000, description="最大处理文件数")
    analyze_content: bool = Field(default=True, description="是否分析压缩包内容")


class ArchiveAnalysisTool:
    """分析压缩文件，提取内容并识别文件类型"""

    name = "archive_analysis"
    version = "v1"
    input_class = ArchiveToolInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "archive_analysis",
                "description": (
                    "分析压缩文件（ZIP/RAR/7Z/TAR/GZIP/BZIP2）。"
                    "支持自动解压、文件类型识别、内容分析。"
                    "返回压缩包内文件列表、类型统计、可疑文件标记等信息。"
                    "\n\n分析完成后，建议按以下顺序串联其他工具："
                    "1. 对识别出的 pcap 文件使用 pcap_analysis 进行流量分析"
                    "2. 对识别出的二进制文件使用 binary_analysis 进行逆向分析"
                    "3. 对识别出的配置文件使用 config_parser 进行解析"
                    "4. 对识别出的代码文件使用 vuln_scan 进行漏洞扫描"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "压缩文件的服务器路径",
                        },
                        "extract_to": {
                            "type": "string",
                            "description": "解压目标目录（默认为临时目录）",
                        },
                        "max_files": {
                            "type": "integer",
                            "description": "最大处理文件数，默认 1000",
                        },
                        "analyze_content": {
                            "type": "boolean",
                            "description": "是否分析压缩包内容，默认 true",
                        },
                    },
                    "required": ["file_path"],
                },
            },
        }

    async def execute(self, input_data: ArchiveToolInput) -> ToolResult:
        start = time.time()

        # Validate path
        path_error = _validate_file_path(input_data.file_path)
        if path_error:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=path_error,
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

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

        # Detect archive type
        archive_type = _detect_archive_type(input_data.file_path)
        if archive_type == "unknown":
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="无法识别的压缩文件格式",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Get file info
        file_size = os.path.getsize(input_data.file_path)
        file_hash = _sha256_file(input_data.file_path)

        # Extract and analyze
        try:
            result = await self._extract_and_analyze(
                input_data.file_path,
                archive_type,
                input_data.extract_to,
                input_data.max_files,
                input_data.analyze_content,
            )
        except Exception as e:
            logger.error(f"Archive analysis failed: {e}")
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"压缩文件分析失败: {e}",
                confidence=0.0,
                evidence_source=["archive_analysis"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Build result
        execution_time_ms = int((time.time() - start) * 1000)

        # Identify files for further analysis
        files_for_analysis = self._identify_analysis_targets(result.get("files", []))

        result.update({
            "file_path": input_data.file_path,
            "file_name": os.path.basename(input_data.file_path),
            "file_size": file_size,
            "file_size_human": _format_size(file_size),
            "sha256": file_hash,
            "archive_type": archive_type,
            "extract_dir": result.get("extract_dir"),
            "files_for_analysis": files_for_analysis,
        })

        # Build summary
        summary_parts = [
            f"压缩文件: {os.path.basename(input_data.file_path)} ({archive_type.upper()})",
            f"文件大小: {_format_size(file_size)}",
            f"包含 {result.get('total_files', 0)} 个文件，总大小 {_format_size(result.get('total_extracted_size', 0))}",
        ]

        # File type statistics
        type_stats = result.get("type_statistics", {})
        if type_stats:
            stats_str = ", ".join([f"{k}: {v}" for k, v in list(type_stats.items())[:5]])
            summary_parts.append(f"文件类型分布: {stats_str}")

        # Suspicious files
        suspicious = result.get("suspicious_files", [])
        if suspicious:
            summary_parts.append(f"发现 {len(suspicious)} 个可疑文件:")
            for s in suspicious[:5]:
                summary_parts.append(f"  - {s['path']}: {s['reason']}")

        # Analysis targets
        if files_for_analysis:
            summary_parts.append(f"可串联分析的文件 ({len(files_for_analysis)} 个):")
            for target in files_for_analysis[:5]:
                summary_parts.append(f"  - {target['path']} ({target['suggested_tool']})")

        result["summary_text"] = "；".join(summary_parts)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result,
            error=None,
            confidence=0.9,
            evidence_source=["archive_analysis"],
            trace_id=input_data.trace_id,
            execution_time_ms=execution_time_ms,
        )

    async def _extract_and_analyze(
        self,
        file_path: str,
        archive_type: str,
        extract_to: Optional[str],
        max_files: int,
        analyze_content: bool,
    ) -> dict[str, Any]:
        """Extract archive and analyze contents."""
        # Create temp directory if not specified
        if extract_to is None:
            extract_to = tempfile.mkdtemp(prefix="cybersec_archive_")
        
        os.makedirs(extract_to, exist_ok=True)

        files = []
        total_extracted_size = 0
        suspicious_files = []
        type_statistics = {}

        if archive_type == "zip":
            files, total_extracted_size, suspicious_files, type_statistics = await self._extract_zip(
                file_path, extract_to, max_files, analyze_content
            )
        elif archive_type == "rar":
            files, total_extracted_size, suspicious_files, type_statistics = await self._extract_rar(
                file_path, extract_to, max_files, analyze_content
            )
        elif archive_type == "7z":
            files, total_extracted_size, suspicious_files, type_statistics = await self._extract_7z(
                file_path, extract_to, max_files, analyze_content
            )
        elif archive_type in ["tar", "gzip", "bzip2"]:
            files, total_extracted_size, suspicious_files, type_statistics = await self._extract_tar(
                file_path, extract_to, max_files, analyze_content, archive_type
            )

        return {
            "total_files": len(files),
            "total_extracted_size": total_extracted_size,
            "extract_dir": extract_to,
            "files": files,
            "suspicious_files": suspicious_files,
            "type_statistics": type_statistics,
        }

    async def _extract_zip(
        self, file_path: str, extract_to: str, max_files: int, analyze_content: bool
    ) -> tuple[list[dict], int, list[dict], dict[str, int]]:
        """Extract ZIP archive."""
        files = []
        total_size = 0
        suspicious = []
        type_stats = {}

        with zipfile.ZipFile(file_path, "r") as zf:
            for i, info in enumerate(zf.infolist()):
                if i >= max_files:
                    break

                # Safety check
                if not _is_safe_path(info.filename):
                    suspicious.append({
                        "path": info.filename,
                        "reason": "路径不安全（可能包含路径遍历）",
                        "risk_level": "high",
                    })
                    continue

                # Extract file
                try:
                    zf.extract(info, extract_to)
                    extracted_path = os.path.join(extract_to, info.filename)
                    
                    # Detect file type
                    file_type = self._detect_file_type(extracted_path)
                    type_stats[file_type] = type_stats.get(file_type, 0) + 1

                    file_info = {
                        "path": info.filename,
                        "size": info.file_size,
                        "size_human": _format_size(info.file_size),
                        "compressed_size": info.compress_size,
                        "type": file_type,
                        "extracted_path": extracted_path,
                    }

                    # Check for suspicious content
                    if analyze_content:
                        content_suspicious = self._check_suspicious_content(extracted_path, info.filename)
                        if content_suspicious:
                            suspicious.extend(content_suspicious)

                    files.append(file_info)
                    total_size += info.file_size

                except Exception as e:
                    logger.warning(f"Failed to extract {info.filename}: {e}")
                    suspicious.append({
                        "path": info.filename,
                        "reason": f"提取失败: {e}",
                        "risk_level": "medium",
                    })

        return files, total_size, suspicious, type_stats

    async def _extract_rar(
        self, file_path: str, extract_to: str, max_files: int, analyze_content: bool
    ) -> tuple[list[dict], int, list[dict], dict[str, int]]:
        """Extract RAR archive."""
        try:
            import rarfile
        except ImportError:
            raise RuntimeError("rarfile 模块未安装，请运行: pip install rarfile")

        files = []
        total_size = 0
        suspicious = []
        type_stats = {}

        with rarfile.RarFile(file_path, "r") as rf:
            for i, info in enumerate(rf.infolist()):
                if i >= max_files:
                    break

                # Safety check
                if not _is_safe_path(info.filename):
                    suspicious.append({
                        "path": info.filename,
                        "reason": "路径不安全",
                        "risk_level": "high",
                    })
                    continue

                try:
                    rf.extract(info, extract_to)
                    extracted_path = os.path.join(extract_to, info.filename)
                    
                    file_type = self._detect_file_type(extracted_path)
                    type_stats[file_type] = type_stats.get(file_type, 0) + 1

                    file_info = {
                        "path": info.filename,
                        "size": info.file_size,
                        "size_human": _format_size(info.file_size),
                        "type": file_type,
                        "extracted_path": extracted_path,
                    }

                    if analyze_content:
                        content_suspicious = self._check_suspicious_content(extracted_path, info.filename)
                        if content_suspicious:
                            suspicious.extend(content_suspicious)

                    files.append(file_info)
                    total_size += info.file_size

                except Exception as e:
                    logger.warning(f"Failed to extract {info.filename}: {e}")

        return files, total_size, suspicious, type_stats

    async def _extract_7z(
        self, file_path: str, extract_to: str, max_files: int, analyze_content: bool
    ) -> tuple[list[dict], int, list[dict], dict[str, int]]:
        """Extract 7Z archive."""
        try:
            import py7zr
        except ImportError:
            raise RuntimeError("py7zr 模块未安装，请运行: pip install py7zr")

        files = []
        total_size = 0
        suspicious = []
        type_stats = {}

        with py7zr.SevenZipFile(file_path, "r") as sz:
            # Get file list
            file_list = sz.getnames()
            
            for i, filename in enumerate(file_list[:max_files]):
                if not _is_safe_path(filename):
                    suspicious.append({
                        "path": filename,
                        "reason": "路径不安全",
                        "risk_level": "high",
                    })
                    continue

            # Extract all
            sz.extractall(extract_to)

            # Analyze extracted files
            for filename in file_list[:max_files]:
                extracted_path = os.path.join(extract_to, filename)
                if os.path.exists(extracted_path):
                    file_size = os.path.getsize(extracted_path)
                    file_type = self._detect_file_type(extracted_path)
                    type_stats[file_type] = type_stats.get(file_type, 0) + 1

                    file_info = {
                        "path": filename,
                        "size": file_size,
                        "size_human": _format_size(file_size),
                        "type": file_type,
                        "extracted_path": extracted_path,
                    }

                    if analyze_content:
                        content_suspicious = self._check_suspicious_content(extracted_path, filename)
                        if content_suspicious:
                            suspicious.extend(content_suspicious)

                    files.append(file_info)
                    total_size += file_size

        return files, total_size, suspicious, type_stats

    async def _extract_tar(
        self, file_path: str, extract_to: str, max_files: int, analyze_content: bool, archive_type: str
    ) -> tuple[list[dict], int, list[dict], dict[str, int]]:
        """Extract TAR/GZIP/BZIP2 archive."""
        files = []
        total_size = 0
        suspicious = []
        type_stats = {}

        mode = "r"
        if archive_type == "gzip":
            mode = "r:gz"
        elif archive_type == "bzip2":
            mode = "r:bz2"

        with tarfile.open(file_path, mode) as tf:
            members = tf.getmembers()
            
            for i, member in enumerate(members[:max_files]):
                if not member.isfile():
                    continue

                # Safety check
                if not _is_safe_path(member.name):
                    suspicious.append({
                        "path": member.name,
                        "reason": "路径不安全",
                        "risk_level": "high",
                    })
                    continue

                try:
                    tf.extract(member, extract_to)
                    extracted_path = os.path.join(extract_to, member.name)
                    
                    file_type = self._detect_file_type(extracted_path)
                    type_stats[file_type] = type_stats.get(file_type, 0) + 1

                    file_info = {
                        "path": member.name,
                        "size": member.size,
                        "size_human": _format_size(member.size),
                        "type": file_type,
                        "extracted_path": extracted_path,
                    }

                    if analyze_content:
                        content_suspicious = self._check_suspicious_content(extracted_path, member.name)
                        if content_suspicious:
                            suspicious.extend(content_suspicious)

                    files.append(file_info)
                    total_size += member.size

                except Exception as e:
                    logger.warning(f"Failed to extract {member.name}: {e}")

        return files, total_size, suspicious, type_stats

    def _detect_file_type(self, file_path: str) -> str:
        """Detect file type by magic bytes and extension."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
        except Exception:
            return "unknown"

        # Check magic bytes
        if header.startswith(b"MZ"):
            return "PE_EXE"
        elif header.startswith(b"\x7fELF"):
            return "ELF"
        elif header.startswith(b"\xfe\xed\xfa") or header.startswith(b"\xfe\xed\xfa\xce"):
            return "Mach-O"
        elif header.startswith(b"\xca\xfe\xba\xbe"):
            return "Java_Class"
        elif header.startswith(b"%PDF"):
            return "PDF"
        elif header.startswith(b"PK\x03\x04"):
            return "ZIP"
        elif header.startswith(b"Rar!"):
            return "RAR"
        elif header.startswith(b"7z\xbc\xaf"):
            return "7Z"
        elif header.startswith(b"\x1f\x8b"):
            return "GZIP"
        elif header.startswith(b"\xd4\xc3\xb2\xa1") or header.startswith(b"\x0a\x0d\x0d\x0a"):
            return "PCAP"
        elif header.startswith(b"GIF8"):
            return "GIF"
        elif header.startswith(b"\x89PNG"):
            return "PNG"
        elif header.startswith(b"\xff\xd8\xff"):
            return "JPEG"
        elif header.startswith(b"<?xml"):
            return "XML"
        elif header.startswith(b"{") or header.startswith(b"["):
            return "JSON"

        # Check extension
        ext = Path(file_path).suffix.lower()
        ext_map = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".java": "Java",
            ".c": "C",
            ".cpp": "C++",
            ".h": "C_Header",
            ".cs": "CSharp",
            ".go": "Go",
            ".rs": "Rust",
            ".rb": "Ruby",
            ".php": "PHP",
            ".sh": "Shell",
            ".bat": "Batch",
            ".ps1": "PowerShell",
            ".yaml": "YAML",
            ".yml": "YAML",
            ".json": "JSON",
            ".xml": "XML",
            ".html": "HTML",
            ".htm": "HTML",
            ".css": "CSS",
            ".sql": "SQL",
            ".md": "Markdown",
            ".txt": "Text",
            ".log": "Log",
            ".csv": "CSV",
            ".conf": "Config",
            ".cfg": "Config",
            ".ini": "Config",
            ".env": "Env_File",
        }

        return ext_map.get(ext, "unknown")

    def _check_suspicious_content(self, file_path: str, filename: str) -> list[dict]:
        """Check file content for suspicious patterns."""
        suspicious = []
        
        # Check for suspicious patterns in filename
        suspicious_patterns = [
            ("password", "可能包含密码"),
            ("secret", "可能包含密钥"),
            ("key", "可能包含密钥"),
            ("token", "可能包含令牌"),
            ("credential", "可能包含凭据"),
            ("dump", "可能是数据转储"),
            ("payload", "可能是载荷文件"),
            ("exploit", "可能是漏洞利用"),
            ("shellcode", "可能是 Shellcode"),
            ("backdoor", "可能是后门"),
        ]

        filename_lower = filename.lower()
        for pattern, reason in suspicious_patterns:
            if pattern in filename_lower:
                suspicious.append({
                    "path": filename,
                    "reason": reason,
                    "risk_level": "medium",
                })
                break

        # Check for encoded/obfuscated content
        try:
            with open(file_path, "rb") as f:
                content = f.read(1024)  # Read first 1KB
                
                # Check for base64 encoded content
                if self._is_likely_base64(content):
                    suspicious.append({
                        "path": filename,
                        "reason": "可能包含 Base64 编码内容",
                        "risk_level": "low",
                    })

                # Check for hex encoded content
                if self._is_likely_hex(content):
                    suspicious.append({
                        "path": filename,
                        "reason": "可能包含十六进制编码内容",
                        "risk_level": "low",
                    })

        except Exception:
            pass

        return suspicious

    def _is_likely_base64(self, content: bytes) -> bool:
        """Check if content looks like base64."""
        try:
            import base64
            # Check if content is valid base64
            decoded = base64.b64decode(content)
            return len(decoded) > 0
        except Exception:
            return False

    def _is_likely_hex(self, content: bytes) -> bool:
        """Check if content looks like hex encoded."""
        try:
            text = content.decode("ascii", errors="ignore")
            # Check if mostly hex characters
            hex_chars = sum(1 for c in text if c in "0123456789abcdefABCDEF")
            return hex_chars > len(text) * 0.8 and len(text) > 10
        except Exception:
            return False

    def _identify_analysis_targets(self, files: list[dict]) -> list[dict]:
        """Identify files that should be analyzed with other tools."""
        targets = []
        
        for file_info in files:
            file_type = file_info.get("type", "unknown")
            path = file_info.get("path", "")
            
            # Map file types to suggested tools
            tool_mapping = {
                "PCAP": "pcap_analysis",
                "PE_EXE": "binary_analysis",
                "ELF": "binary_analysis",
                "Mach-O": "binary_analysis",
                "Python": "vuln_scan",
                "JavaScript": "vuln_scan",
                "Java": "vuln_scan",
                "C": "vuln_scan",
                "C++": "vuln_scan",
                "PHP": "vuln_scan",
                "JSON": "config_parser",
                "YAML": "config_parser",
                "XML": "config_parser",
                "Config": "config_parser",
                "Env_File": "config_parser",
                "Log": "log_analysis",
                "Shell": "vuln_scan",
                "Batch": "vuln_scan",
                "PowerShell": "vuln_scan",
            }
            
            suggested_tool = tool_mapping.get(file_type)
            if suggested_tool:
                targets.append({
                    "path": path,
                    "type": file_type,
                    "suggested_tool": suggested_tool,
                    "extracted_path": file_info.get("extracted_path"),
                })

        return targets


archive_tool = ArchiveAnalysisTool()
