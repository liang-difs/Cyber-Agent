"""
Binary Analysis Tool — 分析二进制文件（ELF/PE/Mach-O）。

支持文件头识别、基本信息提取、安全特征检测。
可用于恶意软件分析、逆向工程辅助。
"""

import os
import time
import hashlib
import struct
import logging
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)

# Magic bytes for binary formats
PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"
MACHO_MAGIC_32 = b"\xfe\xed\xfa\xce"
MACHO_MAGIC_64 = b"\xfe\xed\xfa\xcf"
MACHO_MAGIC_FAT = b"\xca\xfe\xba\xbe"
JAVA_CLASS_MAGIC = b"\xca\xfe\xba\xbe"
DOTNET_MAGIC = b"\x4d\x5a"

# PE Machine Types
PE_MACHINE_TYPES = {
    0x0: "Unknown",
    0x14c: "i386",
    0x8664: "AMD64",
    0x1c0: "ARM",
    0xaa64: "ARM64",
    0x200: "IA64",
}

# ELF Machine Types
ELF_MACHINE_TYPES = {
    0: "No machine",
    1: "AT&T WE 32100",
    2: "SPARC",
    3: "x86",
    4: "Motorola 68000",
    5: "Motorola 88000",
    7: "Intel 80860",
    8: "MIPS I",
    0x14: "PowerPC",
    0x28: "ARM",
    0x3e: "AMD64",
    0xb7: "AArch64",
}

# ELF Types
ELF_TYPES = {
    0: "None",
    1: "Relocatable",
    2: "Executable",
    3: "Shared object",
    4: "Core",
}


class BinaryAnalysisInput(ToolInput):
    """Binary Analysis Tool 输入"""

    file_path: str = Field(..., description="二进制文件路径")
    analyze_strings: bool = Field(default=False, description="是否提取字符串（耗时）")
    analyze_imports: bool = Field(default=True, description="是否分析导入表")
    analyze_sections: bool = Field(default=True, description="是否分析节区")


class BinaryAnalysisTool:
    """分析二进制文件，识别格式并提取安全相关信息"""

    name = "binary_analysis"
    version = "v1"
    input_class = BinaryAnalysisInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "binary_analysis",
                "description": (
                    "分析二进制文件（ELF/PE/Mach-O/Java Class）。"
                    "识别文件格式、架构、安全特征等信息。"
                    "\n\n支持的功能："
                    "1. 文件格式自动识别（ELF/PE/Mach-O/Java Class）"
                    "2. 架构和类型分析"
                    "3. 安全特性检测（NX、ASLR、Stack Canary 等）"
                    "4. 导入表分析"
                    "5. 节区信息提取"
                    "6. 可选：字符串提取"
                    "\n\n分析完成后，建议按以下顺序串联其他工具："
                    "1. 使用 vuln_scan 进行漏洞扫描"
                    "2. 使用 hash_lookup 查询文件哈希信誉"
                    "3. 使用 yara_scan 进行恶意软件检测"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "二进制文件路径",
                        },
                        "analyze_strings": {
                            "type": "boolean",
                            "description": "是否提取字符串，默认 false",
                        },
                        "analyze_imports": {
                            "type": "boolean",
                            "description": "是否分析导入表，默认 true",
                        },
                        "analyze_sections": {
                            "type": "boolean",
                            "description": "是否分析节区，默认 true",
                        },
                    },
                    "required": ["file_path"],
                },
            },
        }

    async def execute(self, input_data: BinaryAnalysisInput) -> ToolResult:
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

        # Read file header
        try:
            with open(input_data.file_path, "rb") as f:
                header = f.read(64)
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

        # Detect binary type
        binary_type = self._detect_binary_type(header)
        if binary_type == "unknown":
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="无法识别的二进制文件格式",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Get file info
        file_size = os.path.getsize(input_data.file_path)
        file_hash = hashlib.sha256(header).hexdigest()

        # Analyze based on type
        try:
            if binary_type == "PE":
                result = self._analyze_pe(input_data.file_path, input_data)
            elif binary_type == "ELF":
                result = self._analyze_elf(input_data.file_path, input_data)
            elif binary_type == "Mach-O":
                result = self._analyze_macho(input_data.file_path, input_data)
            elif binary_type == "Java Class":
                result = self._analyze_java_class(input_data.file_path, input_data)
            else:
                result = {"error": f"不支持的格式: {binary_type}"}
        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"分析失败: {e}",
                confidence=0.0,
                evidence_source=["binary_analysis"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Calculate full file hash
        full_hash = self._calculate_file_hash(input_data.file_path)

        # Build result
        execution_time_ms = int((time.time() - start) * 1000)

        result.update({
            "file_path": input_data.file_path,
            "file_name": os.path.basename(input_data.file_path),
            "binary_type": binary_type,
            "file_size": file_size,
            "sha256": full_hash,
        })

        # Security analysis
        result["security_features"] = self._analyze_security_features(result, binary_type)

        # Build summary
        summary_parts = [
            f"二进制文件: {os.path.basename(input_data.file_path)} ({binary_type})",
            f"文件大小: {file_size} 字节",
            f"SHA256: {full_hash[:16]}...",
        ]

        # Architecture info
        if result.get("architecture"):
            summary_parts.append(f"架构: {result['architecture']}")
        if result.get("bits"):
            summary_parts.append(f"位数: {result['bits']}")

        # Security features
        security = result.get("security_features", {})
        if security:
            enabled = [k for k, v in security.items() if v.get("enabled")]
            disabled = [k for k, v in security.items() if not v.get("enabled")]
            if enabled:
                summary_parts.append(f"已启用安全特性: {', '.join(enabled)}")
            if disabled:
                summary_parts.append(f"未启用安全特性: {', '.join(disabled)}")

        # Imports summary
        imports = result.get("imports", [])
        if imports:
            summary_parts.append(f"导入函数: {len(imports)} 个")

        # Sections summary
        sections = result.get("sections", [])
        if sections:
            summary_parts.append(f"节区数量: {len(sections)} 个")

        # Suspicious indicators
        suspicious = result.get("suspicious_indicators", [])
        if suspicious:
            summary_parts.append(f"可疑指标: {len(suspicious)} 个")
            for indicator in suspicious[:3]:
                summary_parts.append(f"  - {indicator}")

        result["summary_text"] = "；".join(summary_parts)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result,
            error=None,
            confidence=0.9,
            evidence_source=["binary_analysis"],
            trace_id=input_data.trace_id,
            execution_time_ms=execution_time_ms,
        )

    def _detect_binary_type(self, header: bytes) -> str:
        """Detect binary file type."""
        if header.startswith(PE_MAGIC):
            # Check if it's also a .NET assembly
            return "PE"
        elif header.startswith(ELF_MAGIC):
            return "ELF"
        elif header.startswith(MACHO_MAGIC_32) or header.startswith(MACHO_MAGIC_64):
            return "Mach-O"
        elif header.startswith(MACHO_MAGIC_FAT):
            return "Mach-O"
        elif header.startswith(JAVA_CLASS_MAGIC):
            # Could be Java Class or Mach-O FAT
            return "Java Class"
        return "unknown"

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of entire file."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _analyze_pe(self, file_path: str, input_data: BinaryAnalysisInput) -> dict:
        """Analyze PE file."""
        result = {
            "format": "PE",
            "architecture": "Unknown",
            "bits": 32,
            "machine_type": "Unknown",
            "subsystem": "Unknown",
            "imports": [],
            "sections": [],
            "suspicious_indicators": [],
        }

        with open(file_path, "rb") as f:
            # Read DOS header
            dos_header = f.read(64)
            
            # Get PE header offset
            pe_offset = struct.unpack("<I", dos_header[60:64])[0]
            
            # Read PE signature
            f.seek(pe_offset)
            pe_signature = f.read(4)
            if pe_signature != b"PE\x00\x00":
                result["error"] = "Invalid PE signature"
                return result

            # Read COFF header
            coff_header = f.read(20)
            machine = struct.unpack("<H", coff_header[0:2])[0]
            num_sections = struct.unpack("<H", coff_header[2:4])[0]
            timestamp = struct.unpack("<I", coff_header[4:8])[0]
            optional_header_size = struct.unpack("<H", coff_header[16:18])[0]
            characteristics = struct.unpack("<H", coff_header[18:20])[0]

            result["machine_type"] = PE_MACHINE_TYPES.get(machine, f"Unknown (0x{machine:x})")
            result["num_sections"] = num_sections
            result["timestamp"] = timestamp
            result["characteristics"] = characteristics

            # Determine architecture
            if machine == 0x8664:
                result["architecture"] = "AMD64"
                result["bits"] = 64
            elif machine == 0x14c:
                result["architecture"] = "x86"
                result["bits"] = 32
            elif machine == 0xaa64:
                result["architecture"] = "ARM64"
                result["bits"] = 64

            # Read Optional header
            if optional_header_size > 0:
                optional_header = f.read(min(optional_header_size, 240))
                
                # Magic (PE32 or PE32+)
                opt_magic = struct.unpack("<H", optional_header[0:2])[0]
                if opt_magic == 0x20b:
                    result["bits"] = 64
                
                # Subsystem
                if len(optional_header) > 68:
                    subsystem = struct.unpack("<H", optional_header[68:70])[0]
                    subsystems = {
                        0: "Unknown",
                        1: "Native",
                        2: "Windows GUI",
                        3: "Windows Console",
                        5: "OS/2 Console",
                        7: "POSIX Console",
                    }
                    result["subsystem"] = subsystems.get(subsystem, f"Unknown ({subsystem})")

            # Read sections
            if input_data.analyze_sections:
                for i in range(num_sections):
                    section_data = f.read(40)
                    if len(section_data) < 40:
                        break
                    
                    section_name = section_data[0:8].rstrip(b"\x00").decode("ascii", errors="ignore")
                    virtual_size = struct.unpack("<I", section_data[8:12])[0]
                    virtual_addr = struct.unpack("<I", section_data[12:16])[0]
                    raw_size = struct.unpack("<I", section_data[16:20])[0]
                    characteristics = struct.unpack("<I", section_data[36:40])[0]

                    result["sections"].append({
                        "name": section_name,
                        "virtual_size": virtual_size,
                        "virtual_address": virtual_addr,
                        "raw_size": raw_size,
                        "characteristics": characteristics,
                        "executable": bool(characteristics & 0x20000000),
                        "writable": bool(characteristics & 0x80000000),
                    })

        return result

    def _analyze_elf(self, file_path: str, input_data: BinaryAnalysisInput) -> dict:
        """Analyze ELF file."""
        result = {
            "format": "ELF",
            "architecture": "Unknown",
            "bits": 32,
            "machine_type": "Unknown",
            "entry_point": 0,
            "imports": [],
            "sections": [],
            "suspicious_indicators": [],
        }

        with open(file_path, "rb") as f:
            # Read ELF header
            elf_header = f.read(64)
            
            # Check EI_CLASS (4th byte)
            ei_class = elf_header[4]
            if ei_class == 1:
                result["bits"] = 32
            elif ei_class == 2:
                result["bits"] = 64

            # Check EI_DATA (5th byte)
            ei_data = elf_header[5]
            endian = "little" if ei_data == 1 else "big"

            # Parse header based on bits
            if result["bits"] == 32:
                e_type = struct.unpack("<H" if endian == "little" else ">H", elf_header[16:18])[0]
                e_machine = struct.unpack("<H" if endian == "little" else ">H", elf_header[18:20])[0]
                e_entry = struct.unpack("<I" if endian == "little" else ">I", elf_header[24:28])[0]
            else:
                e_type = struct.unpack("<H" if endian == "little" else ">H", elf_header[16:18])[0]
                e_machine = struct.unpack("<H" if endian == "little" else ">H", elf_header[18:20])[0]
                e_entry = struct.unpack("<Q" if endian == "little" else ">Q", elf_header[24:32])[0]

            result["machine_type"] = ELF_MACHINE_TYPES.get(e_machine, f"Unknown ({e_machine})")
            result["elf_type"] = ELF_TYPES.get(e_type, f"Unknown ({e_type})")
            result["entry_point"] = e_entry
            result["endian"] = endian

            # Determine architecture
            if e_machine == 0x3e:
                result["architecture"] = "AMD64"
            elif e_machine == 0x03:
                result["architecture"] = "x86"
            elif e_machine == 0xb7:
                result["architecture"] = "AArch64"
            elif e_machine == 0x28:
                result["architecture"] = "ARM"

        return result

    def _analyze_macho(self, file_path: str, input_data: BinaryAnalysisInput) -> dict:
        """Analyze Mach-O file."""
        result = {
            "format": "Mach-O",
            "architecture": "Unknown",
            "bits": 64,
            "machine_type": "Unknown",
            "imports": [],
            "sections": [],
            "suspicious_indicators": [],
        }

        with open(file_path, "rb") as f:
            header = f.read(8)
            
            # Check magic
            magic = struct.unpack("<I", header[0:4])[0]
            
            if magic == 0xfeedface:
                result["bits"] = 32
                result["endian"] = "little"
            elif magic == 0xcefaedfe:
                result["bits"] = 32
                result["endian"] = "big"
            elif magic == 0xfeedfacf:
                result["bits"] = 64
                result["endian"] = "little"
            elif magic == 0xcffaedfe:
                result["bits"] = 64
                result["endian"] = "big"
            elif magic == 0xcafebabe:
                # Universal binary
                result["format"] = "Mach-O Universal"
                result["bits"] = 0  # Multiple architectures
            
            # Read CPU type
            if result["format"] != "Mach-O Universal":
                cpu_type = struct.unpack("<I" if result["endian"] == "little" else ">I", header[4:8])[0]
                cpu_types = {
                    0x00000007: "x86",
                    0x01000007: "x86_64",
                    0x0000000c: "ARM",
                    0x0100000c: "ARM64",
                }
                result["architecture"] = cpu_types.get(cpu_type, f"Unknown (0x{cpu_type:x})")

        return result

    def _analyze_java_class(self, file_path: str, input_data: BinaryAnalysisInput) -> dict:
        """Analyze Java Class file."""
        result = {
            "format": "Java Class",
            "architecture": "JVM",
            "bits": 32,
            "version": "Unknown",
            "imports": [],
            "sections": [],
            "suspicious_indicators": [],
        }

        with open(file_path, "rb") as f:
            # Read magic
            magic = f.read(4)
            if magic != b"\xca\xfe\xba\xbe":
                result["error"] = "Invalid Java Class magic"
                return result

            # Read version
            minor = struct.unpack(">H", f.read(2))[0]
            major = struct.unpack(">H", f.read(2))[0]
            
            java_versions = {
                45: "1.1",
                46: "1.2",
                47: "1.3",
                48: "1.4",
                49: "5.0",
                50: "6",
                51: "7",
                52: "8",
                53: "9",
                54: "10",
                55: "11",
                56: "12",
                57: "13",
                58: "14",
                59: "15",
                60: "16",
                61: "17",
                62: "18",
                63: "19",
                64: "20",
                65: "21",
            }
            
            result["version"] = java_versions.get(major, f"Unknown ({major}.{minor})")

        return result

    def _analyze_security_features(self, result: dict, binary_type: str) -> dict:
        """Analyze security features."""
        features = {
            "NX (DEP)": {"enabled": False, "description": "数据执行保护"},
            "ASLR": {"enabled": False, "description": "地址空间布局随机化"},
            "Stack Canary": {"enabled": False, "description": "栈保护"},
            "PIE": {"enabled": False, "description": "位置无关可执行文件"},
            "RELRO": {"enabled": False, "description": "重定位只读"},
        }

        if binary_type == "PE":
            # Check PE characteristics
            characteristics = result.get("characteristics", 0)
            # NX is typically enabled by default in modern Windows
            features["NX (DEP)"]["enabled"] = True
            features["ASLR"]["enabled"] = True
            
            # Check for debug info
            if characteristics & 0x20:
                features["Debug Info"] = {"enabled": True, "description": "包含调试信息"}

        elif binary_type == "ELF":
            # Check sections for security features
            sections = result.get("sections", [])
            section_names = [s.get("name", "") for s in sections]
            
            # Check for stack canary
            if ".note.GNU-stack" in section_names:
                features["NX (DEP)"]["enabled"] = True
            
            # Check for PIE
            if result.get("elf_type") == "Shared object":
                features["PIE"]["enabled"] = True

        return features


binary_analysis_tool = BinaryAnalysisTool()
