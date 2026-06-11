"""YARA Rule Engine — Parse and match YARA rules against files and memory.

YARA规则引擎：解析和匹配YARA规则。
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# 尝试导入yara-python
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python not installed. YARA engine will be disabled.")


@dataclass
class YaraRule:
    """YARA规则"""
    name: str
    namespace: str = "default"
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    source: str = ""


@dataclass
class YaraMatch:
    """YARA规则匹配结果"""
    rule: YaraRule
    matched_strings: list[dict[str, Any]]
    offset: int = 0
    length: int = 0
    confidence: float = 0.0
    severity: str = "medium"


class YaraEngine:
    """YARA规则引擎"""

    def __init__(self):
        self._rules: dict[str, YaraRule] = {}
        self._compiled_rules: Any = None
        self._is_dirty = True

    def load_rule(self, rule_source: str, namespace: str = "default") -> Optional[YaraRule]:
        """加载单个YARA规则"""
        if not YARA_AVAILABLE:
            logger.warning("YARA engine disabled: yara-python not installed")
            return None

        try:
            # 解析规则名称
            name = self._extract_rule_name(rule_source)
            if not name:
                logger.warning("Could not extract rule name from source")
                return None

            rule = YaraRule(
                name=name,
                namespace=namespace,
                source=rule_source,
                meta=self._extract_meta(rule_source),
                tags=self._extract_tags(rule_source),
            )

            self._rules[name] = rule
            self._is_dirty = True

            logger.debug("Loaded YARA rule: %s", name)
            return rule

        except Exception as e:
            logger.error("Failed to load YARA rule: %s", e)
            return None

    def load_from_file(self, file_path: str, namespace: str = "default") -> int:
        """从文件加载YARA规则"""
        path = Path(file_path)
        if not path.exists():
            logger.error("YARA rule file not found: %s", file_path)
            return 0

        try:
            content = path.read_text(encoding="utf-8")
            return self._load_rules_from_string(content, namespace)
        except Exception as e:
            logger.error("Failed to load YARA rules from file: %s", e)
            return 0

    def load_from_directory(self, directory: str) -> int:
        """从目录加载所有YARA规则"""
        path = Path(directory)
        if not path.is_dir():
            logger.error("Directory not found: %s", directory)
            return 0

        count = 0
        for yara_file in path.rglob("*.yar"):
            count += self.load_from_file(str(yara_file))

        for yara_file in path.rglob("*.yara"):
            count += self.load_from_file(str(yara_file))

        logger.info("Loaded %d YARA rules from %s", count, directory)
        return count

    def _load_rules_from_string(self, content: str, namespace: str = "default") -> int:
        """从字符串加载规则"""
        # 分割多个规则
        rules = self._split_rules(content)
        count = 0

        for rule_source in rules:
            if self.load_rule(rule_source, namespace):
                count += 1

        return count

    def _split_rules(self, content: str) -> list[str]:
        """分割多个YARA规则"""
        rules = []
        current_rule = []
        brace_count = 0
        in_rule = False

        for line in content.split("\n"):
            stripped = line.strip()

            # 检测规则开始
            if stripped.startswith("rule ") and not in_rule:
                in_rule = True
                current_rule = [line]
                brace_count = line.count("{") - line.count("}")
                # 单行规则（极少见）
                if brace_count == 0 and "{" in line:
                    rules.append("\n".join(current_rule))
                    current_rule = []
                    in_rule = False
                continue

            if in_rule:
                current_rule.append(line)
                brace_count += line.count("{") - line.count("}")

                # 规则结束
                if brace_count == 0:
                    rule_text = "\n".join(current_rule)
                    if "rule " in rule_text and "{" in rule_text:
                        rules.append(rule_text)
                    current_rule = []
                    in_rule = False

        return rules

    def _extract_rule_name(self, source: str) -> Optional[str]:
        """提取规则名称"""
        import re
        match = re.search(r'rule\s+(\w+)', source)
        return match.group(1) if match else None

    def _extract_meta(self, source: str) -> dict[str, Any]:
        """提取元数据"""
        import re
        meta = {}

        # 查找meta部分
        meta_match = re.search(r'meta:\s*\n((?:\s+\w+\s*=\s*.+\n?)+)', source)
        if meta_match:
            meta_text = meta_match.group(1)
            for line in meta_text.strip().split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"')
                    meta[key] = value

        return meta

    def _extract_tags(self, source: str) -> list[str]:
        """提取标签"""
        import re
        match = re.search(r'rule\s+\w+\s*:\s*(\w+(?:\s+\w+)*)', source)
        if match:
            return match.group(1).split()
        return []

    def _compile_rules(self) -> bool:
        """编译所有规则"""
        if not YARA_AVAILABLE or not self._rules:
            return False

        try:
            # 按命名空间组织规则
            sources = {}
            for rule in self._rules.values():
                if rule.namespace not in sources:
                    sources[rule.namespace] = ""
                sources[rule.namespace] += rule.source + "\n"

            self._compiled_rules = yara.compile(sources=sources)
            self._is_dirty = False
            return True

        except yara.Error as e:
            logger.error("Failed to compile YARA rules: %s", e)
            return False

    def match_file(self, file_path: str) -> list[YaraMatch]:
        """匹配文件"""
        if not YARA_AVAILABLE:
            logger.warning("YARA engine disabled")
            return []

        path = Path(file_path)
        if not path.exists():
            logger.error("File not found: %s", file_path)
            return []

        try:
            # 确保规则已编译
            if self._is_dirty:
                if not self._compile_rules():
                    return []

            # 匹配文件
            matches = self._compiled_rules.match(str(path))
            return self._convert_matches(matches)

        except yara.Error as e:
            logger.error("YARA match error: %s", e)
            return []
        except Exception as e:
            logger.error("Failed to match file: %s", e)
            return []

    def match_data(self, data: bytes) -> list[YaraMatch]:
        """匹配数据"""
        if not YARA_AVAILABLE:
            logger.warning("YARA engine disabled")
            return []

        try:
            # 确保规则已编译
            if self._is_dirty:
                if not self._compile_rules():
                    return []

            # 匹配数据
            matches = self._compiled_rules.match(data=data)
            return self._convert_matches(matches)

        except yara.Error as e:
            logger.error("YARA match error: %s", e)
            return []
        except Exception as e:
            logger.error("Failed to match data: %s", e)
            return []

    def _convert_matches(self, matches: Any) -> list[YaraMatch]:
        """转换匹配结果"""
        results = []

        for match in matches:
            rule = self._rules.get(match.rule)
            if not rule:
                # 创建临时规则对象
                rule = YaraRule(name=match.rule)

            # 提取匹配的字符串
            matched_strings = []
            for string_match in match.strings:
                matched_strings.append({
                    "identifier": string_match.identifier,
                    "offset": string_match.offset,
                    "data": string_match.data.hex() if isinstance(string_match.data, bytes) else str(string_match.data),
                })

            # 计算置信度
            confidence = self._calculate_confidence(rule, matched_strings)

            yara_match = YaraMatch(
                rule=rule,
                matched_strings=matched_strings,
                offset=matches[0].offset if matches else 0,
                length=sum(m.length for m in matches) if matches else 0,
                confidence=confidence,
                severity=rule.meta.get("severity", "medium"),
            )
            results.append(yara_match)

        return results

    def _calculate_confidence(self, rule: YaraRule, matched_strings: list[dict]) -> float:
        """计算匹配置信度"""
        # 基础置信度
        base = 0.7

        # 根据匹配字符串数量调整
        string_boost = min(len(matched_strings) * 0.05, 0.2)

        # 根据规则元数据调整
        if rule.meta.get("confidence"):
            try:
                base = float(rule.meta["confidence"])
            except (ValueError, TypeError):
                pass

        return min(base + string_boost, 1.0)

    def get_rule(self, name: str) -> Optional[YaraRule]:
        """获取规则"""
        return self._rules.get(name)

    def list_rules(self) -> list[dict[str, Any]]:
        """列出所有规则"""
        return [
            {
                "name": rule.name,
                "namespace": rule.namespace,
                "tags": rule.tags,
                "meta": rule.meta,
            }
            for rule in self._rules.values()
        ]

    def get_stats(self) -> dict[str, Any]:
        """获取统计信息"""
        return {
            "total_rules": len(self._rules),
            "yara_available": YARA_AVAILABLE,
            "compiled": not self._is_dirty,
            "namespaces": list(set(r.namespace for r in self._rules.values())),
        }


# 内置YARA规则（示例）
BUILTIN_YARA_RULES = """
rule Suspicious_PowerShell : powershell suspicious
{
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "CyberSec Agent"
        severity = "high"
        confidence = "0.8"

    strings:
        $a = "Invoke-Expression" nocase
        $b = "IEX" nocase
        $c = "DownloadString" nocase
        $d = "DownloadFile" nocase
        $e = "Net.WebClient" nocase
        $f = "FromBase64String" nocase
        $g = "EncodedCommand" nocase

    condition:
        2 of them
}

rule Suspicious_Network_Activity : network suspicious
{
    meta:
        description = "Detects suspicious network activity patterns"
        author = "CyberSec Agent"
        severity = "medium"
        confidence = "0.7"

    strings:
        $ip1 = /[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/
        $port1 = ":4444" ascii
        $port2 = ":5555" ascii
        $port3 = ":6666" ascii
        $port4 = ":7777" ascii
        $port5 = ":8888" ascii

    condition:
        any of ($port*) and $ip1
}

rule Base64_Encoded_PE : malware pe
{
    meta:
        description = "Detects base64 encoded PE files"
        author = "CyberSec Agent"
        severity = "critical"
        confidence = "0.9"

    strings:
        $mz = "TVqQAA" ascii  // Base64 for MZ header
        $pe = "PE" ascii wide

    condition:
        $mz at 0 and $pe in (0..1024)
}

rule Ransomware_Indicators : ransomware critical
{
    meta:
        description = "Detects common ransomware indicators"
        author = "CyberSec Agent"
        severity = "critical"
        confidence = "0.85"

    strings:
        $a = "Your files have been encrypted" nocase
        $b = "bitcoin" nocase
        $c = "decrypt" nocase
        $d = ".locked" ascii
        $e = ".encrypted" ascii
        $f = "README.txt" ascii

    condition:
        3 of them
}

rule Webshell_PHP_Generic : webshell persistence
{
    meta:
        description = "Detects common PHP webshell patterns"
        author = "CyberSec Agent"
        severity = "critical"
        confidence = "0.85"

    strings:
        $eval1 = "eval($_" ascii
        $eval2 = "eval(base64_decode" ascii
        $eval3 = "assert($_" ascii
        $exec1 = "exec($_" ascii
        $exec2 = "system($_" ascii
        $exec3 = "passthru($_" ascii
        $shell1 = "shell_exec($_" ascii
        $shell2 = "`$_" ascii
        $cmd1 = "cmd.exe" ascii
        $cmd2 = "/bin/sh" ascii
        $cmd3 = "/bin/bash" ascii
        $b64 = "base64_decode" ascii

    condition:
        (any of ($eval*) or any of ($exec*) or any of ($shell*)) and (any of ($cmd*) or $b64)
}

rule CobaltStrike_Beacon : c2 rat
{
    meta:
        description = "Detects Cobalt Strike Beacon artifacts"
        author = "CyberSec Agent"
        severity = "critical"
        confidence = "0.9"

    strings:
        $beacon1 = "beacon.dll" ascii
        $beacon2 = "beacon.x64.dll" ascii
        $beacon3 = "beacon.sys" ascii
        $config = "cobaltstrike" ascii nocase
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii
        $sleep_mask = "sleep_mask" ascii
        $hash_func = { 2B C1 0F AF C1 }

    condition:
        any of ($beacon*) or $config or any of ($pipe*) or ($sleep_mask and $hash_func)
}

rule Meterpreter_ReverseShell : rat backdoor
{
    meta:
        description = "Detects Meterpreter reverse shell payload"
        author = "CyberSec Agent"
        severity = "critical"
        confidence = "0.9"

    strings:
        $metsrv = "metsrv" ascii
        $stdapi = "stdapi" ascii
        $reverse_tcp = "reverse_tcp" ascii
        $reverse_http = "reverse_http" ascii
        $reverse_https = "reverse_https" ascii
        $payload1 = "payload/" ascii
        $payload2 = "windows/meterpreter" ascii

    condition:
        ($metsrv and $stdapi) or any of ($reverse_*) or all of ($payload*)
}

rule Cryptominer_Generic : impact miner
{
    meta:
        description = "Detects cryptocurrency mining software"
        author = "CyberSec Agent"
        severity = "high"
        confidence = "0.8"

    strings:
        $xmrig1 = "xmrig" ascii nocase
        $xmrig2 = "XMRig" ascii
        $pool1 = "stratum+tcp://" ascii
        $pool2 = "stratum+ssl://" ascii
        $pool3 = "pool.minexmr.com" ascii
        $pool4 = "xmrpool.eu" ascii
        $pool5 = "nanopool.org" ascii
        $miner1 = "cpuminer" ascii nocase
        $miner2 = "cgminer" ascii nocase
        $miner3 = "ethminer" ascii nocase
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase

    condition:
        any of ($xmrig*) or any of ($pool*) or any of ($miner*) or any of ($algo*)
}

rule ReverseShell_Script : execution backdoor
{
    meta:
        description = "Detects reverse shell scripts (bash/python/perl)"
        author = "CyberSec Agent"
        severity = "critical"
        confidence = "0.85"

    strings:
        $bash1 = "bash -i" ascii
        $bash2 = "/dev/tcp/" ascii
        $bash3 = "nc -e" ascii
        $bash4 = "ncat -e" ascii
        $bash5 = "mkfifo" ascii
        $python1 = "import socket" ascii
        $python2 = "import subprocess" ascii
        $python3 = "os.dup2" ascii
        $python4 = "pty.spawn" ascii
        $perl1 = "perl -MSocket" ascii
        $perl2 = "perl -e" ascii

    condition:
        (any of ($bash*)) or (2 of ($python*)) or (all of ($perl*))
}

rule Keylogger_Generic : collection spyware
{
    meta:
        description = "Detects keylogger indicators"
        author = "CyberSec Agent"
        severity = "high"
        confidence = "0.75"

    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "SetWindowsHookEx" ascii
        $api3 = "GetKeyState" ascii
        $api4 = "RegisterRawInputDevices" ascii
        $log1 = "keylog" ascii nocase
        $log2 = "keystroke" ascii nocase
        $log3 = "keylog.txt" ascii nocase

    condition:
        (2 of ($api*)) or (any of ($api*) and any of ($log*))
}

rule Data_Exfiltration_Tool : exfiltration
{
    meta:
        description = "Detects data exfiltration tools and patterns"
        author = "CyberSec Agent"
        severity = "high"
        confidence = "0.7"

    strings:
        $tool1 = "rclone" ascii nocase
        $tool2 = "megacmd" ascii nocase
        $tool3 = "gdrive" ascii nocase
        $tool4 = "s3cmd" ascii nocase
        $tool5 = "aws s3 cp" ascii
        $tool6 = "curl -T" ascii
        $tool7 = "wget --post-file" ascii
        $proto1 = "ftp://" ascii
        $proto2 = "sftp://" ascii
        $proto3 = "scp " ascii

    condition:
        any of ($tool*) or 2 of ($proto*)
}
"""
