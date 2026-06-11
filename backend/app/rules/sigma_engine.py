"""Sigma Rule Engine — Parse and match Sigma rules against log data.

Sigma规则引擎：解析和匹配Sigma规则。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class SigmaRule:
    """Sigma规则"""
    title: str
    id: str
    description: str
    status: str = "experimental"
    author: str = ""
    date: str = ""
    modified: str = ""
    tags: list[str] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    level: str = "medium"  # informational, low, medium, high, critical
    references: list[str] = field(default_factory=list)
    raw_yaml: str = ""


@dataclass
class SigmaMatch:
    """Sigma规则匹配结果"""
    rule: SigmaRule
    matched_conditions: list[str]
    matched_events: list[dict[str, Any]]
    confidence: float = 0.0
    severity: str = "medium"


class SigmaEngine:
    """Sigma规则引擎"""

    def __init__(self):
        self._rules: dict[str, SigmaRule] = {}
        self._rules_by_tag: dict[str, list[str]] = {}
        self._rules_by_level: dict[str, list[str]] = {}

    def load_rule(self, yaml_content: str) -> Optional[SigmaRule]:
        """加载单个Sigma规则"""
        try:
            data = yaml.safe_load(yaml_content)
            if not isinstance(data, dict):
                logger.warning("Invalid Sigma rule format")
                return None

            rule = SigmaRule(
                title=data.get("title", ""),
                id=data.get("id", ""),
                description=data.get("description", ""),
                status=data.get("status", "experimental"),
                author=data.get("author", ""),
                date=str(data.get("date", "")),
                modified=str(data.get("modified", "")),
                tags=data.get("tags", []),
                logsource=data.get("logsource", {}),
                detection=data.get("detection", {}),
                falsepositives=data.get("falsepositives", []),
                level=data.get("level", "medium"),
                references=data.get("references", []),
                raw_yaml=yaml_content,
            )

            if rule.id:
                self._rules[rule.id] = rule
                self._index_rule(rule)
                logger.debug("Loaded Sigma rule: %s", rule.title)
                return rule
            else:
                logger.warning("Sigma rule missing ID")
                return None

        except yaml.YAMLError as e:
            logger.error("Failed to parse Sigma rule YAML: %s", e)
            return None
        except Exception as e:
            logger.error("Failed to load Sigma rule: %s", e)
            return None

    def load_from_file(self, file_path: str) -> int:
        """从文件加载Sigma规则"""
        path = Path(file_path)
        if not path.exists():
            logger.error("Sigma rule file not found: %s", file_path)
            return 0

        try:
            content = path.read_text(encoding="utf-8")
            if path.suffix in (".yml", ".yaml"):
                # 单个规则或规则列表
                data = yaml.safe_load(content)
                if isinstance(data, list):
                    count = 0
                    for item in data:
                        yaml_str = yaml.dump(item)
                        if self.load_rule(yaml_str):
                            count += 1
                    return count
                else:
                    return 1 if self.load_rule(content) else 0
            else:
                return 1 if self.load_rule(content) else 0
        except Exception as e:
            logger.error("Failed to load Sigma rules from file: %s", e)
            return 0

    def load_from_directory(self, directory: str) -> int:
        """从目录加载所有Sigma规则"""
        path = Path(directory)
        if not path.is_dir():
            logger.error("Directory not found: %s", directory)
            return 0

        count = 0
        for yaml_file in path.rglob("*.yml"):
            if self.load_from_file(str(yaml_file)):
                count += 1

        for yaml_file in path.rglob("*.yaml"):
            if self.load_from_file(str(yaml_file)):
                count += 1

        logger.info("Loaded %d Sigma rules from %s", count, directory)
        return count

    def _load_rules_from_string(self, content: str) -> int:
        """从字符串加载多个Sigma规则"""
        try:
            # 分割多个规则（以---分隔）
            rules = content.split("---")
            count = 0

            for rule_yaml in rules:
                rule_yaml = rule_yaml.strip()
                if not rule_yaml:
                    continue

                # 检查是否包含规则内容
                if "title:" not in rule_yaml:
                    continue

                # 确保以---开头
                if not rule_yaml.startswith("---"):
                    rule_yaml = "---\n" + rule_yaml

                if self.load_rule(rule_yaml):
                    count += 1

            return count

        except Exception as e:
            logger.error("Failed to load rules from string: %s", e)
            return 0

    def _index_rule(self, rule: SigmaRule) -> None:
        """索引规则"""
        # 按标签索引
        for tag in rule.tags:
            if tag not in self._rules_by_tag:
                self._rules_by_tag[tag] = []
            if rule.id not in self._rules_by_tag[tag]:
                self._rules_by_tag[tag].append(rule.id)

        # 按级别索引
        level = rule.level.lower()
        if level not in self._rules_by_level:
            self._rules_by_level[level] = []
        if rule.id not in self._rules_by_level[level]:
            self._rules_by_level[level].append(rule.id)

    def match_event(self, event: dict[str, Any], logsource: dict[str, str] = None) -> list[SigmaMatch]:
        """匹配单个事件"""
        matches = []

        for rule_id, rule in self._rules.items():
            # 检查日志源匹配
            if logsource and not self._match_logsource(rule.logsource, logsource):
                continue

            # 检测条件
            matched_conditions = self._evaluate_detection(rule.detection, event)
            if matched_conditions:
                match = SigmaMatch(
                    rule=rule,
                    matched_conditions=matched_conditions,
                    matched_events=[event],
                    confidence=self._calculate_confidence(rule, matched_conditions),
                    severity=rule.level,
                )
                matches.append(match)

        return matches

    def match_events(self, events: list[dict[str, Any]], logsource: dict[str, str] = None) -> list[SigmaMatch]:
        """匹配多个事件"""
        all_matches = []

        for event in events:
            matches = self.match_event(event, logsource)
            all_matches.extend(matches)

        # 合并相同规则的匹配
        merged = self._merge_matches(all_matches)
        return merged

    def _match_logsource(self, rule_logsource: dict[str, str], event_logsource: dict[str, str]) -> bool:
        """匹配日志源"""
        for key, value in rule_logsource.items():
            if key not in event_logsource:
                return False
            if event_logsource[key].lower() != value.lower():
                return False
        return True

    def _evaluate_detection(self, detection: dict[str, Any], event: dict[str, Any]) -> list[str]:
        """评估检测条件"""
        matched = []

        # 提取选择器（排除condition、timeframe等关键字）
        selectors = {k: v for k, v in detection.items() if k not in ("condition", "timeframe", "fields")}

        # 评估每个选择器
        selector_results = {}
        for selector_name, conditions in selectors.items():
            if self._match_selector(conditions, event):
                selector_results[selector_name] = True
                matched.append(selector_name)
            else:
                selector_results[selector_name] = False

        # 评估条件表达式
        condition = detection.get("condition", "")
        if condition:
            if self._evaluate_condition(condition, selector_results):
                if not matched:
                    matched.append("condition_match")
            else:
                # 条件不满足，清除匹配
                matched.clear()

        return matched

    def _match_selector(self, conditions: Any, event: dict[str, Any]) -> bool:
        """匹配选择器条件"""
        if isinstance(conditions, dict):
            # 字段匹配
            for field_name, expected in conditions.items():
                actual = self._get_nested_value(event, field_name)
                if actual is None:
                    return False
                if not self._match_value(actual, expected):
                    return False
            return True

        elif isinstance(conditions, list):
            # OR条件
            for condition in conditions:
                if isinstance(condition, dict):
                    if self._match_selector(condition, event):
                        return True
            return False

        return False

    def _match_value(self, actual: Any, expected: Any) -> bool:
        """匹配值"""
        if isinstance(expected, str):
            # 字符串匹配（支持通配符）
            if "*" in expected:
                pattern = expected.replace("*", ".*")
                return bool(re.match(pattern, str(actual), re.IGNORECASE))
            return str(actual).lower() == expected.lower()
        elif isinstance(expected, list):
            # 列表匹配（OR）
            return any(self._match_value(actual, exp) for exp in expected)
        elif isinstance(expected, dict):
            # 复杂匹配
            if "contains" in expected:
                return expected["contains"].lower() in str(actual).lower()
            if "startswith" in expected:
                return str(actual).lower().startswith(expected["startswith"].lower())
            if "endswith" in expected:
                return str(actual).lower().endswith(expected["endswith"].lower())
            if "re" in expected:
                return bool(re.search(expected["re"], str(actual), re.IGNORECASE))
        return actual == expected

    def _get_nested_value(self, data: dict, key: str) -> Any:
        """获取嵌套值"""
        keys = key.split(".")
        value = data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return None
        return value

    def _evaluate_condition(self, condition: str, results: dict[str, bool]) -> bool:
        """评估条件表达式 — 支持 AND、OR、NOT 和嵌套括号"""
        condition = condition.strip()

        # Handle parentheses by finding matching pairs
        while "(" in condition:
            # Find the innermost parenthesized group
            start = condition.rfind("(")
            end = condition.find(")", start)
            if end == -1:
                break
            inner = condition[start + 1:end]
            inner_result = self._evaluate_condition(inner, results)
            # Replace the parenthesized expression with its result
            condition = condition[:start] + ("__TRUE__" if inner_result else "__FALSE__") + condition[end + 1:]

        # Handle NOT
        if condition.startswith("not "):
            inner = condition[4:].strip()
            return not self._evaluate_condition(inner, results)
        if condition.startswith("NOT "):
            inner = condition[4:].strip()
            return not self._evaluate_condition(inner, results)

        # Handle AND (lower precedence than OR in some Sigma flavors, but we use standard left-to-right)
        if " and " in condition:
            parts = condition.split(" and ", 1)
            return self._evaluate_condition(parts[0], results) and self._evaluate_condition(parts[1], results)

        # Handle OR
        if " or " in condition:
            parts = condition.split(" or ", 1)
            return self._evaluate_condition(parts[0], results) or self._evaluate_condition(parts[1], results)

        # Handle placeholder results from parenthesized sub-expressions
        if condition == "__TRUE__":
            return True
        if condition == "__FALSE__":
            return False

        # Direct selector match
        return results.get(condition, False)

    def _calculate_confidence(self, rule: SigmaRule, matched_conditions: list[str]) -> float:
        """计算匹配置信度"""
        base_confidence = {
            "critical": 0.9,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.4,
            "informational": 0.2,
        }.get(rule.level.lower(), 0.5)

        # 根据匹配条件数量调整
        condition_boost = min(len(matched_conditions) * 0.05, 0.1)

        return min(base_confidence + condition_boost, 1.0)

    def _merge_matches(self, matches: list[SigmaMatch]) -> list[SigmaMatch]:
        """合并相同规则的匹配"""
        merged = {}

        for match in matches:
            rule_id = match.rule.id
            if rule_id in merged:
                # 合并事件
                existing = merged[rule_id]
                existing.matched_events.extend(match.matched_events)
                existing.matched_conditions = list(set(existing.matched_conditions + match.matched_conditions))
                existing.confidence = max(existing.confidence, match.confidence)
            else:
                merged[rule_id] = match

        return list(merged.values())

    def get_rule(self, rule_id: str) -> Optional[SigmaRule]:
        """获取规则"""
        return self._rules.get(rule_id)

    def get_rules_by_tag(self, tag: str) -> list[SigmaRule]:
        """按标签获取规则"""
        rule_ids = self._rules_by_tag.get(tag, [])
        return [self._rules[rid] for rid in rule_ids if rid in self._rules]

    def get_rules_by_level(self, level: str) -> list[SigmaRule]:
        """按级别获取规则"""
        rule_ids = self._rules_by_level.get(level.lower(), [])
        return [self._rules[rid] for rid in rule_ids if rid in self._rules]

    def list_rules(self) -> list[dict[str, str]]:
        """列出所有规则"""
        return [
            {
                "id": rule.id,
                "title": rule.title,
                "level": rule.level,
                "status": rule.status,
                "tags": ", ".join(rule.tags[:3]),
            }
            for rule in self._rules.values()
        ]

    def get_stats(self) -> dict[str, Any]:
        """获取统计信息"""
        return {
            "total_rules": len(self._rules),
            "by_level": {level: len(ids) for level, ids in self._rules_by_level.items()},
            "by_tag": {tag: len(ids) for tag, ids in self._rules_by_tag.items()},
        }


# 内置Sigma规则（示例）
BUILTIN_SIGMA_RULES = """
---
title: Suspicious PowerShell Execution
id: 00000000-0000-0000-0000-000000000001
status: experimental
description: Detects suspicious PowerShell execution patterns
author: CyberSec Agent
date: 2026/06/05
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'Invoke-Expression'
      - 'IEX'
      - 'DownloadString'
      - 'DownloadFile'
      - 'Net.WebClient'
      - '-enc'
      - '-EncodedCommand'
      - 'FromBase64String'
      - 'ToBase64String'
      - 'bypass'
      - 'hidden'
      - 'noprofile'
      - 'noni'
  condition: selection
falsepositives:
  - Legitimate PowerShell scripts
level: high
---
title: Suspicious Network Connection
id: 00000000-0000-0000-0000-000000000002
status: experimental
description: Detects suspicious network connections
author: CyberSec Agent
date: 2026/06/05
tags:
  - attack.command_and_control
  - attack.t1071
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort:
      - 4444
      - 5555
      - 6666
      - 7777
      - 8888
  condition: selection
falsepositives:
  - Custom applications
level: medium
---
title: Failed Login Attempts
id: 00000000-0000-0000-0000-000000000003
status: experimental
description: Detects multiple failed login attempts
author: CyberSec Agent
date: 2026/06/05
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  category: authentication
detection:
  selection:
    EventType: 'login_failure'
  timeframe: 5m
  condition: selection | count() > 5
falsepositives:
  - User forgetting password
level: high
---
title: SSH Authentication Failure
id: 00000000-0000-0000-0000-000000000021
status: experimental
description: Detects SSH authentication failure events (single or multiple)
author: CyberSec Agent
date: 2026/06/07
tags:
  - attack.credential_access
  - attack.t1110.004
logsource:
  category: authentication
  service: ssh
detection:
  selection:
    EventType: 'login_failure'
  condition: selection
falsepositives:
  - Misconfigured SSH client
level: medium
---
title: SSH Root Login Attempt
id: 00000000-0000-0000-0000-000000000022
status: experimental
description: Detects SSH login attempts targeting root account
author: CyberSec Agent
date: 2026/06/07
tags:
  - attack.credential_access
  - attack.t1110.004
logsource:
  category: authentication
  service: ssh
detection:
  selection_event:
    EventType: 'login_failure'
    user: 'root'
  selection_raw:
    raw|contains:
      - 'Failed password for root'
      - 'Failed password for invalid user root'
  condition: selection_event or selection_raw
falsepositives:
  - Legitimate root SSH access
level: high
---
title: SSH Login from External IP
id: 00000000-0000-0000-0000-000000000023
status: experimental
description: Detects SSH login attempts from external (non-RFC1918) IPs
author: CyberSec Agent
date: 2026/06/07
tags:
  - attack.initial_access
  - attack.t1078
logsource:
  category: authentication
  service: ssh
detection:
  selection:
    EventType:
      - 'login_failure'
      - 'login_success'
  filter_private:
    src_ip|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.2'
      - '172.3'
      - '127.'
  condition: selection and not filter_private
falsepositives:
  - Legitimate remote SSH access
level: medium
---
title: Encoded PowerShell Command
id: 00000000-0000-0000-0000-000000000004
status: experimental
description: Detects encoded PowerShell commands commonly used for defense evasion
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1059.001
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_enc:
    CommandLine|contains:
      - '-enc '
      - '-EncodedCommand'
      - '-e '
      - 'FromBase64String'
  selection_invoke:
    CommandLine|contains:
      - 'powershell'
      - 'pwsh'
  condition: selection_enc and selection_invoke
falsepositives:
  - Legitimate encoded deployment scripts
level: high
---
title: Credential Dumping Tool Execution
id: 00000000-0000-0000-0000-000000000005
status: experimental
description: Detects execution of known credential dumping tools
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.credential_access
  - attack.t1003
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'mimikatz'
      - 'sekurlsa'
      - 'kerberos'
      - 'lsadump'
      - 'procdump'
      - 'comsvcs.dll'
      - 'MiniDump'
  condition: selection
falsepositives:
  - Security testing tools
level: critical
---
title: Lateral Movement via SMB/PSExec
id: 00000000-0000-0000-0000-000000000006
status: experimental
description: Detects lateral movement using SMB and PSExec-like tools
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.lateral_movement
  - attack.t1021.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'psexec'
      - 'paexec'
      - 'wmic /node:'
      - 'net use \\\\'
      - 'sc \\\\'
      - 'schtasks /s '
  condition: selection
falsepositives:
  - IT administration tools
level: high
---
title: Web Shell Detection
id: 00000000-0000-0000-0000-000000000007
status: experimental
description: Detects common web shell patterns in HTTP requests and file uploads
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.persistence
  - attack.t1505.003
logsource:
  category: webserver
detection:
  selection:
    uri|contains:
      - 'eval('
      - 'exec('
      - 'system('
      - 'passthru('
      - 'shell_exec('
      - 'assert('
      - 'base64_decode('
      - 'cmd.exe'
      - '/bin/sh'
      - '/bin/bash'
      - 'whoami'
      - 'powershell'
  condition: selection
falsepositives:
  - Development/debug endpoints
level: critical
---
title: SQL Injection Attempt
id: 00000000-0000-0000-0000-000000000008
status: experimental
description: Detects SQL injection patterns in web requests
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: webserver
detection:
  selection:
    uri|contains:
      - "' OR "
      - "' AND "
      - "UNION SELECT"
      - "UNION ALL SELECT"
      - "' OR '1'='1"
      - "'; DROP TABLE"
      - "'; EXEC "
      - "1' AND '1'='1"
      - "admin'--"
  condition: selection
falsepositives:
  - Legitimate search queries
level: high
---
title: Directory Traversal Attempt
id: 00000000-0000-0000-0000-000000000009
status: experimental
description: Detects path traversal attempts in web requests
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.initial_access
  - attack.t1083
logsource:
  category: webserver
detection:
  selection:
    uri|contains:
      - '../'
      - '..\\'
      - '%2e%2e%2f'
      - '%2e%2e/'
      - '..%2f'
      - '%2e%2e%5c'
  condition: selection
falsepositives:
  - None
level: high
---
title: Scheduled Task Creation
id: 00000000-0000-0000-0000-000000000010
status: experimental
description: Detects scheduled task creation for persistence
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.persistence
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_schtasks:
    CommandLine|contains:
      - 'schtasks /create'
      - 'schtasks /Change'
  selection_register:
    CommandLine|contains:
      - 'reg add'
      - 'regedit'
  selection_reg_paths:
    CommandLine|contains:
      - 'CurrentVersion\\Run'
      - 'CurrentVersion\\RunOnce'
      - 'Winlogon\\Shell'
      - 'Services\\'
  condition: (selection_schtasks) or (selection_register and selection_reg_paths)
falsepositives:
  - IT automation scripts
level: high
---
title: UAC Bypass Detection
id: 00000000-0000-0000-0000-000000000011
status: experimental
description: Detects common UAC bypass techniques
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.privilege_escalation
  - attack.t1548.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'eventvwr.exe'
      - 'fodhelper.exe'
      - 'computerdefaults.exe'
      - 'sdclt.exe'
      - 'slui.exe'
      - 'cmd.exe /c echo'
      - 'reg add HKCU\\Software\\Classes'
  condition: selection
falsepositives:
  - Legitimate admin tools
level: high
---
title: Process Injection Detection
id: 00000000-0000-0000-0000-000000000012
status: experimental
description: Detects process injection and hollowing techniques
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.defense_evasion
  - attack.t1055
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'VirtualAllocEx'
      - 'WriteProcessMemory'
      - 'CreateRemoteThread'
      - 'NtUnmapViewOfSection'
      - 'QueueUserAPC'
      - 'SetThreadContext'
      - 'ReflectiveLoader'
  condition: selection
falsepositives:
  - Debugging tools
level: critical
---
title: Log Clearing Detection
id: 00000000-0000-0000-0000-000000000013
status: experimental
description: Detects attempts to clear or tamper with logs
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.defense_evasion
  - attack.t1070
logsource:
  category: process_creation
  product: windows
detection:
  selection_clear:
    CommandLine|contains:
      - 'wevtutil cl '
      - 'wevtutil sl '
      - 'Clear-EventLog'
      - 'Remove-Item'
  selection_log_path:
    CommandLine|contains:
      - '\\Windows\\System32\\winevt\\Logs'
      - 'Security.evtx'
      - 'System.evtx'
      - 'Application.evtx'
  condition: selection_clear or selection_log_path
falsepositives:
  - Log rotation scripts
level: critical
---
title: Network Scanning Detection
id: 00000000-0000-0000-0000-000000000014
status: experimental
description: Detects network scanning and reconnaissance tools
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.discovery
  - attack.t1046
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'nmap '
      - 'masscan'
      - 'zmap'
      - 'nbtscan'
      - 'enum4linux'
      - 'smbclient'
      - 'rpcclient'
      - 'ldapsearch'
      - 'dig '
      - 'nslookup'
      - 'whois '
  condition: selection
falsepositives:
  - IT network diagnostics
level: medium
---
title: SSH Brute Force Detection
id: 00000000-0000-0000-0000-000000000015
status: experimental
description: Detects SSH brute force attempts from authentication logs
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.credential_access
  - attack.t1110.004
logsource:
  category: authentication
  product: linux
detection:
  selection:
    message|contains:
      - 'Failed password for'
      - 'Failed password for invalid user'
      - 'authentication failure'
      - 'Invalid user'
      - 'Connection closed by authenticating user'
  condition: selection
falsepositives:
  - Misconfigured SSH clients
level: high
---
title: Reverse Shell Detection
id: 00000000-0000-0000-0000-000000000016
status: experimental
description: Detects reverse shell commands and patterns
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  category: process_creation
detection:
  selection_bash:
    CommandLine|contains:
      - 'bash -i'
      - 'bash -c'
      - '/dev/tcp/'
      - '/dev/udp/'
      - 'nc -e'
      - 'ncat -e'
      - 'mkfifo'
      - 'telnet '
  selection_python:
    CommandLine|contains:
      - 'python -c'
      - 'python3 -c'
      - 'import socket'
      - 'import subprocess'
      - 'os.dup2'
      - 'pty.spawn'
  selection_perl:
    CommandLine|contains:
      - 'perl -e'
      - 'perl -MSocket'
  condition: selection_bash or selection_python or selection_perl
falsepositives:
  - Legitimate remote administration
level: critical
---
title: Cryptocurrency Miner Detection
id: 00000000-0000-0000-0000-000000000017
status: experimental
description: Detects cryptocurrency mining activity
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.impact
  - attack.t1496
logsource:
  category: process_creation
detection:
  selection_process:
    CommandLine|contains:
      - 'xmrig'
      - 'minergate'
      - 'cpuminer'
      - 'cgminer'
      - 'bfgminer'
      - 'ethminer'
      - 'nbminer'
  selection_pool:
    CommandLine|contains:
      - 'stratum+tcp://'
      - 'stratum+ssl://'
      - 'pool.minexmr.com'
      - 'xmrpool.eu'
      - 'nanopool.org'
      - 'f2pool.com'
  condition: selection_process or selection_pool
falsepositives:
  - Legitimate mining operations
level: critical
---
title: Data Exfiltration via DNS
id: 00000000-0000-0000-0000-000000000018
status: experimental
description: Detects DNS-based data exfiltration patterns
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.exfiltration
  - attack.t1048.001
logsource:
  category: dns
detection:
  selection_long_domain:
    query|re: '^[a-zA-Z0-9]{30,}\\.'
  selection_txt:
    record_type: 'TXT'
    query|re: '^[a-zA-Z0-9]{20,}\\.'
  condition: selection_long_domain or selection_txt
falsepositives:
  - DKIM/SPF records
level: high
---
title: Cobalt Strike Beacon Detection
id: 00000000-0000-0000-0000-000000000019
status: experimental
description: Detects Cobalt Strike beacon configuration and communication patterns
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.command_and_control
  - attack.t1071.001
logsource:
  category: network_connection
detection:
  selection_default_ports:
    DestinationPort:
      - 50050
      - 443
      - 80
      - 8080
  selection_beacon_interval:
    # Beacon with regular interval (detected by PCAP analysis)
    metadata|contains:
      - 'beacon'
      - 'sleep'
      - 'cobaltstrike'
      - 'cobalt strike'
  condition: selection_default_ports or selection_beacon_interval
falsepositives:
  - Normal HTTPS traffic
level: critical
---
title: Ransomware Activity Detection
id: 00000000-0000-0000-0000-000000000020
status: experimental
description: Detects ransomware-like file operations and ransom note patterns
author: CyberSec Agent
date: 2026/06/06
tags:
  - attack.impact
  - attack.t1486
logsource:
  category: process_creation
  product: windows
detection:
  selection_encrypt:
    CommandLine|contains:
      - 'vssadmin delete shadows'
      - 'bcdedit /set {default} recoveryenabled no'
      - 'wbadmin delete catalog'
      - 'cipher /w'
      - 'wevtutil cl Security'
      - 'wevtutil cl System'
      - 'del /f /q *.bak'
      - 'del /f /q *.backup'
  selection_ransom_ext:
    CommandLine|contains:
      - '.encrypted'
      - '.locked'
      - '.crypto'
      - '.crypt'
      - '.ransom'
      - 'DECRYPT_INSTRUCTION'
      - 'HOW_TO_DECRYPT'
      - 'README_RESTORE'
  condition: selection_encrypt or selection_ransom_ext
falsepositives:
  - Legitimate backup operations
level: critical
"""

