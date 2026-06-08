"""Rule Manager — Unified rule management for Sigma and YARA.

规则管理器：统一管理Sigma和YARA规则。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from app.rules.sigma_engine import SigmaEngine, SigmaMatch
from app.rules.yara_engine import YaraEngine, YaraMatch

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    """统一的规则匹配结果"""
    rule_type: str  # "sigma" or "yara"
    rule_name: str
    rule_id: str
    description: str
    severity: str
    confidence: float
    matched_conditions: list[str]
    matched_data: dict[str, Any]
    recommendations: list[str] = field(default_factory=list)


class RuleManager:
    """规则管理器"""

    def __init__(self, rules_directory: str = None):
        self.sigma_engine = SigmaEngine()
        self.yara_engine = YaraEngine()

        # 加载内置规则
        self._load_builtin_rules()

        # 加载目录规则
        if rules_directory:
            self.load_from_directory(rules_directory)

    def _load_builtin_rules(self) -> None:
        """加载内置规则"""
        from app.rules.sigma_engine import BUILTIN_SIGMA_RULES
        from app.rules.yara_engine import BUILTIN_YARA_RULES

        # 加载内置Sigma规则
        self.sigma_engine._load_rules_from_string(BUILTIN_SIGMA_RULES)

        # 加载内置YARA规则
        self.yara_engine._load_rules_from_string(BUILTIN_YARA_RULES)

        logger.info("Loaded builtin rules")

    def load_from_directory(self, directory: str) -> dict[str, int]:
        """从目录加载规则"""
        path = Path(directory)
        if not path.is_dir():
            logger.error("Rules directory not found: %s", directory)
            return {"sigma": 0, "yara": 0}

        sigma_count = self.sigma_engine.load_from_directory(str(path / "sigma"))
        yara_count = self.yara_engine.load_from_directory(str(path / "yara"))

        return {"sigma": sigma_count, "yara": yara_count}

    def match_log_event(self, event: dict[str, Any], logsource: dict[str, str] = None) -> list[RuleMatch]:
        """匹配日志事件"""
        matches = []

        # Sigma规则匹配
        sigma_matches = self.sigma_engine.match_event(event, logsource)
        for match in sigma_matches:
            rule_match = RuleMatch(
                rule_type="sigma",
                rule_name=match.rule.title,
                rule_id=match.rule.id,
                description=match.rule.description,
                severity=match.severity,
                confidence=match.confidence,
                matched_conditions=match.matched_conditions,
                matched_data={
                    "event": event,
                    "logsource": logsource,
                },
                recommendations=self._get_sigma_recommendations(match),
            )
            matches.append(rule_match)

        return matches

    def match_log_events(self, events: list[dict[str, Any]], logsource: dict[str, str] = None) -> list[RuleMatch]:
        """匹配多个日志事件"""
        matches = []

        # Sigma规则匹配
        sigma_matches = self.sigma_engine.match_events(events, logsource)
        for match in sigma_matches:
            rule_match = RuleMatch(
                rule_type="sigma",
                rule_name=match.rule.title,
                rule_id=match.rule.id,
                description=match.rule.description,
                severity=match.severity,
                confidence=match.confidence,
                matched_conditions=match.matched_conditions,
                matched_data={
                    "event_count": len(match.matched_events),
                    "events": match.matched_events[:5],  # 只保留前5个
                    "logsource": logsource,
                },
                recommendations=self._get_sigma_recommendations(match),
            )
            matches.append(rule_match)

        return matches

    def match_file(self, file_path: str) -> list[RuleMatch]:
        """匹配文件"""
        matches = []

        # YARA规则匹配
        yara_matches = self.yara_engine.match_file(file_path)
        for match in yara_matches:
            rule_match = RuleMatch(
                rule_type="yara",
                rule_name=match.rule.name,
                rule_id=match.rule.name,
                description=match.rule.meta.get("description", ""),
                severity=match.severity,
                confidence=match.confidence,
                matched_conditions=[s["identifier"] for s in match.matched_strings],
                matched_data={
                    "file": file_path,
                    "offset": match.offset,
                    "length": match.length,
                    "strings": match.matched_strings,
                },
                recommendations=self._get_yara_recommendations(match),
            )
            matches.append(rule_match)

        return matches

    def match_data(self, data: bytes, context: str = "") -> list[RuleMatch]:
        """匹配数据"""
        matches = []

        # YARA规则匹配
        yara_matches = self.yara_engine.match_data(data)
        for match in yara_matches:
            rule_match = RuleMatch(
                rule_type="yara",
                rule_name=match.rule.name,
                rule_id=match.rule.name,
                description=match.rule.meta.get("description", ""),
                severity=match.severity,
                confidence=match.confidence,
                matched_conditions=[s["identifier"] for s in match.matched_strings],
                matched_data={
                    "context": context,
                    "offset": match.offset,
                    "length": match.length,
                    "strings": match.matched_strings,
                },
                recommendations=self._get_yara_recommendations(match),
            )
            matches.append(rule_match)

        return matches

    def _get_sigma_recommendations(self, match: SigmaMatch) -> list[str]:
        """获取Sigma匹配的建议"""
        recommendations = []

        # 根据标签生成建议
        tags = match.rule.tags
        if "attack.execution" in tags:
            recommendations.append("检查进程执行链，确认是否为合法操作")
        if "attack.credential_access" in tags:
            recommendations.append("检查账户活动，考虑强制密码重置")
        if "attack.command_and_control" in tags:
            recommendations.append("封锁可疑IP，检查网络连接")
        if "attack.lateral_movement" in tags:
            recommendations.append("隔离受影响主机，检查横向移动痕迹")

        # 根据级别生成建议
        if match.severity == "critical":
            recommendations.append("立即响应：隔离受影响系统")
        elif match.severity == "high":
            recommendations.append("优先处理：进行深入调查")

        return recommendations

    def _get_yara_recommendations(self, match: YaraMatch) -> list[str]:
        """获取YARA匹配的建议"""
        recommendations = []

        # 根据规则标签生成建议
        tags = match.rule.tags
        if "malware" in tags:
            recommendations.append("隔离文件，进行恶意软件分析")
        if "ransomware" in tags:
            recommendations.append("立即隔离，检查备份完整性")
        if "suspicious" in tags:
            recommendations.append("进行深入分析，确认是否为威胁")

        # 根据级别生成建议
        if match.severity == "critical":
            recommendations.append("紧急响应：隔离并进行取证")
        elif match.severity == "high":
            recommendations.append("优先分析：检查文件来源和传播路径")

        return recommendations

    def get_rule(self, rule_type: str, rule_id: str) -> Optional[Any]:
        """获取规则"""
        if rule_type == "sigma":
            return self.sigma_engine.get_rule(rule_id)
        elif rule_type == "yara":
            return self.yara_engine.get_rule(rule_id)
        return None

    def list_rules(self, rule_type: str = None) -> dict[str, list]:
        """列出规则"""
        result = {}

        if rule_type is None or rule_type == "sigma":
            result["sigma"] = self.sigma_engine.list_rules()

        if rule_type is None or rule_type == "yara":
            result["yara"] = self.yara_engine.list_rules()

        return result

    def get_stats(self) -> dict[str, Any]:
        """获取统计信息"""
        return {
            "sigma": self.sigma_engine.get_stats(),
            "yara": self.yara_engine.get_stats(),
            "total_rules": (
                self.sigma_engine.get_stats()["total_rules"] +
                self.yara_engine.get_stats()["total_rules"]
            ),
        }

    def add_sigma_rule(self, yaml_content: str) -> Optional[str]:
        """添加Sigma规则"""
        rule = self.sigma_engine.load_rule(yaml_content)
        return rule.id if rule else None

    def add_yara_rule(self, rule_source: str, namespace: str = "default") -> Optional[str]:
        """添加YARA规则"""
        rule = self.yara_engine.load_rule(rule_source, namespace)
        return rule.name if rule else None


# 全局规则管理器实例
_rule_manager: Optional[RuleManager] = None


def get_rule_manager() -> RuleManager:
    """获取全局规则管理器"""
    global _rule_manager
    if _rule_manager is None:
        _rule_manager = RuleManager()
    return _rule_manager
