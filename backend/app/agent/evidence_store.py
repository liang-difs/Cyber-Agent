"""Evidence Store — collects and indexes tool results for citation.

证据存证引擎：收集工具调用结果，强制结论引用具体证据编号。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class Evidence:
    """单条证据"""
    evidence_id: str              # E1, E2, E3...
    source_tool: str              # 来源工具名
    source_query: str             # 查询内容
    category: str                 # 分类：threat_intel, whois, dns, ssl, etc.
    finding: str                  # 关键发现（一句话）
    details: dict[str, Any]       # 完整数据
    confidence: float             # 置信度 0.0-1.0
    timestamp: str                # 时间戳


@dataclass
class EvidenceCollection:
    """一次调查的证据集合"""
    collection_id: str
    target: str
    target_type: str
    started_at: str
    evidence: list[Evidence] = field(default_factory=list)
    conclusions: list[str] = field(default_factory=list)

    def add_evidence(
        self,
        source_tool: str,
        source_query: str,
        category: str,
        finding: str,
        details: dict[str, Any],
        confidence: float = 0.8,
    ) -> Evidence:
        """添加一条证据，返回带编号的 Evidence 对象"""
        ev_id = f"E{len(self.evidence) + 1}"
        ev = Evidence(
            evidence_id=ev_id,
            source_tool=source_tool,
            source_query=source_query,
            category=category,
            finding=finding,
            details=details,
            confidence=confidence,
            timestamp=datetime.now().isoformat(),
        )
        self.evidence.append(ev)
        return ev

    def get_evidence_table(self) -> str:
        """生成证据表格（markdown 格式）"""
        if not self.evidence:
            return "暂无证据"

        lines = [
            "| 编号 | 来源 | 分类 | 关键发现 | 置信度 |",
            "|------|------|------|----------|--------|",
        ]
        for ev in self.evidence:
            conf_pct = f"{ev.confidence * 100:.0f}%"
            lines.append(
                f"| {ev.evidence_id} | {ev.source_tool} | {ev.category} | {ev.finding[:60]} | {conf_pct} |"
            )
        return "\n".join(lines)

    def get_summary(self) -> dict[str, Any]:
        """获取证据摘要（动态加权置信度）"""
        from datetime import datetime

        by_category: dict[str, int] = {}
        for ev in self.evidence:
            by_category[ev.category] = by_category.get(ev.category, 0) + 1

        # 工具基础权重
        tool_weights = {
            "whois_lookup": 1.3, "dns_lookup": 1.3, "ssl_lookup": 1.3,
            "threat_intel": 1.3, "ip_threat_analysis": 1.2, "hash_lookup": 1.2,
            "ioc_lookup": 1.2, "pcap_analysis": 1.1, "log_analysis": 1.0,
            "knowledge_graph": 0.9, "rag_search": 0.8, "web_search": 0.7,
        }

        # 动态权重 = 工具权重 × 证据质量 × 时效性
        if self.evidence:
            now = datetime.now()
            weighted_scores = []
            total_weight = 0.0

            for ev in self.evidence:
                tool_w = tool_weights.get(ev.source_tool, 1.0)

                # 证据质量：基于置信度（有结果 vs 无结果）
                quality = ev.confidence if ev.confidence > 0 else 0.1

                # 时效性：越新越重要（1.0 = 刚产生，0.5 = 较旧）
                try:
                    ev_time = datetime.fromisoformat(ev.timestamp)
                    age_minutes = (now - ev_time).total_seconds() / 60
                    freshness = max(0.5, 1.0 - age_minutes / 120)  # 2小时内线性衰减
                except Exception:
                    freshness = 1.0

                score = tool_w * quality * freshness
                weighted_scores.append(score)
                total_weight += tool_w

            overall_confidence = sum(weighted_scores) / total_weight if total_weight > 0 else 0.0
        else:
            overall_confidence = 0.0

        return {
            "total_evidence": len(self.evidence),
            "by_category": by_category,
            "overall_confidence": round(overall_confidence, 3),
            "confidence_breakdown": [
                {"id": ev.evidence_id, "tool": ev.source_tool, "confidence": ev.confidence}
                for ev in self.evidence
            ],
            "tools_used": list(set(ev.source_tool for ev in self.evidence)),
        }

    def to_dict(self) -> dict[str, Any]:
        """导出为字典"""
        return {
            "collection_id": self.collection_id,
            "target": self.target,
            "target_type": self.target_type,
            "started_at": self.started_at,
            "evidence": [
                {
                    "id": ev.evidence_id,
                    "tool": ev.source_tool,
                    "query": ev.source_query,
                    "category": ev.category,
                    "finding": ev.finding,
                    "confidence": ev.confidence,
                    "timestamp": ev.timestamp,
                }
                for ev in self.evidence
            ],
            "conclusions": self.conclusions,
            "summary": self.get_summary(),
        }


class EvidenceStore:
    """证据存储管理器（内存实现，按会话隔离）"""

    def __init__(self):
        self._collections: dict[str, EvidenceCollection] = {}

    def start_collection(
        self,
        collection_id: str,
        target: str,
        target_type: str,
    ) -> EvidenceCollection:
        """开始一次新的证据收集"""
        collection = EvidenceCollection(
            collection_id=collection_id,
            target=target,
            target_type=target_type,
            started_at=datetime.now().isoformat(),
        )
        self._collections[collection_id] = collection
        return collection

    def get_collection(self, collection_id: str) -> Optional[EvidenceCollection]:
        """获取证据集合"""
        return self._collections.get(collection_id)

    def add_evidence(
        self,
        collection_id: str,
        source_tool: str,
        source_query: str,
        category: str,
        finding: str,
        details: dict[str, Any],
        confidence: float = 0.8,
    ) -> Optional[Evidence]:
        """向指定集合添加证据"""
        collection = self._collections.get(collection_id)
        if not collection:
            return None
        return collection.add_evidence(
            source_tool=source_tool,
            source_query=source_query,
            category=category,
            finding=finding,
            details=details,
            confidence=confidence,
        )

    def add_conclusion(self, collection_id: str, conclusion: str) -> bool:
        """添加结论"""
        collection = self._collections.get(collection_id)
        if not collection:
            return False
        collection.conclusions.append(conclusion)
        return True

    def export_collection(self, collection_id: str) -> Optional[dict[str, Any]]:
        """导出证据集合"""
        collection = self._collections.get(collection_id)
        if not collection:
            return None
        return collection.to_dict()

    def get_evidence_table(self, collection_id: str) -> str:
        """获取证据表格"""
        collection = self._collections.get(collection_id)
        if not collection:
            return "无证据集合"
        return collection.get_evidence_table()


# 全局单例
_evidence_store: Optional[EvidenceStore] = None


def get_evidence_store() -> EvidenceStore:
    global _evidence_store
    if _evidence_store is None:
        _evidence_store = EvidenceStore()
    return _evidence_store
