"""Relation — Represents an edge in the knowledge graph.

关系：知识图谱中的边。
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class RelationType(str, Enum):
    """关系类型"""
    # 漏洞相关
    EXPLOITS = "exploits"                    # 利用漏洞
    AFFECTS = "affects"                      # 影响
    MITIGATES = "mitigates"                  # 缓解
    PATCHES = "patches"                      # 修复

    # 威胁相关
    USES = "uses"                            # 使用
    ATTRIBUTED_TO = "attributed_to"          # 归因于
    PART_OF = "part_of"                      # 属于
    DELIVERS = "delivers"                    # 投递
    DROPS = "drops"                          # 释放
    DOWNLOADS = "downloads"                  # 下载
    COMMUNICATES_WITH = "communicates_with"  # 通信

    # 攻击链相关
    PRECEDES = "precedes"                    # 先于
    FOLLOWS = "follows"                      # 后于
    TRIGGERS = "triggers"                    # 触发
    LEADS_TO = "leads_to"                    # 导致

    # 关联相关
    RELATED_TO = "related_to"                # 相关
    SIMILAR_TO = "similar_to"                # 相似
    EQUIVALENT_TO = "equivalent_to"          # 等同
    ALIAS_OF = "alias_of"                    # 别名

    # 资产相关
    HOSTS = "hosts"                          # 托管
    RUNS = "runs"                            # 运行
    CONNECTS_TO = "connects_to"              # 连接到
    RESOLVES_TO = "resolves_to"              # 解析到

    # 组织相关
    BELONGS_TO = "belongs_to"                # 属于
    OWNS = "owns"                            # 拥有
    MANAGES = "manages"                      # 管理
    MEMBER_OF = "member_of"                  # 成员

    # 地理相关
    LOCATED_IN = "located_in"                # 位于
    ORIGINATES_FROM = "originates_from"      # 来自

    # 时间相关
    OCCURRED_AT = "occurred_at"              # 发生于
    DISCOVERED_AT = "discovered_at"          # 发现于

    # 自定义
    CUSTOM = "custom"                        # 自定义关系


class Relation(BaseModel):
    """知识图谱关系"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = Field(..., description="源实体ID")
    target_id: str = Field(..., description="目标实体ID")
    relation_type: RelationType = Field(..., description="关系类型")
    properties: dict[str, Any] = Field(default_factory=dict, description="关系属性")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="置信度")
    source: str = Field(default="", description="数据来源")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    weight: float = Field(default=1.0, ge=0.0, description="关系权重")
    bidirectional: bool = Field(default=False, description="是否双向关系")

    def update_property(self, key: str, value: Any) -> None:
        """更新属性"""
        self.properties[key] = value
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type.value,
            "properties": self.properties,
            "confidence": self.confidence,
            "source": self.source,
            "weight": self.weight,
            "bidirectional": self.bidirectional,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Relation:
        """从字典创建关系"""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            source_id=data["source_id"],
            target_id=data["target_id"],
            relation_type=RelationType(data["relation_type"]),
            properties=data.get("properties", {}),
            confidence=data.get("confidence", 1.0),
            source=data.get("source", ""),
            weight=data.get("weight", 1.0),
            bidirectional=data.get("bidirectional", False),
        )

    def reverse(self) -> Relation:
        """创建反向关系"""
        return Relation(
            id=str(uuid.uuid4()),
            source_id=self.target_id,
            target_id=self.source_id,
            relation_type=self.relation_type,
            properties=self.properties,
            confidence=self.confidence,
            source=self.source,
            weight=self.weight,
            bidirectional=self.bidirectional,
        )

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Relation):
            return False
        return self.id == other.id


# 预定义的关系属性模式
RELATION_SCHEMAS = {
    RelationType.EXPLOITS: {
        "required": [],
        "optional": ["technique", "platform", "first_seen"],
    },
    RelationType.USES: {
        "required": [],
        "optional": ["purpose", "since", "confidence"],
    },
    RelationType.ATTRIBUTED_TO: {
        "required": [],
        "optional": ["confidence", "evidence", "attribution_date"],
    },
    RelationType.COMMUNICATES_WITH: {
        "required": [],
        "optional": ["port", "protocol", "direction", "frequency"],
    },
    RelationType.DELIVERS: {
        "required": [],
        "optional": ["method", "vector", "first_seen"],
    },
    RelationType.HOSTS: {
        "required": [],
        "optional": ["service", "port", "since"],
    },
    RelationType.RESOLVES_TO: {
        "required": [],
        "optional": ["record_type", "ttl", "first_seen"],
    },
}

# 关系的方向性定义
RELATION_DIRECTION = {
    RelationType.EXPLOITS: "source_to_target",       # 源利用目标
    RelationType.AFFECTS: "source_to_target",        # 源影响目标
    RelationType.USES: "source_to_target",           # 源使用目标
    RelationType.ATTRIBUTED_TO: "source_to_target",  # 源归因于目标
    RelationType.DELIVERS: "source_to_target",       # 源投递目标
    RelationType.DROPS: "source_to_target",          # 源释放目标
    RelationType.DOWNLOADS: "source_to_target",      # 源下载目标
    RelationType.COMMUNICATES_WITH: "bidirectional", # 双向通信
    RelationType.PRECEDES: "source_to_target",       # 源先于目标
    RelationType.FOLLOWS: "source_to_target",        # 源后于目标
    RelationType.RELATED_TO: "bidirectional",        # 双向相关
    RelationType.SIMILAR_TO: "bidirectional",        # 双向相似
    RelationType.HOSTS: "source_to_target",          # 源托管目标
    RelationType.RUNS: "source_to_target",           # 源运行目标
    RelationType.CONNECTS_TO: "source_to_target",    # 源连接目标
    RelationType.RESOLVES_TO: "source_to_target",    # 源解析到目标
    RelationType.BELONGS_TO: "source_to_target",     # 源属于目标
    RelationType.OWNS: "source_to_target",           # 源拥有目标
    RelationType.LOCATED_IN: "source_to_target",     # 源位于目标
}
