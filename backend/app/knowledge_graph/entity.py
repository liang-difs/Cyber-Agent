"""Entity — Represents a node in the knowledge graph.

实体：知识图谱中的节点。
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    """实体类型"""
    # 漏洞相关
    CVE = "cve"                        # CVE漏洞
    VULNERABILITY = "vulnerability"     # 漏洞
    WEAKNESS = "weakness"              # 弱点

    # 威胁相关
    THREAT_ACTOR = "threat_actor"      # 威胁行为者
    MALWARE = "malware"                # 恶意软件
    CAMPAIGN = "campaign"              # 攻击活动
    TOOL = "tool"                      # 攻击工具

    # 技术相关
    TECHNIQUE = "technique"            # ATT&CK技术
    TACTIC = "tactic"                  # ATT&CK战术
    PROCEDURE = "procedure"            # 攻击过程

    # 指标相关
    IP = "ip"                          # IP地址
    DOMAIN = "domain"                  # 域名
    URL = "url"                        # URL
    HASH = "hash"                      # 文件哈希
    EMAIL = "email"                    # 邮箱

    # 资产相关
    ASSET = "asset"                    # 资产
    HOST = "host"                      # 主机
    SERVICE = "service"                # 服务
    APPLICATION = "application"        # 应用

    # 其他
    GROUP = "group"                    # 组
    PERSON = "person"                  # 人员
    ORGANIZATION = "organization"      # 组织
    LOCATION = "location"              # 位置
    EVENT = "event"                    # 事件
    UNKNOWN = "unknown"                # 未知


class Entity(BaseModel):
    """知识图谱实体"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="实体名称")
    entity_type: EntityType = Field(..., description="实体类型")
    properties: dict[str, Any] = Field(default_factory=dict, description="实体属性")
    aliases: list[str] = Field(default_factory=list, description="别名")
    source: str = Field(default="", description="数据来源")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="置信度")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = Field(default_factory=list, description="标签")

    def add_alias(self, alias: str) -> None:
        """添加别名"""
        if alias not in self.aliases:
            self.aliases.append(alias)

    def update_property(self, key: str, value: Any) -> None:
        """更新属性"""
        self.properties[key] = value
        self.updated_at = datetime.now(timezone.utc)

    def merge(self, other: Entity) -> None:
        """合并另一个实体的信息"""
        # 合并别名
        for alias in other.aliases:
            self.add_alias(alias)

        # 合并属性（不覆盖已有的）
        for key, value in other.properties.items():
            if key not in self.properties:
                self.properties[key] = value

        # 合并标签
        for tag in other.tags:
            if tag not in self.tags:
                self.tags.append(tag)

        # 更新置信度（取较高值）
        self.confidence = max(self.confidence, other.confidence)

        # 更新时间
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "entity_type": self.entity_type.value,
            "properties": self.properties,
            "aliases": self.aliases,
            "source": self.source,
            "confidence": self.confidence,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Entity:
        """从字典创建实体"""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data["name"],
            entity_type=EntityType(data["entity_type"]),
            properties=data.get("properties", {}),
            aliases=data.get("aliases", []),
            source=data.get("source", ""),
            confidence=data.get("confidence", 1.0),
            tags=data.get("tags", []),
        )

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Entity):
            return False
        return self.id == other.id


# 预定义的实体属性模式
ENTITY_SCHEMAS = {
    EntityType.CVE: {
        "required": ["cve_id", "description"],
        "optional": ["cvss_score", "severity", "published", "modified", "affected_products"],
    },
    EntityType.MALWARE: {
        "required": ["name"],
        "optional": ["family", "type", "platform", "first_seen", "aliases"],
    },
    EntityType.THREAT_ACTOR: {
        "required": ["name"],
        "optional": ["country", "motivation", "sophistication", "aliases"],
    },
    EntityType.TECHNIQUE: {
        "required": ["technique_id", "name"],
        "optional": ["tactic", "description", "platforms"],
    },
    EntityType.IP: {
        "required": ["address"],
        "optional": ["country", "city", "asn", "organization", "is_malicious"],
    },
    EntityType.DOMAIN: {
        "required": ["name"],
        "optional": ["registrar", "creation_date", "is_malicious"],
    },
    EntityType.HASH: {
        "required": ["value", "algorithm"],
        "optional": ["file_name", "file_size", "file_type"],
    },
}
