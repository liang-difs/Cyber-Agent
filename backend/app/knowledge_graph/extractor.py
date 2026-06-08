"""Entity Extractor — Extract entities from text.

实体提取器：从文本中提取实体。
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from app.knowledge_graph.entity import Entity, EntityType
from app.knowledge_graph.relation import Relation, RelationType

logger = logging.getLogger(__name__)


class EntityExtractor:
    """实体提取器"""

    def __init__(self):
        # 正则表达式模式
        self._patterns = {
            EntityType.CVE: re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
            EntityType.IP: re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            EntityType.DOMAIN: re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
            EntityType.URL: re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+'),
            EntityType.HASH: {
                'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
                'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
                'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            },
            EntityType.EMAIL: re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        }

        # ATT&CK技术ID模式
        self._technique_pattern = re.compile(r'T\d{4}(?:\.\d{3})?')

        # 常见恶意软件家族
        self._malware_families = [
            'cobaltstrike', 'metasploit', 'mimikatz', 'empire',
            'covenant', 'sliver', 'bloodhound',
            'emotet', 'trickbot', 'ryuk', 'conti', 'wannacry',
            'ransomware', 'trojan', 'backdoor', 'rat', 'rootkit',
        ]

    def extract_entities(self, text: str) -> list[Entity]:
        """从文本中提取实体"""
        entities = []
        seen = set()

        # 提取CVE
        for match in self._patterns[EntityType.CVE].finditer(text):
            cve_id = match.group()
            if cve_id not in seen:
                seen.add(cve_id)
                entities.append(Entity(
                    name=cve_id,
                    entity_type=EntityType.CVE,
                    properties={"cve_id": cve_id},
                    source="text_extraction",
                ))

        # 提取IP
        for match in self._patterns[EntityType.IP].finditer(text):
            ip = match.group()
            if ip not in seen and not self._is_private_ip(ip):
                seen.add(ip)
                entities.append(Entity(
                    name=ip,
                    entity_type=EntityType.IP,
                    properties={"address": ip},
                    source="text_extraction",
                ))

        # 提取域名
        for match in self._patterns[EntityType.DOMAIN].finditer(text):
            domain = match.group()
            if domain not in seen and not self._is_common_domain(domain):
                seen.add(domain)
                entities.append(Entity(
                    name=domain,
                    entity_type=EntityType.DOMAIN,
                    properties={"name": domain},
                    source="text_extraction",
                ))

        # 提取URL
        for match in self._patterns[EntityType.URL].finditer(text):
            url = match.group()
            if url not in seen:
                seen.add(url)
                entities.append(Entity(
                    name=url,
                    entity_type=EntityType.URL,
                    properties={"url": url},
                    source="text_extraction",
                ))

        # 提取哈希
        for hash_type, pattern in self._patterns[EntityType.HASH].items():
            for match in pattern.finditer(text):
                hash_value = match.group()
                if hash_value not in seen:
                    seen.add(hash_value)
                    entities.append(Entity(
                        name=hash_value,
                        entity_type=EntityType.HASH,
                        properties={"value": hash_value, "algorithm": hash_type},
                        source="text_extraction",
                    ))

        # 提取邮箱
        for match in self._patterns[EntityType.EMAIL].finditer(text):
            email = match.group()
            if email not in seen:
                seen.add(email)
                entities.append(Entity(
                    name=email,
                    entity_type=EntityType.EMAIL,
                    properties={"email": email},
                    source="text_extraction",
                ))

        # 提取ATT&CK技术
        for match in self._technique_pattern.finditer(text):
            technique_id = match.group()
            if technique_id not in seen:
                seen.add(technique_id)
                entities.append(Entity(
                    name=technique_id,
                    entity_type=EntityType.TECHNIQUE,
                    properties={"technique_id": technique_id},
                    source="text_extraction",
                ))

        # 提取恶意软件家族
        text_lower = text.lower()
        for family in self._malware_families:
            if family in text_lower and family not in seen:
                seen.add(family)
                entities.append(Entity(
                    name=family,
                    entity_type=EntityType.MALWARE,
                    properties={"name": family, "family": family},
                    source="text_extraction",
                ))

        return entities

    def extract_relations(self, text: str, entities: list[Entity] = None) -> list[Relation]:
        """从文本中提取关系"""
        if entities is None:
            entities = self.extract_entities(text)

        relations = []

        # 按类型分组实体
        entities_by_type = {}
        for entity in entities:
            if entity.entity_type not in entities_by_type:
                entities_by_type[entity.entity_type] = []
            entities_by_type[entity.entity_type].append(entity)

        # 提取CVE和IP/域名的关系
        cves = entities_by_type.get(EntityType.CVE, [])
        ips = entities_by_type.get(EntityType.IP, [])
        domains = entities_by_type.get(EntityType.DOMAIN, [])

        # 简单的共现关系提取
        for cve in cves:
            for ip in ips:
                # 检查是否在同一上下文中
                if self._are_in_context(text, cve.name, ip.name):
                    relations.append(Relation(
                        source_id=cve.id,
                        target_id=ip.id,
                        relation_type=RelationType.RELATED_TO,
                        properties={"context": "co_occurrence"},
                        confidence=0.6,
                        source="text_extraction",
                    ))

            for domain in domains:
                if self._are_in_context(text, cve.name, domain.name):
                    relations.append(Relation(
                        source_id=cve.id,
                        target_id=domain.id,
                        relation_type=RelationType.RELATED_TO,
                        properties={"context": "co_occurrence"},
                        confidence=0.6,
                        source="text_extraction",
                    ))

        # 提取恶意软件和IP/域名的关系
        malwares = entities_by_type.get(EntityType.MALWARE, [])
        for malware in malwares:
            for ip in ips:
                if self._are_in_context(text, malware.name, ip.name):
                    relations.append(Relation(
                        source_id=malware.id,
                        target_id=ip.id,
                        relation_type=RelationType.COMMUNICATES_WITH,
                        properties={"context": "co_occurrence"},
                        confidence=0.5,
                        source="text_extraction",
                    ))

            for domain in domains:
                if self._are_in_context(text, malware.name, domain.name):
                    relations.append(Relation(
                        source_id=malware.id,
                        target_id=domain.id,
                        relation_type=RelationType.COMMUNICATES_WITH,
                        properties={"context": "co_occurrence"},
                        confidence=0.5,
                        source="text_extraction",
                    ))

        return relations

    def _is_private_ip(self, ip: str) -> bool:
        """检查是否为私有IP"""
        parts = ip.split('.')
        if len(parts) != 4:
            return True

        try:
            first = int(parts[0])
            second = int(parts[1])

            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            # 127.0.0.0/8
            if first == 127:
                return True

            return False
        except ValueError:
            return True

    def _is_common_domain(self, domain: str) -> bool:
        """检查是否为常见域名"""
        common_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org',
            'example.com', 'localhost',
        ]
        return domain.lower() in common_domains

    def _are_in_context(self, text: str, term1: str, term2: str, window: int = 200) -> bool:
        """检查两个术语是否在同一上下文中"""
        idx1 = text.lower().find(term1.lower())
        idx2 = text.lower().find(term2.lower())

        if idx1 == -1 or idx2 == -1:
            return False

        # 检查距离
        return abs(idx1 - idx2) < window

    def extract_from_log(self, log_entry: dict[str, Any]) -> list[Entity]:
        """从日志条目中提取实体"""
        entities = []

        # 提取IP
        for field in ['src_ip', 'dst_ip', 'source_ip', 'destination_ip', 'ip']:
            if field in log_entry:
                ip = log_entry[field]
                if isinstance(ip, str) and self._patterns[EntityType.IP].match(ip):
                    entities.append(Entity(
                        name=ip,
                        entity_type=EntityType.IP,
                        properties={"address": ip, "field": field},
                        source="log_extraction",
                    ))

        # 提取域名
        for field in ['domain', 'hostname', 'host', 'server']:
            if field in log_entry:
                domain = log_entry[field]
                if isinstance(domain, str) and self._patterns[EntityType.DOMAIN].match(domain):
                    entities.append(Entity(
                        name=domain,
                        entity_type=EntityType.DOMAIN,
                        properties={"name": domain, "field": field},
                        source="log_extraction",
                    ))

        # 提取URL
        for field in ['url', 'uri', 'request']:
            if field in log_entry:
                url = log_entry[field]
                if isinstance(url, str) and self._patterns[EntityType.URL].match(url):
                    entities.append(Entity(
                        name=url,
                        entity_type=EntityType.URL,
                        properties={"url": url, "field": field},
                        source="log_extraction",
                    ))

        # 提取用户
        for field in ['user', 'username', 'account']:
            if field in log_entry:
                user = log_entry[field]
                if isinstance(user, str) and user:
                    entities.append(Entity(
                        name=user,
                        entity_type=EntityType.PERSON,
                        properties={"name": user, "field": field},
                        source="log_extraction",
                    ))

        return entities

    def extract_from_ioc(self, ioc_data: dict[str, Any]) -> list[Entity]:
        """从IoC数据中提取实体"""
        entities = []

        # 提取IP
        if 'ip' in ioc_data:
            ip = ioc_data['ip']
            entities.append(Entity(
                name=ip,
                entity_type=EntityType.IP,
                properties={"address": ip, **ioc_data.get('ip_info', {})},
                source="ioc_extraction",
                confidence=ioc_data.get('confidence', 0.8),
            ))

        # 提取域名
        if 'domain' in ioc_data:
            domain = ioc_data['domain']
            entities.append(Entity(
                name=domain,
                entity_type=EntityType.DOMAIN,
                properties={"name": domain, **ioc_data.get('domain_info', {})},
                source="ioc_extraction",
                confidence=ioc_data.get('confidence', 0.8),
            ))

        # 提取哈希
        if 'hash' in ioc_data:
            hash_value = ioc_data['hash']
            hash_type = ioc_data.get('hash_type', 'unknown')
            entities.append(Entity(
                name=hash_value,
                entity_type=EntityType.HASH,
                properties={"value": hash_value, "algorithm": hash_type},
                source="ioc_extraction",
                confidence=ioc_data.get('confidence', 0.8),
            ))

        return entities

    def extract_from_cve(self, cve_data: dict[str, Any]) -> Entity:
        """从CVE数据中提取实体"""
        cve_id = cve_data.get('cve_id', cve_data.get('id', ''))
        return Entity(
            name=cve_id,
            entity_type=EntityType.CVE,
            properties={
                "cve_id": cve_id,
                "description": cve_data.get('description', ''),
                "cvss_score": cve_data.get('cvss_score', 0),
                "severity": cve_data.get('severity', ''),
                "published": cve_data.get('published', ''),
                "affected_products": cve_data.get('affected_products', []),
            },
            source="cve_extraction",
            confidence=1.0,
        )


# 全局实体提取器实例
_entity_extractor: Optional[EntityExtractor] = None


def get_entity_extractor() -> EntityExtractor:
    """获取全局实体提取器实例"""
    global _entity_extractor
    if _entity_extractor is None:
        _entity_extractor = EntityExtractor()
    return _entity_extractor
