"""Knowledge Graph — Core graph implementation.

知识图谱：核心图实现。
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Optional

from app.knowledge_graph.entity import Entity, EntityType
from app.knowledge_graph.relation import Relation, RelationType

logger = logging.getLogger(__name__)


class KnowledgeGraph:
    """知识图谱"""

    def __init__(self):
        self._entities: dict[str, Entity] = {}
        self._relations: dict[str, Relation] = {}
        self._entity_index: dict[str, set[str]] = defaultdict(set)  # type -> entity_ids
        self._name_index: dict[str, set[str]] = defaultdict(set)    # name -> entity_ids
        self._relation_index: dict[str, set[str]] = defaultdict(set)  # entity_id -> relation_ids
        self._type_relation_index: dict[str, set[str]] = defaultdict(set)  # relation_type -> relation_ids

    # ========== 实体操作 ==========

    def add_entity(self, entity: Entity) -> str:
        """添加实体"""
        # 检查是否已存在同名实体
        existing = self.find_entity_by_name(entity.name, entity.entity_type)
        if existing:
            # 合并实体
            existing.merge(entity)
            logger.debug("Merged entity '%s' with existing '%s'", entity.name, existing.id)
            return existing.id

        # 添加新实体
        self._entities[entity.id] = entity
        self._entity_index[entity.entity_type.value].add(entity.id)
        self._name_index[entity.name.lower()].add(entity.id)

        # 索引别名
        for alias in entity.aliases:
            self._name_index[alias.lower()].add(entity.id)

        logger.debug("Added entity '%s' (%s)", entity.name, entity.entity_type.value)
        return entity.id

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """获取实体"""
        return self._entities.get(entity_id)

    def update_entity(self, entity_id: str, properties: dict[str, Any]) -> bool:
        """更新实体属性"""
        entity = self._entities.get(entity_id)
        if not entity:
            return False

        for key, value in properties.items():
            entity.update_property(key, value)

        return True

    def delete_entity(self, entity_id: str) -> bool:
        """删除实体"""
        entity = self._entities.get(entity_id)
        if not entity:
            return False

        # 删除关联的关系
        relation_ids = list(self._relation_index.get(entity_id, set()))
        for rel_id in relation_ids:
            self.delete_relation(rel_id)

        # 删除索引
        self._entity_index[entity.entity_type.value].discard(entity_id)
        self._name_index[entity.name.lower()].discard(entity_id)
        for alias in entity.aliases:
            self._name_index[alias.lower()].discard(entity_id)

        # 删除实体
        del self._entities[entity_id]
        logger.debug("Deleted entity '%s'", entity.name)

        return True

    def find_entity_by_name(self, name: str, entity_type: EntityType = None) -> Optional[Entity]:
        """按名称查找实体"""
        entity_ids = self._name_index.get(name.lower(), set())
        for eid in entity_ids:
            entity = self._entities.get(eid)
            if entity and (entity_type is None or entity.entity_type == entity_type):
                return entity
        return None

    def find_entities_by_type(self, entity_type: EntityType) -> list[Entity]:
        """按类型查找实体"""
        entity_ids = self._entity_index.get(entity_type.value, set())
        return [self._entities[eid] for eid in entity_ids if eid in self._entities]

    def search_entities(self, query: str, entity_type: EntityType = None, limit: int = 10) -> list[Entity]:
        """搜索实体"""
        query_lower = query.lower()
        results = []

        for entity in self._entities.values():
            # 类型过滤
            if entity_type and entity.entity_type != entity_type:
                continue

            # 名称匹配
            if query_lower in entity.name.lower():
                results.append(entity)
                continue

            # 别名匹配
            for alias in entity.aliases:
                if query_lower in alias.lower():
                    results.append(entity)
                    break

            # 属性匹配
            for value in entity.properties.values():
                if isinstance(value, str) and query_lower in value.lower():
                    results.append(entity)
                    break

        # 按置信度排序
        results.sort(key=lambda e: e.confidence, reverse=True)
        return results[:limit]

    # ========== 关系操作 ==========

    def add_relation(self, relation: Relation) -> str:
        """添加关系"""
        # 验证实体存在
        if relation.source_id not in self._entities:
            raise ValueError(f"Source entity '{relation.source_id}' not found")
        if relation.target_id not in self._entities:
            raise ValueError(f"Target entity '{relation.target_id}' not found")

        # 检查是否已存在相同关系
        existing = self.find_relation(relation.source_id, relation.target_id, relation.relation_type)
        if existing:
            # 更新置信度
            existing.confidence = max(existing.confidence, relation.confidence)
            existing.weight = max(existing.weight, relation.weight)
            logger.debug("Updated existing relation '%s' -> '%s'", relation.source_id, relation.target_id)
            return existing.id

        # 添加新关系
        self._relations[relation.id] = relation
        self._relation_index[relation.source_id].add(relation.id)
        self._relation_index[relation.target_id].add(relation.id)
        self._type_relation_index[relation.relation_type.value].add(relation.id)

        logger.debug("Added relation '%s' -> '%s' (%s)",
                     relation.source_id, relation.target_id, relation.relation_type.value)

        return relation.id

    def get_relation(self, relation_id: str) -> Optional[Relation]:
        """获取关系"""
        return self._relations.get(relation_id)

    def delete_relation(self, relation_id: str) -> bool:
        """删除关系"""
        relation = self._relations.get(relation_id)
        if not relation:
            return False

        # 删除索引
        self._relation_index[relation.source_id].discard(relation_id)
        self._relation_index[relation.target_id].discard(relation_id)
        self._type_relation_index[relation.relation_type.value].discard(relation_id)

        # 删除关系
        del self._relations[relation_id]
        logger.debug("Deleted relation '%s'", relation_id)

        return True

    def find_relation(self, source_id: str, target_id: str, relation_type: RelationType = None) -> Optional[Relation]:
        """查找特定关系"""
        relation_ids = self._relation_index.get(source_id, set())
        for rel_id in relation_ids:
            relation = self._relations.get(rel_id)
            if relation and relation.target_id == target_id:
                if relation_type is None or relation.relation_type == relation_type:
                    return relation
        return None

    def get_entity_relations(self, entity_id: str, direction: str = "both") -> list[Relation]:
        """获取实体的所有关系"""
        relation_ids = self._relation_index.get(entity_id, set())
        relations = []

        for rel_id in relation_ids:
            relation = self._relations.get(rel_id)
            if not relation:
                continue

            if direction == "outgoing" and relation.source_id == entity_id:
                relations.append(relation)
            elif direction == "incoming" and relation.target_id == entity_id:
                relations.append(relation)
            elif direction == "both":
                relations.append(relation)

        return relations

    def get_related_entities(self, entity_id: str, relation_type: RelationType = None, direction: str = "both") -> list[Entity]:
        """获取相关实体"""
        relations = self.get_entity_relations(entity_id, direction)
        related = []

        for relation in relations:
            if relation_type and relation.relation_type != relation_type:
                continue

            if relation.source_id == entity_id:
                target = self._entities.get(relation.target_id)
                if target:
                    related.append(target)
            else:
                source = self._entities.get(relation.source_id)
                if source:
                    related.append(source)

        return related

    def find_relations_by_type(self, relation_type: RelationType) -> list[Relation]:
        """按类型查找关系"""
        relation_ids = self._type_relation_index.get(relation_type.value, set())
        return [self._relations[rid] for rid in relation_ids if rid in self._relations]

    # ========== 图查询 ==========

    def get_neighbors(self, entity_id: str, depth: int = 1) -> dict[str, Any]:
        """获取邻居节点（BFS）"""
        from collections import deque
        visited = set()
        result = {"entities": {}, "relations": {}}
        queue = deque([(entity_id, 0)])

        while queue:
            current_id, current_depth = queue.popleft()

            if current_id in visited or current_depth > depth:
                continue

            visited.add(current_id)
            entity = self._entities.get(current_id)
            if entity:
                result["entities"][current_id] = entity.to_dict()

            # 获取关系
            relations = self.get_entity_relations(current_id)
            for relation in relations:
                result["relations"][relation.id] = relation.to_dict()

                # 添加邻居到队列
                if current_depth < depth:
                    neighbor_id = relation.target_id if relation.source_id == current_id else relation.source_id
                    if neighbor_id not in visited:
                        queue.append((neighbor_id, current_depth + 1))

        return result

    def find_path(self, source_id: str, target_id: str, max_depth: int = 5) -> list[list[str]]:
        """查找两个实体之间的路径（BFS，双向遍历）"""
        from collections import deque
        if source_id == target_id:
            return [[source_id]]

        paths = []
        queue = deque([(source_id, [source_id])])
        visited = {source_id}

        while queue:
            current_id, path = queue.popleft()

            if len(path) > max_depth:
                continue

            # Traverse both outgoing and incoming relations
            relations = self.get_entity_relations(current_id)
            for relation in relations:
                neighbor_id = relation.target_id if relation.source_id == current_id else relation.source_id

                if neighbor_id == target_id:
                    paths.append(path + [neighbor_id])
                    continue

                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, path + [neighbor_id]))

        return paths

    def get_subgraph(self, entity_ids: list[str], include_relations: bool = True) -> dict[str, Any]:
        """获取子图"""
        entities = {}
        relations = {}

        for eid in entity_ids:
            entity = self._entities.get(eid)
            if entity:
                entities[eid] = entity.to_dict()

                if include_relations:
                    entity_relations = self.get_entity_relations(eid)
                    for rel in entity_relations:
                        if rel.id not in relations:
                            relations[rel.id] = rel.to_dict()

        return {"entities": entities, "relations": relations}

    # ========== 统计和分析 ==========

    def get_stats(self) -> dict[str, Any]:
        """获取统计信息"""
        entity_type_counts = {}
        for etype, ids in self._entity_index.items():
            entity_type_counts[etype] = len(ids)

        relation_type_counts = {}
        for rtype, ids in self._type_relation_index.items():
            relation_type_counts[rtype] = len(ids)

        return {
            "total_entities": len(self._entities),
            "total_relations": len(self._relations),
            "entity_types": entity_type_counts,
            "relation_types": relation_type_counts,
        }

    def get_most_connected(self, limit: int = 10) -> list[dict[str, Any]]:
        """获取连接最多的实体"""
        entity_connections = []
        for entity_id in self._entities:
            relations = self.get_entity_relations(entity_id)
            entity_connections.append({
                "entity": self._entities[entity_id].to_dict(),
                "connection_count": len(relations),
            })

        entity_connections.sort(key=lambda x: x["connection_count"], reverse=True)
        return entity_connections[:limit]

    # ========== 导入导出 ==========

    def export_to_dict(self) -> dict[str, Any]:
        """导出为字典"""
        return {
            "entities": {eid: e.to_dict() for eid, e in self._entities.items()},
            "relations": {rid: r.to_dict() for rid, r in self._relations.items()},
            "stats": self.get_stats(),
        }

    def import_from_dict(self, data: dict[str, Any]) -> int:
        """从字典导入"""
        count = 0

        # 导入实体
        for eid, entity_data in data.get("entities", {}).items():
            entity = Entity.from_dict(entity_data)
            self.add_entity(entity)
            count += 1

        # 导入关系
        for rid, relation_data in data.get("relations", {}).items():
            try:
                relation = Relation.from_dict(relation_data)
                self.add_relation(relation)
                count += 1
            except ValueError as e:
                logger.warning("Failed to import relation: %s", e)

        return count

    def clear(self) -> None:
        """清空图谱"""
        self._entities.clear()
        self._relations.clear()
        self._entity_index.clear()
        self._name_index.clear()
        self._relation_index.clear()
        self._type_relation_index.clear()
        logger.info("Knowledge graph cleared")


# 全局知识图谱实例
_knowledge_graph: Optional[KnowledgeGraph] = None


def get_knowledge_graph() -> KnowledgeGraph:
    """获取全局知识图谱实例"""
    global _knowledge_graph
    if _knowledge_graph is None:
        _knowledge_graph = KnowledgeGraph()
    return _knowledge_graph
