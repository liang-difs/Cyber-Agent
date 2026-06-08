"""Knowledge Graph Tool — Query and manage the knowledge graph.

知识图谱工具：查询和管理知识图谱。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.governance.tool_protocol import ToolInput, ToolResult
from app.knowledge_graph import EntityType, RelationType
from app.knowledge_graph.graph import get_knowledge_graph
from app.knowledge_graph.extractor import get_entity_extractor

logger = logging.getLogger(__name__)


class KnowledgeGraphInput(ToolInput):
    """知识图谱工具输入"""

    operation: str = Field(
        ...,
        description="操作类型: search(搜索实体), query(查询关系), extract(提取实体), stats(统计信息), path(查找路径)"
    )
    query: Optional[str] = Field(default=None, description="搜索查询")
    entity_type: Optional[str] = Field(default=None, description="实体类型过滤")
    entity_id: Optional[str] = Field(default=None, description="实体ID")
    target_id: Optional[str] = Field(default=None, description="目标实体ID(用于路径查询)")
    content: Optional[str] = Field(default=None, description="文本内容(用于实体提取)")
    depth: int = Field(default=1, description="查询深度")
    limit: int = Field(default=10, description="结果数量限制")


class KnowledgeGraphTool:
    """知识图谱工具"""

    name = "knowledge_graph"
    version = "v1"
    input_class = KnowledgeGraphInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "knowledge_graph",
                "description": (
                    "查询和管理知识图谱。支持以下操作：\n"
                    "- search: 搜索实体（CVE、恶意软件、IP、域名等）\n"
                    "- query: 查询实体的关系和邻居\n"
                    "- extract: 从文本中提取实体和关系\n"
                    "- stats: 获取图谱统计信息\n"
                    "- path: 查找两个实体之间的路径\n\n"
                    "可用于威胁情报关联分析、攻击链溯源、漏洞影响评估。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "operation": {
                            "type": "string",
                            "enum": ["search", "query", "extract", "stats", "path"],
                            "description": "操作类型",
                        },
                        "query": {
                            "type": "string",
                            "description": "搜索查询",
                        },
                        "entity_type": {
                            "type": "string",
                            "enum": [
                                "cve", "malware", "threat_actor", "technique",
                                "ip", "domain", "hash", "url", "asset",
                            ],
                            "description": "实体类型过滤",
                        },
                        "entity_id": {
                            "type": "string",
                            "description": "实体ID",
                        },
                        "target_id": {
                            "type": "string",
                            "description": "目标实体ID(用于路径查询)",
                        },
                        "content": {
                            "type": "string",
                            "description": "文本内容(用于实体提取)",
                        },
                        "depth": {
                            "type": "integer",
                            "description": "查询深度，默认1",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "结果数量限制，默认10",
                        },
                    },
                    "required": ["operation"],
                },
            },
        }

    async def execute(self, input_data: KnowledgeGraphInput) -> ToolResult:
        """执行知识图谱操作"""
        start_time = time.time()
        trace_id = input_data.trace_id

        try:
            graph = get_knowledge_graph()
            extractor = get_entity_extractor()

            operation = input_data.operation

            # 操作别名：LLM 可能发送非标准操作名
            operation_aliases = {
                "search_entity": "search",
                "search_entities": "search",
                "find": "search",
                "lookup": "search",
                "query_entity": "query",
                "query_relation": "query",
                "get_neighbors": "query",
                "get_relations": "query",
                "extract_entities": "extract",
                "extract_iocs": "extract",
                "statistics": "stats",
                "get_stats": "stats",
                "find_path": "path",
                "shortest_path": "path",
            }
            operation = operation_aliases.get(operation, operation)

            if operation == "search":
                result = await self._search(graph, input_data)
            elif operation == "query":
                result = await self._query(graph, input_data)
            elif operation == "extract":
                result = await self._extract(graph, extractor, input_data)
            elif operation == "stats":
                result = await self._stats(graph)
            elif operation == "path":
                result = await self._find_path(graph, input_data)
            else:
                return ToolResult(
                    success=False,
                    tool_name=self.name,
                    tool_version=self.version,
                    error=f"Invalid operation: {operation}",
                    trace_id=trace_id,
                )

            execution_time = int((time.time() - start_time) * 1000)

            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data=result,
                confidence=0.9,
                evidence_source=["knowledge_graph"],
                trace_id=trace_id,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            logger.error("Knowledge graph operation failed: %s", e)
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                error=str(e),
                trace_id=trace_id,
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def _search(self, graph, input_data: KnowledgeGraphInput) -> dict[str, Any]:
        """搜索实体"""
        query = input_data.query
        if not query:
            return {"error": "query is required for search"}

        entity_type = None
        if input_data.entity_type:
            try:
                entity_type = EntityType(input_data.entity_type)
            except ValueError:
                return {"error": f"Invalid entity type: {input_data.entity_type}"}

        entities = graph.search_entities(query, entity_type, input_data.limit)

        return {
            "operation": "search",
            "query": query,
            "entity_type": input_data.entity_type,
            "total_results": len(entities),
            "entities": [e.to_dict() for e in entities],
        }

    async def _query(self, graph, input_data: KnowledgeGraphInput) -> dict[str, Any]:
        """查询实体关系"""
        entity_id = input_data.entity_id
        if not entity_id:
            return {"error": "entity_id is required for query"}

        entity = graph.get_entity(entity_id)
        if not entity:
            return {"error": f"Entity not found: {entity_id}"}

        # 获取邻居
        neighbors = graph.get_neighbors(entity_id, input_data.depth)

        # 获取关系
        relations = graph.get_entity_relations(entity_id)

        return {
            "operation": "query",
            "entity": entity.to_dict(),
            "depth": input_data.depth,
            "neighbors": neighbors,
            "relations": [r.to_dict() for r in relations],
        }

    async def _extract(self, graph, extractor, input_data: KnowledgeGraphInput) -> dict[str, Any]:
        """提取实体"""
        content = input_data.content
        if not content:
            return {"error": "content is required for extract"}

        # 提取实体
        entities = extractor.extract_entities(content)

        # 提取关系
        relations = extractor.extract_relations(content, entities)

        # 添加到图谱
        added_entities = []
        for entity in entities:
            entity_id = graph.add_entity(entity)
            added_entities.append({"id": entity_id, "name": entity.name, "type": entity.entity_type.value})

        added_relations = []
        for relation in relations:
            try:
                relation_id = graph.add_relation(relation)
                added_relations.append({"id": relation_id, "type": relation.relation_type.value})
            except ValueError as e:
                logger.warning("Failed to add relation: %s", e)

        return {
            "operation": "extract",
            "total_entities": len(entities),
            "total_relations": len(relations),
            "entities": added_entities,
            "relations": added_relations,
        }

    async def _stats(self, graph) -> dict[str, Any]:
        """获取统计信息"""
        stats = graph.get_stats()
        most_connected = graph.get_most_connected(5)

        return {
            "operation": "stats",
            "statistics": stats,
            "most_connected": most_connected,
        }

    async def _find_path(self, graph, input_data: KnowledgeGraphInput) -> dict[str, Any]:
        """查找路径"""
        source_id = input_data.entity_id
        target_id = input_data.target_id

        if not source_id or not target_id:
            return {"error": "entity_id and target_id are required for path"}

        source = graph.get_entity(source_id)
        target = graph.get_entity(target_id)

        if not source:
            return {"error": f"Source entity not found: {source_id}"}
        if not target:
            return {"error": f"Target entity not found: {target_id}"}

        paths = graph.find_path(source_id, target_id, input_data.depth)

        return {
            "operation": "path",
            "source": source.to_dict(),
            "target": target.to_dict(),
            "paths": paths,
            "path_count": len(paths),
        }


# 创建工具实例
knowledge_graph_tool = KnowledgeGraphTool()
