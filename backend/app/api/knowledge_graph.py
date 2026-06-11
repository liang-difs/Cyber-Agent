"""Knowledge Graph API — direct endpoints for graph queries.

知识图谱专用 API，提供实体搜索、关系查询、统计等功能。
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.knowledge_graph.entity import EntityType
from app.knowledge_graph.graph import get_knowledge_graph

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/knowledge-graph", tags=["Knowledge Graph"])


def _get_current_user(user=Depends(get_current_user)):
    return user


@router.get("/stats")
async def get_stats(user=Depends(_get_current_user)):
    """获取知识图谱统计信息"""
    try:
        kg = get_knowledge_graph()
        stats = kg.get_stats()
        return stats
    except Exception as e:
        logger.error("Failed to get KG stats: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/entities")
async def list_entities(
    entity_type: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    user=Depends(_get_current_user),
):
    """搜索或列出实体"""
    try:
        kg = get_knowledge_graph()

        if query:
            et = None
            if entity_type:
                try:
                    et = EntityType(entity_type)
                except ValueError:
                    pass
            entities = kg.search_entities(query, entity_type=et, limit=limit)
        elif entity_type:
            try:
                et = EntityType(entity_type)
                entities = kg.find_entities_by_type(et)[:limit]
            except ValueError:
                entities = []
        else:
            # Return a sample of entities
            all_entities = []
            for et in EntityType:
                found = kg.find_entities_by_type(et)[:5]
                all_entities.extend(found)
                if len(all_entities) >= limit:
                    break
            entities = all_entities[:limit]

        return {
            "entities": [e.to_dict() for e in entities],
            "total": len(entities),
        }
    except Exception as e:
        logger.error("Failed to list entities: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/entities/{entity_id}")
async def get_entity(entity_id: str, user=Depends(_get_current_user)):
    """获取实体详情"""
    try:
        kg = get_knowledge_graph()
        entity = kg.get_entity(entity_id)
        if not entity:
            raise HTTPException(status_code=404, detail="Entity not found")

        # Get neighbors
        neighbors = kg.get_neighbors(entity_id, depth=1)
        relations = kg.get_entity_relations(entity_id)

        return {
            "entity": entity.to_dict(),
            "neighbors": neighbors,
            "relations": [r.to_dict() for r in relations],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get entity: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/relations")
async def list_relations(
    entity_id: Optional[str] = None,
    relation_type: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    user=Depends(_get_current_user),
):
    """列出关系"""
    try:
        kg = get_knowledge_graph()

        if entity_id:
            relations = kg.get_entity_relations(entity_id)[:limit]
        elif relation_type:
            from app.knowledge_graph.relation import RelationType
            try:
                rt = RelationType(relation_type)
                relations = kg.find_relations_by_type(rt)[:limit]
            except ValueError:
                relations = []
        else:
            relations = []

        return {
            "relations": [r.to_dict() for r in relations],
            "total": len(relations),
        }
    except Exception as e:
        logger.error("Failed to list relations: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/search")
async def search(
    q: str = Query(..., description="Search query"),
    entity_type: Optional[str] = None,
    limit: int = Query(default=20, ge=1, le=100),
    user=Depends(_get_current_user),
):
    """搜索实体"""
    try:
        kg = get_knowledge_graph()
        et = None
        if entity_type:
            try:
                et = EntityType(entity_type)
            except ValueError:
                pass

        entities = kg.search_entities(q, entity_type=et, limit=limit)

        return {
            "entities": [e.to_dict() for e in entities],
            "total": len(entities),
            "query": q,
        }
    except Exception as e:
        logger.error("Failed to search entities: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
