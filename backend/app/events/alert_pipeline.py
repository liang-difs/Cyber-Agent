"""Alert Pipeline — 告警事件驱动管线。

当新告警产生时，自动触发：
1. 规则引擎匹配
2. 知识图谱更新
3. 响应动作执行
4. 多智能体协同分析
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class AlertPipeline:
    """告警事件驱动管线"""

    def __init__(self):
        self._rule_manager = None
        self._knowledge_graph = None
        self._entity_extractor = None
        self._action_manager = None
        self._coordinator = None
        self._enabled = True
        self._stats = {
            "total_processed": 0,
            "rules_matched": 0,
            "entities_extracted": 0,
            "actions_executed": 0,
            "errors": 0,
        }

    @property
    def rule_manager(self):
        if self._rule_manager is None:
            from app.rules.rule_manager import get_rule_manager
            self._rule_manager = get_rule_manager()
        return self._rule_manager

    @property
    def knowledge_graph(self):
        if self._knowledge_graph is None:
            from app.knowledge_graph.graph import get_knowledge_graph
            self._knowledge_graph = get_knowledge_graph()
        return self._knowledge_graph

    @property
    def entity_extractor(self):
        if self._entity_extractor is None:
            from app.knowledge_graph.extractor import get_entity_extractor
            self._entity_extractor = get_entity_extractor()
        return self._entity_extractor

    @property
    def action_manager(self):
        if self._action_manager is None:
            from app.response.action_manager import get_action_manager
            self._action_manager = get_action_manager()
        return self._action_manager

    async def process_alert(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """处理新告警事件"""
        if not self._enabled:
            return {"status": "disabled"}

        results = {
            "alert_id": alert_data.get("id", ""),
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "stages": {},
        }

        try:
            # 阶段1: 规则引擎匹配
            rule_results = await self._match_rules(alert_data)
            results["stages"]["rule_match"] = rule_results
            if rule_results.get("matched"):
                self._stats["rules_matched"] += 1

            # 阶段2: 知识图谱更新
            graph_results = await self._update_knowledge_graph(alert_data)
            results["stages"]["knowledge_graph"] = graph_results
            self._stats["entities_extracted"] += graph_results.get("entities_added", 0)

            # 阶段3: 响应动作执行（仅对高危告警）
            severity = alert_data.get("severity", "medium")
            verdict = alert_data.get("verdict", "")
            confidence = alert_data.get("confidence", 0.0)

            if self._should_auto_respond(severity, verdict, confidence):
                action_results = await self._execute_response_actions(alert_data)
                results["stages"]["response_actions"] = action_results
                self._stats["actions_executed"] += action_results.get("actions_executed", 0)
            else:
                results["stages"]["response_actions"] = {"skipped": True, "reason": "Below threshold"}

            # 阶段4: 多智能体协同分析（可选，对关键告警）
            if severity == "critical" and confidence >= 0.8:
                multi_agent_results = await self._trigger_multi_agent_analysis(alert_data)
                results["stages"]["multi_agent"] = multi_agent_results
            else:
                results["stages"]["multi_agent"] = {"skipped": True, "reason": "Not critical"}

            self._stats["total_processed"] += 1
            results["success"] = True

        except Exception as e:
            logger.error("Alert pipeline error: %s", e)
            self._stats["errors"] += 1
            results["success"] = False
            results["error"] = str(e)

        return results

    async def _match_rules(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """使用规则引擎匹配告警"""
        try:
            # 构建日志事件格式
            log_event = {
                "rule_id": alert_data.get("rule_id", ""),
                "description": alert_data.get("description", ""),
                "src_ip": alert_data.get("src_ip", ""),
                "dst_ip": alert_data.get("dst_ip", ""),
                "severity": alert_data.get("severity", ""),
                "status": alert_data.get("status", ""),
            }

            # 匹配Sigma规则
            matches = self.rule_manager.match_log_events([log_event])

            if matches:
                return {
                    "matched": True,
                    "match_count": len(matches),
                    "rules": [
                        {
                            "rule_name": m.rule_name,
                            "severity": m.severity,
                            "confidence": m.confidence,
                        }
                        for m in matches
                    ],
                }

            return {"matched": False, "match_count": 0}

        except Exception as e:
            logger.warning("Rule matching failed: %s", e)
            return {"matched": False, "error": str(e)}

    async def _update_knowledge_graph(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """将告警中的IoC注入知识图谱"""
        try:
            # 从告警数据中提取实体
            text = f"""
            规则: {alert_data.get('rule_id', '')}
            描述: {alert_data.get('description', '')}
            源IP: {alert_data.get('src_ip', '')}
            目标IP: {alert_data.get('dst_ip', '')}
            """

            entities = self.entity_extractor.extract_entities(text)

            # 添加到知识图谱
            entities_added = 0
            for entity in entities:
                try:
                    self.knowledge_graph.add_entity(entity)
                    entities_added += 1
                except Exception as e:
                    logger.warning("Failed to add entity to graph: %s", e)

            # 提取并添加关系
            relations = self.entity_extractor.extract_relations(text, entities)
            relations_added = 0
            for relation in relations:
                try:
                    self.knowledge_graph.add_relation(relation)
                    relations_added += 1
                except Exception as e:
                    logger.warning("Failed to add relation to graph: %s", e)

            return {
                "entities_added": entities_added,
                "relations_added": relations_added,
                "total_entities": len(entities),
            }

        except Exception as e:
            logger.warning("Knowledge graph update failed: %s", e)
            return {"entities_added": 0, "error": str(e)}

    def _should_auto_respond(self, severity: str, verdict: str, confidence: float) -> bool:
        """判断是否应该自动响应"""
        # 高危或关键告警，且为真阳性，且置信度足够高
        if severity in ("critical", "high") and verdict == "true_positive" and confidence >= 0.7:
            return True
        # 关键告警，即使没有verdict，只要置信度高
        if severity == "critical" and confidence >= 0.8:
            return True
        return False

    async def _execute_response_actions(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """执行响应动作"""
        try:
            # 构建威胁数据
            threat_data = {
                "type": alert_data.get("rule_id", "unknown"),
                "severity": alert_data.get("severity", "medium"),
                "ip": alert_data.get("src_ip"),
                "host": alert_data.get("dst_ip"),
                "description": alert_data.get("description", ""),
            }

            # 使用auto_respond自动决定执行哪些动作
            results = await self.action_manager.auto_respond(threat_data)

            successful = sum(1 for r in results if r.success)
            failed = len(results) - successful

            return {
                "actions_executed": len(results),
                "successful": successful,
                "failed": failed,
                "details": [
                    {
                        "action_type": r.action_type,
                        "success": r.success,
                        "message": r.message,
                    }
                    for r in results
                ],
            }

        except Exception as e:
            logger.warning("Response action execution failed: %s", e)
            return {"actions_executed": 0, "error": str(e)}

    async def _trigger_multi_agent_analysis(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """触发多智能体协同分析"""
        try:
            from app.api.multi_agent import get_coordinator
            from app.multi_agent.protocol import TaskRequest, TaskPriority

            coordinator = get_coordinator()

            # 创建应急响应任务
            task = TaskRequest(
                task_type="incident_response",
                description=f"分析告警: {alert_data.get('rule_id', '')} - {alert_data.get('description', '')}",
                parameters={
                    "alert_id": alert_data.get("id", ""),
                    "rule_id": alert_data.get("rule_id", ""),
                    "src_ip": alert_data.get("src_ip", ""),
                    "dst_ip": alert_data.get("dst_ip", ""),
                    "severity": alert_data.get("severity", ""),
                },
                priority=TaskPriority.HIGH,
            )

            # 执行任务
            result = await coordinator.execute_task(task)

            return {
                "triggered": True,
                "task_id": result.task_id,
                "success": result.success,
                "steps_executed": result.result.get("steps_executed", 0),
            }

        except Exception as e:
            logger.warning("Multi-agent analysis failed: %s", e)
            return {"triggered": False, "error": str(e)}

    def get_stats(self) -> dict[str, Any]:
        """获取统计信息"""
        return {
            **self._stats,
            "enabled": self._enabled,
        }

    def enable(self) -> None:
        """启用管线"""
        self._enabled = True

    def disable(self) -> None:
        """禁用管线"""
        self._enabled = False


# 全局告警管线实例
_alert_pipeline: Optional[AlertPipeline] = None


def get_alert_pipeline() -> AlertPipeline:
    """获取全局告警管线实例"""
    global _alert_pipeline
    if _alert_pipeline is None:
        _alert_pipeline = AlertPipeline()
    return _alert_pipeline
