"""Action Manager — Manages and executes response actions.

动作管理器：管理和执行响应动作。
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.response.actions import (
    ActionStatus,
    ActionResult,
    BaseAction,
    BlockIPAction,
    IsolateHostAction,
    NotifyAction,
    QuarantineFileAction,
    DisableAccountAction,
)

logger = logging.getLogger(__name__)


async def _persist_action(result: ActionResult, params: dict[str, Any], tenant_id: str = "default") -> None:
    """Persist action result to database (best-effort)."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import ResponseAction

        factory = get_session_factory()
        if factory is None:
            return

        async with factory() as session:
            record = ResponseAction(
                id=result.action_id,
                action_type=result.action_type,
                status=result.status.value,
                success=result.success,
                message=result.message,
                details=result.details,
                params=params,
                rollback_available=result.rollback_available,
                tenant_id=tenant_id,
                execution_time_ms=result.execution_time_ms,
            )
            session.add(record)
            await session.commit()
    except Exception as e:
        logger.warning("Failed to persist action %s: %s", result.action_id, e)


async def _update_action_status(action_id: str, status: str, success: bool) -> None:
    """Update action status in database (best-effort)."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import ResponseAction
        from sqlalchemy import update

        factory = get_session_factory()
        if factory is None:
            return

        async with factory() as session:
            await session.execute(
                update(ResponseAction)
                .where(ResponseAction.id == action_id)
                .values(status=status, success=success, rolled_back=(status == "rolled_back"))
            )
            await session.commit()
    except Exception as e:
        logger.warning("Failed to update action %s: %s", action_id, e)


class ActionManager:
    """动作管理器"""

    def __init__(self, config: dict[str, Any] = None):
        self.config = config or {}
        self._actions: dict[str, BaseAction] = {}
        self._action_history: list[dict[str, Any]] = []
        self._action_types: dict[str, type] = {
            "block_ip": BlockIPAction,
            "isolate_host": IsolateHostAction,
            "notify": NotifyAction,
            "quarantine_file": QuarantineFileAction,
            "disable_account": DisableAccountAction,
        }

    def register_action_type(self, action_type: str, action_class: type) -> None:
        """注册动作类型"""
        self._action_types[action_type] = action_class
        logger.info("Registered action type: %s", action_type)

    async def execute_action(
        self,
        action_type: str,
        params: dict[str, Any],
        action_id: str = None,
    ) -> ActionResult:
        """执行动作"""
        if action_type not in self._action_types:
            return ActionResult(
                action_id=action_id or str(uuid.uuid4()),
                action_type=action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"Unknown action type: {action_type}",
            )

        # 创建动作实例
        action_id = action_id or str(uuid.uuid4())
        action_class = self._action_types[action_type]
        action = action_class(action_id)

        # 执行动作
        try:
            result = await action.execute(params)

            # 保存动作实例（用于回滚）
            if result.success:
                self._actions[action_id] = action

            # 记录历史（内存 + 数据库）
            self._action_history.append({
                "action_id": action_id,
                "action_type": action_type,
                "status": result.status.value,
                "success": result.success,
                "message": result.message,
                "executed_at": result.executed_at.isoformat(),
                "params": params,
            })

            # 持久化到数据库
            await _persist_action(result, params, self.config.get("tenant_id", "default"))

            return result

        except Exception as e:
            logger.error("Action execution failed: %s", e)
            return ActionResult(
                action_id=action_id,
                action_type=action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"Action execution failed: {str(e)}",
            )

    async def execute_actions(
        self,
        actions: list[dict[str, Any]],
    ) -> list[ActionResult]:
        """批量执行动作"""
        results = []

        for action_def in actions:
            action_type = action_def.get("type")
            params = action_def.get("params", {})
            action_id = action_def.get("id")

            result = await self.execute_action(action_type, params, action_id)
            results.append(result)

        return results

    async def rollback_action(self, action_id: str) -> ActionResult:
        """回滚动作"""
        action = self._actions.get(action_id)
        if not action:
            return ActionResult(
                action_id=action_id,
                action_type="unknown",
                status=ActionStatus.FAILED,
                success=False,
                message=f"Action not found: {action_id}",
            )

        if not action.can_rollback():
            return ActionResult(
                action_id=action_id,
                action_type=action.action_type,
                status=ActionStatus.SKIPPED,
                success=True,
                message="Action does not support rollback",
            )

        try:
            result = await action.rollback()

            # 记录历史（内存 + 数据库）
            self._action_history.append({
                "action_id": action_id,
                "action_type": action.action_type,
                "status": "rolled_back",
                "success": result.success,
                "message": result.message,
                "executed_at": datetime.now(timezone.utc).isoformat(),
            })

            # 更新数据库状态
            await _update_action_status(action_id, "rolled_back", result.success)

            # 移除动作
            if result.success:
                del self._actions[action_id]

            return result

        except Exception as e:
            logger.error("Action rollback failed: %s", e)
            return ActionResult(
                action_id=action_id,
                action_type=action.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"Action rollback failed: {str(e)}",
            )

    def get_action(self, action_id: str) -> Optional[BaseAction]:
        """获取动作"""
        return self._actions.get(action_id)

    def get_action_history(self, limit: int = 100) -> list[dict[str, Any]]:
        """获取动作历史"""
        return self._action_history[-limit:]

    def get_available_actions(self) -> list[dict[str, str]]:
        """获取可用动作类型"""
        return [
            {
                "type": action_type,
                "class": action_class.__name__,
                "description": action_class.__doc__ or "",
            }
            for action_type, action_class in self._action_types.items()
        ]

    def get_stats(self) -> dict[str, Any]:
        """获取统计信息"""
        total = len(self._action_history)
        successful = sum(1 for a in self._action_history if a.get("success"))
        failed = total - successful

        by_type = {}
        for action in self._action_history:
            action_type = action.get("action_type", "unknown")
            by_type[action_type] = by_type.get(action_type, 0) + 1

        return {
            "total_actions": total,
            "successful": successful,
            "failed": failed,
            "success_rate": successful / total if total > 0 else 0,
            "by_type": by_type,
            "pending_rollbacks": len(self._actions),
        }

    def clear_history(self) -> None:
        """清空历史"""
        self._action_history.clear()

    async def auto_respond(self, threat_data: dict[str, Any]) -> list[ActionResult]:
        """根据威胁数据自动响应"""
        actions = []
        severity = threat_data.get("severity", "medium")
        threat_type = threat_data.get("type", "")

        # 根据威胁类型和严重程度决定响应动作
        if severity in ("critical", "high"):
            # 高危威胁：阻断 + 隔离 + 通知
            if "ip" in threat_data:
                actions.append({
                    "type": "block_ip",
                    "params": {
                        "ip": threat_data["ip"],
                        "duration_seconds": 3600,
                        "reason": f"High severity threat: {threat_type}",
                    },
                })

            if "host" in threat_data:
                actions.append({
                    "type": "isolate_host",
                    "params": {
                        "host": threat_data["host"],
                        "reason": f"High severity threat: {threat_type}",
                    },
                })

            # 通知安全团队
            actions.append({
                "type": "notify",
                "params": {
                    "recipients": self.config.get("notify_recipients", ["security-team"]),
                    "message": f"High severity threat detected: {threat_type}",
                    "severity": severity,
                },
            })

        elif severity == "medium":
            # 中危威胁：通知 + 可选阻断
            if "ip" in threat_data:
                actions.append({
                    "type": "block_ip",
                    "params": {
                        "ip": threat_data["ip"],
                        "duration_seconds": 1800,
                        "reason": f"Medium severity threat: {threat_type}",
                    },
                })

            actions.append({
                "type": "notify",
                "params": {
                    "recipients": self.config.get("notify_recipients", ["security-team"]),
                    "message": f"Medium severity threat detected: {threat_type}",
                    "severity": severity,
                },
            })

        else:
            # 低危威胁：仅通知
            actions.append({
                "type": "notify",
                "params": {
                    "recipients": self.config.get("notify_recipients", ["security-team"]),
                    "message": f"Low severity threat detected: {threat_type}",
                    "severity": severity,
                },
            })

        # 执行动作
        results = await self.execute_actions(actions)
        return results


# 全局动作管理器实例
_action_manager: Optional[ActionManager] = None

# 默认配置
DEFAULT_CONFIG = {
    "notify_recipients": ["security-team"],
    "auto_respond_enabled": True,
    "auto_respond_min_severity": "high",
    "block_ip_duration_seconds": 3600,
}


def get_action_manager() -> ActionManager:
    """获取全局动作管理器实例"""
    global _action_manager
    if _action_manager is None:
        _action_manager = ActionManager(config=DEFAULT_CONFIG)
    return _action_manager
