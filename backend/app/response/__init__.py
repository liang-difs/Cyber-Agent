"""Response Actions Module.

提供自动响应动作，包括阻断、隔离、通知等功能。
"""

from app.response.action_manager import ActionManager, get_action_manager
from app.response.actions import (
    BlockIPAction,
    IsolateHostAction,
    NotifyAction,
    QuarantineFileAction,
    DisableAccountAction,
)

__all__ = [
    "ActionManager",
    "get_action_manager",
    "BlockIPAction",
    "IsolateHostAction",
    "NotifyAction",
    "QuarantineFileAction",
    "DisableAccountAction",
]
