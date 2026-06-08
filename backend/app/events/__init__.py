"""Event Bus Module — 事件驱动管线。

提供告警事件的自动处理和模块间联动。
"""

from app.events.alert_pipeline import AlertPipeline, get_alert_pipeline

__all__ = [
    "AlertPipeline",
    "get_alert_pipeline",
]
