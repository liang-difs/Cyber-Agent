"""
Celery application — 4-level priority queue.

Queue priorities:
  celery_critical (P0) — real-time alert triage, incident response
  celery_high     (P1) — pcap analysis, IoC batch queries
  celery_default  (P2) — report generation, RAG indexing
  celery_low      (P3) — bulk data sync, cleanup jobs

Usage:
  from app.tasks.celery_app import celery_app
  from app.tasks.alert_triage import triage_alert
  result = triage_alert.delay(alert_id="...", tenant_id="default")
"""

from __future__ import annotations

import importlib
import os

from celery import Celery

_broker = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
_backend = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")

celery_app = Celery(
    "cybersec_agent",
    broker=_broker,
    backend=_backend,
    include=[
        "app.tasks.alert_triage",
        "app.tasks.pcap_analysis",
    ],
)

from kombu import Queue

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=300,
    task_time_limit=600,
    result_expires=3600,
    # 4-level priority queue definitions
    task_queues=(
        Queue("celery_critical", routing_key="critical", queue_arguments={"x-max-priority": 10}),
        Queue("celery_high", routing_key="high", queue_arguments={"x-max-priority": 7}),
        Queue("celery_default", routing_key="default", queue_arguments={"x-max-priority": 4}),
        Queue("celery_low", routing_key="low", queue_arguments={"x-max-priority": 1}),
    ),
    task_default_queue="celery_default",
    task_routes={
        "app.tasks.alert_triage.*": {"queue": "celery_critical"},
        "app.tasks.pcap_analysis.*": {"queue": "celery_high"},
    },
)

celery_app.autodiscover_tasks(["app.tasks"])

for module_name in ("app.tasks.alert_triage", "app.tasks.pcap_analysis"):
    importlib.import_module(module_name)
