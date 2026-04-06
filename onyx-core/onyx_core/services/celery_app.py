"""
ONYX CTI — Celery Application
Distributed task queue for crawlers, NLP processing, analysis, and enrichment.
Uses Redis as broker and result backend.
"""

from __future__ import annotations

import os

from celery import Celery

# Create Celery app
celery = Celery(
    "onyx",
    broker=os.getenv("CELERY_BROKER_URL", "redis://:onyx_redis_secret_2026@redis:6379/1"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://:onyx_redis_secret_2026@redis:6379/1"),
)

# Configuration
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_default_queue="default",
    task_queues={
        "default": {"routing_key": "default"},
        "crawlers": {"routing_key": "crawlers"},
        "nlp": {"routing_key": "nlp"},
        "analysis": {"routing_key": "analysis"},
    },
    task_routes={
        "onyx_crawlers.*": {"queue": "crawlers"},
        "onyx_nlp.*": {"queue": "nlp"},
        "onyx_analyzers.*": {"queue": "analysis"},
    },
    beat_schedule={
        "clearweb-pastebin-monitor": {
            "task": "onyx_crawlers.clearweb.pastebin_monitor.scan",
            "schedule": 300.0,  # Every 5 minutes
        },
        "clearweb-github-monitor": {
            "task": "onyx_crawlers.clearweb.github_monitor.scan",
            "schedule": 600.0,  # Every 10 minutes
        },
        "dashboard-stats-refresh": {
            "task": "onyx_api.tasks.refresh_dashboard_cache",
            "schedule": 30.0,  # Every 30 seconds
        },
        "ioc-expiration-check": {
            "task": "onyx_api.tasks.expire_stale_iocs",
            "schedule": 3600.0,  # Every hour
        },
    },
)

# Auto-discover tasks from all ONYX packages
celery.autodiscover_tasks([
    "onyx_crawlers.darkweb",
    "onyx_crawlers.clearweb",
    "onyx_nlp.processors",
    "onyx_analyzers",
    "onyx_api.tasks",
])
