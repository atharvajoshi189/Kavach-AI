"""Celery application configuration for AegisMesh background workers.

Uses Redis as both the message broker and the result backend.
All serialization is restricted to JSON — pickle is never used.
"""

from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "aegismesh",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks", "app.workers.guardian_tasks", "app.workers.ai_tasks"],
)

celery_app.conf.update(
    # Serialization — JSON only, no pickle
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task tracking
    task_track_started=True,

    # Time limits (seconds)
    task_soft_time_limit=300,
    task_time_limit=600,

    # Result expiration (1 hour)
    result_expires=3600,

    # Retry configuration
    task_acks_late=True,
    task_reject_on_worker_lost=True,

    # Worker configuration suitable for development
    worker_concurrency=2,
    worker_prefetch_multiplier=1,
)

