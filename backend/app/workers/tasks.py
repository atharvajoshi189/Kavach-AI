"""Celery background tasks for AegisMesh."""

from datetime import datetime, timezone
import logging
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.tasks.health_check_task", bind=True)
def health_check_task(self) -> dict:
    """Demonstration background task to verify worker execution and message pipeline."""
    task_id = self.request.id
    logger.info("Executing health_check_task [%s]", task_id)
    return {
        "task_name": "health_check_task",
        "task_id": task_id,
        "status": "completed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

