"""
Celery task worker — async background processing.
Allows the API to return a job_id immediately while heavy ML
processing runs asynchronously.

Usage:
    celery -A app.worker worker --loglevel=info --concurrency=4
"""

import asyncio
import logging
from datetime import datetime, timezone

from celery import Celery
from celery.utils.log import get_task_logger

from app.core.config import settings

logger = get_task_logger(__name__)

celery_app = Celery(
    "ai_privacy_shield",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,                # acknowledge only after completion
    worker_prefetch_multiplier=1,       # one task at a time per worker (ML is memory-heavy)
    result_expires=3600,                # results stored for 1 hour
    task_soft_time_limit=120,           # 2-minute soft limit
    task_time_limit=180,                # 3-minute hard kill
    task_routes={
        "app.worker.process_image_task": {"queue": "processing"},
        "app.worker.cleanup_task":       {"queue": "maintenance"},
    },
)


@celery_app.task(
    bind=True,
    name="app.worker.process_image_task",
    max_retries=2,
    default_retry_delay=10,
)
def process_image_task(
    self,
    image_bytes_b64: str,
    job_id: str,
    protection_level: str,
    modules_dict: dict,
    user_id: str | None = None,
) -> dict:
    """
    Celery task: runs the full protection pipeline in a worker process.
    Returns a JSON-serialisable result dict.
    """
    import base64
    from app.schemas.schemas import ModulesConfig
    from app.services.processing_service import get_processing_service

    logger.info("Worker starting job %s (level=%s)", job_id, protection_level)

    try:
        self.update_state(state="PROGRESS", meta={"progress": 10, "step": "Decoding image"})

        image_bytes = base64.b64decode(image_bytes_b64)
        modules = ModulesConfig(**modules_dict)
        service = get_processing_service()

        self.update_state(state="PROGRESS", meta={"progress": 20, "step": "Running AI pipeline"})

        # Run async code in a fresh event loop
        result = asyncio.get_event_loop().run_until_complete(
            service.process(
                image_bytes=image_bytes,
                job_id=job_id,
                protection_level=protection_level,
                modules=modules,
                user_id=user_id,
            )
        )

        self.update_state(state="PROGRESS", meta={"progress": 95, "step": "Finalising"})

        # Convert Pydantic model to dict for JSON serialisation
        return result.model_dump(mode="json")

    except Exception as exc:
        logger.exception("Job %s failed: %s", job_id, exc)
        raise self.retry(exc=exc)


@celery_app.task(name="app.worker.cleanup_task")
def cleanup_task(max_age_hours: int = 24) -> dict:
    """
    Periodic maintenance: delete output files older than max_age_hours.
    Schedule with Celery Beat:
        celery -A app.worker beat --loglevel=info
    """
    import os
    import time
    from pathlib import Path

    cutoff = time.time() - (max_age_hours * 3600)
    deleted = 0

    for directory in [settings.UPLOAD_DIR, settings.OUTPUT_DIR]:
        for f in Path(directory).iterdir():
            if f.is_file() and f.stat().st_mtime < cutoff:
                f.unlink()
                deleted += 1

    logger.info("Cleanup: deleted %d files older than %dh", deleted, max_age_hours)
    return {"deleted_files": deleted, "max_age_hours": max_age_hours}


# ── Celery Beat schedule (periodic tasks) ────────────────────────────────

celery_app.conf.beat_schedule = {
    "cleanup-old-files-daily": {
        "task": "app.worker.cleanup_task",
        "schedule": 86400.0,  # every 24 hours
        "args": (24,),
    },
}
