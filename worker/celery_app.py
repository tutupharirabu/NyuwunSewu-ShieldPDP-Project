from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "nyuwunsewu",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["worker.tasks"],
)
celery_app.conf.update(
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_time_limit=60 * 60,
    task_soft_time_limit=55 * 60,
)

