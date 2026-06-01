import asyncio

from worker.celery_app import celery_app
from app.services.scan_service import run_scan_by_id


@celery_app.task(name="worker.tasks.run_scan_task")
def run_scan_task(scan_id: str, runtime_options: dict | None = None) -> None:
    asyncio.run(run_scan_by_id(scan_id, runtime_options or {}))

