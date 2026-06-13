"""SLA monitor untuk breach notification Pasal 46 UU PDP (3x24 jam).

Menjalankan loop asyncio (di FastAPI lifespan) yang memantau jam SLA 72 jam
tiap breach aktif dan mengirim reminder berjenjang (48/24/6/1 jam) lalu menandai
overdue. Fungsi `due_sla_alerts` sengaja murni agar mudah diuji tanpa DB/waktu.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.session import get_sessionmaker
from app.models.agent import BreachNotification
from app.services.breach_notification import BreachNotificationService

logger = logging.getLogger(__name__)


def due_sla_alerts(
    hours_remaining: float,
    is_overdue: bool,
    already_sent: list[str],
    thresholds: list[int],
) -> list[str]:
    """Kembalikan label ambang yang BARU harus dialertkan (anti-spam).

    - Untuk tiap threshold T (mis. 48,24,6,1): jika hours_remaining <= T dan
      "T" belum di already_sent → ikutkan.
    - Jika is_overdue dan "overdue" belum terkirim → ikutkan "overdue".
    """
    sent = set(already_sent)
    new: list[str] = []
    for t in sorted(thresholds, reverse=True):  # 48, 24, 6, 1
        label = str(t)
        if hours_remaining <= t and label not in sent:
            new.append(label)
    if is_overdue and "overdue" not in sent:
        new.append("overdue")
    return new


async def process_breach_alerts(
    session: AsyncSession, thresholds: list[int], send: bool = True
) -> dict[str, list[str]]:
    """Periksa semua breach aktif; kirim reminder/overdue yang baru; commit.

    Kembalikan map breach_id -> daftar label yang baru dialertkan.
    """
    stmt = select(BreachNotification).where(
        BreachNotification.status.notin_(["notified", "dismissed"])
    )
    breaches = (await session.execute(stmt)).scalars().all()
    fired: dict[str, list[str]] = {}

    for b in breaches:
        sla = BreachNotificationService.check_sla_compliance(b.detected_at)
        new = due_sla_alerts(
            sla.hours_remaining, sla.is_overdue, b.sla_alerts_sent, thresholds
        )
        if not new:
            continue
        if send:
            for label in new:
                try:
                    suffix = (
                        " (OVERDUE)"
                        if label == "overdue"
                        else f" (ambang {label} jam)"
                    )
                    msg = (
                        f"⏰ <b>SLA Pasal 46</b> — {b.breach_title}\n"
                        f"Sisa: {sla.hours_remaining} jam{suffix}"
                    )
                    await BreachNotificationService.send_telegram_notification(msg)
                except Exception:
                    logger.exception("SLA reminder telegram failed (non-fatal)")
        b.sla_alerts_sent = [*b.sla_alerts_sent, *new]
        if sla.is_overdue and b.status != "overdue":
            b.status = "overdue"
        fired[b.id] = new

    if fired:
        await session.commit()
    return fired


async def _tick() -> None:
    thresholds = get_settings().sla_alert_thresholds
    async with get_sessionmaker()() as session:
        await process_breach_alerts(session, thresholds, send=True)


async def run_sla_monitor(stop_event: asyncio.Event) -> None:
    """Loop pemantau SLA. Berhenti rapi saat stop_event di-set."""
    interval = get_settings().sla_monitor_interval_seconds
    logger.info("SLA monitor started (interval=%ss)", interval)
    while not stop_event.is_set():
        try:
            await _tick()
        except Exception:
            logger.exception("SLA monitor tick failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
    logger.info("SLA monitor stopped")
