"""Tests for the breach SLA monitor (Pasal 46, 3x24 jam)."""

import asyncio
from datetime import datetime, timedelta, timezone

from app.database.session import get_sessionmaker
from app.models.agent import BreachNotification
from app.services.sla_monitor import due_sla_alerts, process_breach_alerts

THRESHOLDS = [48, 24, 6, 1]


def _run(coro):
    return asyncio.run(coro)


class TestDueSlaAlerts:
    def test_no_alert_when_far_from_deadline(self):
        assert due_sla_alerts(60.0, False, [], THRESHOLDS) == []

    def test_fires_48_threshold(self):
        assert due_sla_alerts(47.0, False, [], THRESHOLDS) == ["48"]

    def test_fires_multiple_uncrossed_at_once(self):
        # 5 jam tersisa → 48,24,6 terlewati sekaligus jika belum dikirim
        assert due_sla_alerts(5.0, False, [], THRESHOLDS) == ["48", "24", "6"]

    def test_respects_already_sent(self):
        assert due_sla_alerts(5.0, False, ["48", "24"], THRESHOLDS) == ["6"]

    def test_overdue_once(self):
        assert due_sla_alerts(0.0, True, ["48", "24", "6", "1"], THRESHOLDS) == [
            "overdue"
        ]
        assert (
            due_sla_alerts(0.0, True, ["48", "24", "6", "1", "overdue"], THRESHOLDS)
            == []
        )


class TestProcessBreachAlerts:
    def test_marks_overdue_and_records_alert(self):
        now = datetime.now(timezone.utc)

        async def _do():
            async with get_sessionmaker()() as session:
                breach = BreachNotification(
                    organization_id="org-sla",
                    finding_ids=["f1"],
                    breach_title="t",
                    description="d",
                    breach_type="x",
                    severity="high",
                    status="assessing",
                    detected_at=now - timedelta(hours=100),  # lewat 72 jam
                    sla_deadline=now - timedelta(hours=28),
                    sla_alerts_sent=[],
                )
                session.add(breach)
                await session.commit()
                await session.refresh(breach)

                fired = await process_breach_alerts(
                    session, [48, 24, 6, 1], send=False
                )
                await session.refresh(breach)
                return breach.status, breach.sla_alerts_sent, breach.id in fired

        status, alerts_sent, was_fired = _run(_do())
        assert status == "overdue"
        assert "overdue" in alerts_sent
        assert was_fired

    def test_skips_notified_and_dismissed(self):
        now = datetime.now(timezone.utc)

        async def _do():
            async with get_sessionmaker()() as session:
                notified = BreachNotification(
                    organization_id="org-sla2",
                    finding_ids=["f2"],
                    breach_title="t2",
                    description="d",
                    breach_type="x",
                    severity="high",
                    status="notified",
                    detected_at=now - timedelta(hours=100),
                    sla_deadline=now - timedelta(hours=28),
                    sla_alerts_sent=[],
                )
                session.add(notified)
                await session.commit()
                await session.refresh(notified)
                fired = await process_breach_alerts(
                    session, [48, 24, 6, 1], send=False
                )
                return notified.id in fired

        assert _run(_do()) is False
