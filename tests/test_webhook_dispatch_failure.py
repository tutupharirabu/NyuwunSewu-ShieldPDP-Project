"""Regression test: webhook dispatch failures must be recorded, not swallowed.

Previously a down/misconfigured receiver caused the scan.completed delivery to
fail silently (no log, nothing persisted, and in-place stats mutation that the
plain-JSON column never tracked). A failed delivery must now show up in
``scan.stats['_webhook_errors']``.
"""

import asyncio

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database.session import AsyncSessionLocal
from app.main import app
from app.models import Policy, Project, Scan, Target, User, WebhookSubscription
from app.services.scan_service import ScanRunner


async def _seed_and_dispatch() -> dict:
    async with AsyncSessionLocal() as session:
        admin = (
            await session.execute(select(User).where(User.email == "admin@nyuwunsewu.local"))
        ).scalar_one()
        org_id = admin.organization_id
        project = Project(organization_id=org_id, owner_id=admin.id, name="Dispatch Test")
        session.add(project)
        await session.flush()
        policy = Policy(organization_id=org_id, project_id=project.id, name="Dispatch Policy")
        target = Target(
            organization_id=org_id, project_id=project.id, base_url="https://lab.example"
        )
        session.add_all([policy, target])
        await session.flush()
        scan = Scan(
            organization_id=org_id,
            project_id=project.id,
            target_id=target.id,
            policy_id=policy.id,
            started_by_id=admin.id,
            status="completed",
            stats={"findings": 0, "endpoints": 0},
        )
        # Subscription points at an unreachable port -> connection refused ->
        # dispatch_webhook returns 0 (a failed delivery).
        sub = WebhookSubscription(
            organization_id=org_id,
            name="dead-receiver",
            url="http://127.0.0.1:1/",
            secret="test-secret",
            events=["scan.completed", "scan.failed"],
            is_active=True,
        )
        session.add_all([scan, sub])
        await session.commit()

        runner = ScanRunner(session)
        await runner._dispatch_webhooks(scan, "scan.completed")
        await session.refresh(scan)
        await session.refresh(sub)
        return {
            "errors": (scan.stats or {}).get("_webhook_errors", []),
            "last_status": sub.last_delivery_status,
        }


def test_failed_webhook_delivery_is_recorded_on_scan():
    with TestClient(app):  # triggers startup bootstrap (admin/org/roles)
        result = asyncio.run(_seed_and_dispatch())
    assert result["errors"], "expected a recorded webhook delivery error"
    assert any("127.0.0.1:1" in e for e in result["errors"])
    # 0 == connection failure captured by dispatch_webhook.
    assert result["last_status"] == 0
