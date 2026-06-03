"""Regression tests for the agent-auth ``/findings/ingest`` endpoint.

The agent secret is a single shared secret across all tenants, so an ingest
request carries no trustworthy tenant identity. The owning organization MUST be
resolved STRICTLY from the referenced scan -- never from an arbitrary
``Organization.limit(1)`` fallback, which would let any holder of the shared
secret write findings into another tenant's view (cross-tenant IDOR). This is
the same guard already enforced for ``/agent-sessions/ingest`` (see
``test_agent_session_ingest.py``); these tests assert findings ingest matches.
"""

import asyncio

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import get_settings
from app.database.session import AsyncSessionLocal
from app.main import app
from app.models import Finding, Policy, Project, Scan, Target, User

AGENT_HEADERS = {"X-Agent-Secret": get_settings().secret_key}

FINDING_BODY = {
    "finding_type": "bola_idor",
    "title": "IDOR on account balance endpoint",
    "severity": "high",
    "confidence": 95.0,
    "description": "Account balances for other customers are retrievable.",
    "agent_name": "phantom",
}


async def _seed_scan() -> tuple[str, str]:
    """Create a minimal real Scan; return (scan_id, organization_id)."""
    async with AsyncSessionLocal() as session:
        admin = (
            await session.execute(
                select(User).where(User.email == "admin@nyuwunsewu.local")
            )
        ).scalar_one()
        project = Project(
            organization_id=admin.organization_id,
            owner_id=admin.id,
            name="Findings Ingest Regression",
        )
        session.add(project)
        await session.flush()
        policy = Policy(
            organization_id=admin.organization_id,
            project_id=project.id,
            name="Findings Ingest Policy",
        )
        target = Target(
            organization_id=admin.organization_id,
            project_id=project.id,
            base_url="https://lab.example",
        )
        session.add_all([policy, target])
        await session.flush()
        scan = Scan(
            organization_id=admin.organization_id,
            project_id=project.id,
            target_id=target.id,
            policy_id=policy.id,
            started_by_id=admin.id,
        )
        session.add(scan)
        await session.commit()
        return scan.id, admin.organization_id


def test_findings_ingest_requires_scan_id_to_resolve_org():
    """No scan_id must be rejected with 400, never silently attached to an
    arbitrary organization via the Organization.limit(1) fallback."""
    with TestClient(app) as client:
        resp = client.post(
            "/findings/ingest",
            headers=AGENT_HEADERS,
            json={**FINDING_BODY, "target_url": "https://lab.example"},
        )
        assert resp.status_code == 400, resp.text
        assert "scan_id" in resp.json()["detail"]


def test_findings_ingest_rejects_unknown_scan():
    with TestClient(app) as client:
        resp = client.post(
            "/findings/ingest",
            headers=AGENT_HEADERS,
            json={**FINDING_BODY, "scan_id": "does-not-exist-1234"},
        )
        assert resp.status_code == 404, resp.text


def test_findings_ingest_scopes_finding_to_scan_org():
    with TestClient(app) as client:
        scan_id, org_id = asyncio.run(_seed_scan())
        resp = client.post(
            "/findings/ingest",
            headers=AGENT_HEADERS,
            json={**FINDING_BODY, "scan_id": scan_id},
        )
        assert resp.status_code == 201, resp.text
        finding_id = resp.json()["finding_id"]

        finding = asyncio.run(_load_finding(finding_id))
        assert finding is not None
        assert finding.scan_id == scan_id
        assert finding.organization_id == org_id


async def _load_finding(finding_id: str) -> Finding | None:
    async with AsyncSessionLocal() as session:
        return (
            await session.execute(select(Finding).where(Finding.id == finding_id))
        ).scalar_one_or_none()
