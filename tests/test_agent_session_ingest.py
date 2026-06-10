"""Regression tests for the agent-auth AgentSession ingest pipeline.

Covers three bugs/risks that affected the Phantom pipeline:
1. Sessions created via the agent-auth ``/agent-sessions/ingest`` endpoint had
   ``organization_id=None`` and were therefore invisible to the operator's
   org-scoped ``GET /agent-sessions`` query (the frontend AgentSessionsPage).
2. ``POST /agent-sessions/{id}/ingest-log`` 422'd because ``AgentLogSubmit``
   required ``session_id`` in the body, while the agent only sends it in the
   URL path.
3. The org for an ingested session must be resolved STRICTLY from the scan —
   never from an arbitrary ``Organization.limit(1)`` fallback, which would be a
   cross-tenant IDOR given the single shared agent secret.
"""

import asyncio
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import get_settings
from app.database.session import AsyncSessionLocal
from app.main import app
from app.models import Policy, Project, Scan, Target, User

AGENT_HEADERS = {"X-Agent-Secret": get_settings().agent_secret}
LOGIN_BODY = {
    "email": "admin@nyuwunsewu.local",
    "password": "ChangeMe123!",
    "organization_slug": "default-organization",
}


async def _seed_scan() -> str:
    """Create a minimal real Scan and return its id.

    The project name is suffixed with a unique token so multiple tests can each
    seed their own scan without tripping the (organization_id, name) uniqueness
    constraint on projects.
    """
    suffix = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        admin = (
            await session.execute(
                select(User).where(User.email == "admin@nyuwunsewu.local")
            )
        ).scalar_one()
        project = Project(
            organization_id=admin.organization_id,
            owner_id=admin.id,
            name=f"Agent Session Regression {suffix}",
        )
        session.add(project)
        await session.flush()
        policy = Policy(
            organization_id=admin.organization_id,
            project_id=project.id,
            name=f"Agent Session Policy {suffix}",
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
        return scan.id


def test_agent_ingested_session_is_visible_to_operator_and_accepts_logs():
    with TestClient(app) as client:
        # Seed inside the client context so the startup lifespan has
        # bootstrapped the admin user / default organization.
        scan_id = asyncio.run(_seed_scan())

        # Agent (no user auth) creates a session via the ingest endpoint.
        created = client.post(
            "/agent-sessions/ingest",
            headers=AGENT_HEADERS,
            json={
                "scan_id": scan_id,
                "target_url": "https://lab.example",
                "agent_name": "phantom",
                "status": "idle",
                "message": "Scan completed, exploration pending.",
                "level": "info",
            },
        )
        assert created.status_code == 201, created.text
        session_id = created.json()["session_id"]

        # Operator logs in and lists sessions — the agent-created session MUST
        # appear (regression: it used to be orphaned with organization_id=None).
        login = client.post("/auth/login", json=LOGIN_BODY)
        headers = {"authorization": f"Bearer {login.json()['access_token']}"}
        listing = client.get("/agent-sessions", headers=headers)
        assert listing.status_code == 200, listing.text
        assert session_id in {s["id"] for s in listing.json()}

        # Agent pushes a log with NO session_id in the body (only in the path).
        # Regression: this used to 422 because session_id was required.
        log_resp = client.post(
            f"/agent-sessions/{session_id}/ingest-log",
            headers=AGENT_HEADERS,
            json={
                "level": "info",
                "message": "Completed IDOR check",
                "action": "idor_check",
            },
        )
        assert log_resp.status_code == 200, log_resp.text
        assert log_resp.json()["log_count"] >= 1


def test_action_phase_normalized_into_current_action():
    """The agent's action is stored as a canonical phase value so the UI shows
    a uniform label — whether sent as an explicit ``action_phase`` enum or as
    classifiable free text in ``current_action``."""
    with TestClient(app) as client:
        scan_id = asyncio.run(_seed_scan())
        login = client.post("/auth/login", json=LOGIN_BODY)
        headers = {"authorization": f"Bearer {login.json()['access_token']}"}

        # Explicit enum is kept verbatim.
        created = client.post(
            "/agent-sessions/ingest",
            headers=AGENT_HEADERS,
            json={
                "scan_id": scan_id,
                "target_url": "https://lab.example",
                "agent_name": "phantom",
                "status": "exploring",
                "action_phase": "testing_idor",
                "message": "Replaying requests with swapped account IDs",
                "level": "info",
            },
        )
        assert created.status_code == 201, created.text
        session_id = created.json()["session_id"]
        detail = client.get(f"/agent-sessions/{session_id}", headers=headers)
        assert detail.json()["current_action"] == "testing_idor"

        # Free text with no explicit phase is keyword-normalized.
        client.post(
            "/agent-sessions/ingest",
            headers=AGENT_HEADERS,
            json={
                "scan_id": scan_id,
                "target_url": "https://lab.example",
                "agent_name": "phantom",
                "current_action": "Registering userA and userB test accounts",
            },
        )
        detail = client.get(f"/agent-sessions/{session_id}", headers=headers)
        assert detail.json()["current_action"] == "enumerating_accounts"


def test_policy_refusal_marks_session_refused():
    """A refusal — explicit status or free-text decline — halts the session with
    the dedicated ``refused`` status (not ``failed``), stamps completed_at, and
    records a warning the operator can read."""
    with TestClient(app) as client:
        scan_id = asyncio.run(_seed_scan())
        login = client.post("/auth/login", json=LOGIN_BODY)
        headers = {"authorization": f"Bearer {login.json()['access_token']}"}

        created = client.post(
            "/agent-sessions/ingest",
            headers=AGENT_HEADERS,
            json={
                "scan_id": scan_id,
                "target_url": "https://lab.example",
                "agent_name": "phantom",
                "status": "exploring",
                "action_phase": "recon",
            },
        )
        session_id = created.json()["session_id"]

        refusal = client.post(
            "/agent-sessions/ingest",
            headers=AGENT_HEADERS,
            json={
                "scan_id": scan_id,
                "target_url": "https://lab.example",
                "agent_name": "phantom",
                "status": "refused",
                "action_phase": "refused",
                "level": "warning",
                "message": "Declining to flood the login endpoint per non-offensive policy.",
            },
        )
        assert refusal.status_code == 201, refusal.text
        assert refusal.json()["status"] == "refused"

        detail = client.get(f"/agent-sessions/{session_id}", headers=headers).json()
        assert detail["status"] == "refused"
        assert detail["current_action"] == "refused"
        assert detail["completed_at"] is not None
        assert any(log["level"] == "warning" for log in detail["logs"])


def test_freetext_refusal_in_log_flips_status_to_refused():
    """Even without an explicit status, a strong refusal phrase pushed through
    the log channel flips the session to ``refused``."""
    with TestClient(app) as client:
        scan_id = asyncio.run(_seed_scan())
        login = client.post("/auth/login", json=LOGIN_BODY)
        headers = {"authorization": f"Bearer {login.json()['access_token']}"}

        created = client.post(
            "/agent-sessions/ingest",
            headers=AGENT_HEADERS,
            json={
                "scan_id": scan_id,
                "target_url": "https://lab.example",
                "agent_name": "phantom",
                "status": "exploring",
                "action_phase": "testing_auth",
            },
        )
        session_id = created.json()["session_id"]

        client.post(
            f"/agent-sessions/{session_id}/ingest-log",
            headers=AGENT_HEADERS,
            json={
                "level": "warning",
                "message": "I will not proceed with credential brute-forcing.",
            },
        )
        detail = client.get(f"/agent-sessions/{session_id}", headers=headers).json()
        assert detail["status"] == "refused"


def test_ingest_rejects_unresolvable_org_instead_of_arbitrary_fallback():
    """No scan_id / unknown scan_id must be rejected, never silently attached
    to an arbitrary organization (cross-tenant IDOR guard)."""
    with TestClient(app) as client:
        missing_scan = client.post(
            "/agent-sessions/ingest",
            headers=AGENT_HEADERS,
            json={"target_url": "https://lab.example", "agent_name": "phantom"},
        )
        assert missing_scan.status_code == 400, missing_scan.text

        unknown_scan = client.post(
            "/agent-sessions/ingest",
            headers=AGENT_HEADERS,
            json={
                "scan_id": "does-not-exist-1234",
                "target_url": "https://lab.example",
                "agent_name": "phantom",
            },
        )
        assert unknown_scan.status_code == 404, unknown_scan.text
