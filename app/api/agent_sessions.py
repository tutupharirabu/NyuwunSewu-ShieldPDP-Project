"""Agent session management API endpoints."""

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.config import get_settings
from app.core.rbac import Permission
from app.database.session import get_session
from app.models import AgentSession, User
from app.schemas.agent import (
    AgentApprovalRequest,
    AgentLogSubmit,
    AgentSessionCreate,
    AgentSessionResponse,
)
from app.services import agent_service

router = APIRouter(tags=["agent-sessions"])


# --- Agent-auth helpers (mirrors findings ingest pattern) ---


def _verify_agent_auth(x_agent_secret: str | None) -> bool:
    """Verify the agent's shared secret for session management."""
    if not x_agent_secret:
        return False
    settings = get_settings()
    agent_secret = getattr(settings, "agent_secret", None)
    if agent_secret and hmac.compare_digest(x_agent_secret, agent_secret):
        return True
    return hmac.compare_digest(x_agent_secret, settings.secret_key)


class AgentSessionIngest(BaseModel):
    """Session create/update submitted by an external agent."""

    scan_id: str | None = None
    target_url: str
    agent_name: str = "phantom"
    status: str | None = None
    current_action: str | None = None
    message: str | None = None
    level: str = "info"
    action: str | None = None


class AgentSessionIngestResponse(BaseModel):
    session_id: str
    status: str
    message: str


@router.get("/agent-sessions", response_model=list[AgentSessionResponse])
async def list_agent_sessions(
    scan_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> list[AgentSession]:
    """List all agent sessions."""
    query = select(AgentSession).where(
        AgentSession.organization_id == user.organization_id
    )
    if scan_id:
        query = query.where(AgentSession.scan_id == scan_id)
    if status:
        query = query.where(AgentSession.status == status)

    query = query.order_by(AgentSession.created_at.desc()).limit(limit)
    result = await session.execute(query)
    return list(result.scalars().all())


@router.get("/agent-sessions/{session_id}", response_model=AgentSessionResponse)
async def get_agent_session(
    session_id: str,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> AgentSession:
    """Get a specific agent session."""
    result = await session.execute(
        select(AgentSession).where(
            AgentSession.id == session_id,
            AgentSession.organization_id == user.organization_id,
        )
    )
    agent_session = result.scalar_one_or_none()
    if agent_session is None:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return agent_session


@router.post(
    "/agent-sessions",
    response_model=AgentSessionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_agent_session(
    payload: AgentSessionCreate,
    user: User = Depends(require_permission(Permission.SCAN_CREATE)),
    session: AsyncSession = Depends(get_session),
) -> AgentSession:
    """Create a new agent exploration session."""
    return await agent_service.create_agent_session(
        session,
        target_url=payload.target_url,
        scan_id=payload.scan_id,
        agent_name=payload.agent_name,
        organization_id=user.organization_id,
    )


@router.post("/agent-sessions/{session_id}/log")
async def add_agent_log(
    session_id: str,
    payload: AgentLogSubmit,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Add a log entry to an agent session."""
    result = await agent_service.add_log_entry(
        session,
        session_id=session_id,
        level=payload.level,
        message=payload.message,
        action=payload.action,
        details=payload.details,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return {"status": "ok", "log_count": len(result.logs)}


@router.post("/agent-sessions/{session_id}/request-approval")
async def request_action_approval(
    session_id: str,
    payload: AgentApprovalRequest,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Request user approval for a risky action."""
    result = await agent_service.request_approval(
        session,
        session_id=session_id,
        action=payload.action,
        description=payload.description,
        risk_level=payload.risk_level,
        request_data=payload.request,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return {"status": "pending_approval", "action": payload.action}


@router.post("/agent-sessions/{session_id}/approve")
async def approve_pending_action(
    session_id: str,
    payload: AgentApprovalRequest,
    user: User = Depends(require_permission(Permission.SCAN_CREATE)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Approve or deny a pending action."""
    result = await agent_service.approve_action(
        session,
        session_id=session_id,
        approved=payload.approved,
        notes=payload.notes,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return {"status": "approved" if payload.approved else "denied"}


@router.post("/agent-sessions/{session_id}/complete")
async def complete_agent_session(
    session_id: str,
    findings_count: int = 0,
    user: User = Depends(require_permission(Permission.SCAN_CREATE)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Mark agent session as completed."""
    result = await agent_service.complete_session(
        session,
        session_id=session_id,
        findings_count=findings_count,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return {"status": "completed", "findings_count": findings_count}


# --- Agent-auth endpoints (no user auth, uses X-Agent-Secret) ---


@router.post(
    "/agent-sessions/ingest",
    response_model=AgentSessionIngestResponse,
    status_code=status.HTTP_201_CREATED,
)
async def ingest_agent_session(
    payload: AgentSessionIngest,
    x_agent_secret: str | None = Header(None),
    session: AsyncSession = Depends(get_session),
) -> AgentSessionIngestResponse:
    """Create or update an agent session from an external agent.

    Authenticated via ``X-Agent-Secret`` header (same secret as findings ingest).
    The receiver calls this to create a session when a scan completes.
    The agent calls this to update status/logs during exploration.
    """
    if not _verify_agent_auth(x_agent_secret):
        raise HTTPException(status_code=401, detail="Invalid agent secret")

    # Look for an existing session for this scan_id + agent_name
    existing_result = await session.execute(
        select(AgentSession).where(
            AgentSession.scan_id == payload.scan_id,
            AgentSession.agent_name == payload.agent_name,
        )
    )
    existing = existing_result.scalar_one_or_none()

    if existing:
        # Update existing session
        if payload.status:
            existing.status = payload.status
        if payload.current_action:
            existing.current_action = payload.current_action

        # Add log entry if message provided
        if payload.message:
            await agent_service.add_log_entry(
                session,
                session_id=existing.id,
                level=payload.level,
                message=payload.message,
                action=payload.action,
            )

        await session.commit()
        await session.refresh(existing)

        return AgentSessionIngestResponse(
            session_id=existing.id,
            status=existing.status,
            message="Session updated",
        )
    else:
        # Resolve the owning organization STRICTLY from the scan so the session
        # is scoped to the correct tenant and visible to that operator in the
        # UI. We deliberately do NOT fall back to an arbitrary organization
        # (e.g. Organization.limit(1)): the agent secret is a single shared
        # secret, so attaching to a "default" org would let an agent write
        # sessions into another tenant's view (cross-tenant IDOR).
        if not payload.scan_id:
            raise HTTPException(
                status_code=400,
                detail="scan_id is required to resolve the owning organization",
            )

        from app.models import Scan

        scan_result = await session.execute(
            select(Scan).where(Scan.id == payload.scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(
                status_code=404, detail=f"Scan {payload.scan_id} not found"
            )

        # Create new session, scoped to the scan's organization.
        new_session = await agent_service.create_agent_session(
            session,
            target_url=payload.target_url,
            scan_id=payload.scan_id,
            agent_name=payload.agent_name,
            organization_id=scan.organization_id,
        )

        # Set initial status if provided
        if payload.status:
            new_session.status = payload.status
            await session.commit()
            await session.refresh(new_session)

        # Add initial log entry if message provided
        if payload.message:
            await agent_service.add_log_entry(
                session,
                session_id=new_session.id,
                level=payload.level,
                message=payload.message,
                action=payload.action,
            )

        return AgentSessionIngestResponse(
            session_id=new_session.id,
            status=new_session.status,
            message="Session created",
        )


@router.post("/agent-sessions/{session_id}/ingest-log")
async def ingest_agent_log(
    session_id: str,
    payload: AgentLogSubmit,
    x_agent_secret: str | None = Header(None),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Add a log entry to an agent session (agent-auth version).

    The agent calls this to push logs during exploration without user auth.
    """
    if not _verify_agent_auth(x_agent_secret):
        raise HTTPException(status_code=401, detail="Invalid agent secret")

    result = await agent_service.add_log_entry(
        session,
        session_id=session_id,
        level=payload.level,
        message=payload.message,
        action=payload.action,
        details=payload.details,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return {"status": "ok", "log_count": len(result.logs)}


@router.post("/agent-sessions/{session_id}/ingest-complete")
async def ingest_session_complete(
    session_id: str,
    findings_count: int = 0,
    x_agent_secret: str | None = Header(None),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Mark an agent session as completed (agent-auth version)."""
    if not _verify_agent_auth(x_agent_secret):
        raise HTTPException(status_code=401, detail="Invalid agent secret")

    result = await agent_service.complete_session(
        session,
        session_id=session_id,
        findings_count=findings_count,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return {"status": "completed", "findings_count": findings_count}
