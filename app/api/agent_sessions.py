"""Agent session management API endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_ip, require_permission
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
