"""Agent session management service with real-time logging and Telegram notifications."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

import aiohttp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import AgentSession

logger = logging.getLogger(__name__)


async def create_agent_session(
    session: AsyncSession,
    target_url: str,
    scan_id: str | None = None,
    agent_name: str = "phantom",
) -> AgentSession:
    """Create a new agent exploration session."""
    agent_session = AgentSession(
        scan_id=scan_id,
        target_url=target_url,
        agent_name=agent_name,
        status="idle",
        logs=[],
        findings_count=0,
        started_at=datetime.now(timezone.utc),
    )
    session.add(agent_session)
    await session.commit()
    await session.refresh(agent_session)
    
    await log_to_telegram(
        f"🤖 Agent session started: {agent_session.id[:8]}\n"
        f"Target: {target_url}\n"
        f"Agent: {agent_name}"
    )
    
    return agent_session


async def update_agent_session(
    session: AsyncSession,
    session_id: str,
    **kwargs: Any,
) -> AgentSession | None:
    """Update agent session fields."""
    result = await session.execute(
        select(AgentSession).where(AgentSession.id == session_id)
    )
    agent_session = result.scalar_one_or_none()
    if agent_session is None:
        return None
    
    for field, value in kwargs.items():
        if hasattr(agent_session, field):
            setattr(agent_session, field, value)
    
    await session.commit()
    await session.refresh(agent_session)
    return agent_session


async def add_log_entry(
    session: AsyncSession,
    session_id: str,
    level: str,
    message: str,
    action: str | None = None,
    details: dict | None = None,
) -> AgentSession | None:
    """Add a log entry to the agent session."""
    result = await session.execute(
        select(AgentSession).where(AgentSession.id == session_id)
    )
    agent_session = result.scalar_one_or_none()
    if agent_session is None:
        return None
    
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
        "action": action,
        "details": details or {},
    }
    
    agent_session.logs = agent_session.logs or []
    agent_session.logs.append(log_entry)
    
    if action:
        agent_session.current_action = action
    
    await session.commit()
    await session.refresh(agent_session)
    
    # Send to Telegram for important logs
    if level in ("warning", "error", "success"):
        emoji = {"warning": "⚠️", "error": "❌", "success": "✅"}.get(level, "📝")
        await log_to_telegram(
            f"{emoji} [{level.upper()}] Session {session_id[:8]}\n"
            f"Action: {action or 'N/A'}\n"
            f"Message: {message}"
        )
    
    return agent_session


async def request_approval(
    session: AsyncSession,
    session_id: str,
    action: str,
    description: str,
    risk_level: str = "medium",
    request_data: dict | None = None,
) -> AgentSession | None:
    """Request user approval for a risky action."""
    result = await session.execute(
        select(AgentSession).where(AgentSession.id == session_id)
    )
    agent_session = result.scalar_one_or_none()
    if agent_session is None:
        return None
    
    agent_session.status = "pending_approval"
    agent_session.pending_action = {
        "action": action,
        "description": description,
        "risk_level": risk_level,
        "request": request_data or {},
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }
    
    await session.commit()
    await session.refresh(agent_session)
    
    # Send approval request to Telegram
    risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(risk_level, "⚪")
    await log_to_telegram(
        f"🔒 {risk_emoji} Approval Required\n"
        f"Session: {session_id[:8]}\n"
        f"Action: {action}\n"
        f"Risk: {risk_level}\n"
        f"Description: {description}\n"
        f"\nReply with 'approve {session_id[:8]}' or 'deny {session_id[:8]}'"
    )
    
    return agent_session


async def approve_action(
    session: AsyncSession,
    session_id: str,
    approved: bool,
    notes: str | None = None,
) -> AgentSession | None:
    """Approve or deny a pending action."""
    result = await session.execute(
        select(AgentSession).where(AgentSession.id == session_id)
    )
    agent_session = result.scalar_one_or_none()
    if agent_session is None:
        return None
    
    if approved:
        agent_session.status = "approved"
        await add_log_entry(session, session_id, "success", f"Action approved: {agent_session.pending_action.get('action', 'unknown')}")
    else:
        agent_session.status = "denied"
        await add_log_entry(session, session_id, "warning", f"Action denied: {agent_session.pending_action.get('action', 'unknown')}", details={"notes": notes})
    
    agent_session.pending_action = None
    await session.commit()
    await session.refresh(agent_session)
    return agent_session


async def complete_session(
    session: AsyncSession,
    session_id: str,
    findings_count: int = 0,
) -> AgentSession | None:
    """Mark agent session as completed."""
    result = await session.execute(
        select(AgentSession).where(AgentSession.id == session_id)
    )
    agent_session = result.scalar_one_or_none()
    if agent_session is None:
        return None
    
    agent_session.status = "completed"
    agent_session.findings_count = findings_count
    agent_session.completed_at = datetime.now(timezone.utc)
    
    await session.commit()
    await session.refresh(agent_session)
    
    await log_to_telegram(
        f"✅ Agent session completed: {session_id[:8]}\n"
        f"Findings submitted: {findings_count}\n"
        f"Target: {agent_session.target_url}"
    )
    
    return agent_session


async def log_to_telegram(message: str) -> None:
    """Send a log message to Telegram."""
    settings = get_settings()
    telegram_token = getattr(settings, "telegram_bot_token", None)
    telegram_chat_id = getattr(settings, "telegram_chat_id", None)

    if not telegram_token or not telegram_chat_id:
        logger.debug("Telegram not configured, skipping log")
        return

    url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
    payload = {
        "chat_id": telegram_chat_id,
        "text": message,
        "parse_mode": "HTML",
    }

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as http_session:
            async with http_session.post(url, json=payload) as resp:
                if resp.status != 200:
                    logger.warning(f"Telegram API error: {resp.status}")
    except Exception as e:
        logger.warning(f"Failed to send Telegram message: {e}")


async def find_session_by_prefix(
    session: AsyncSession,
    prefix: str,
) -> AgentSession | None:
    """Find an agent session by its ID prefix (first 8 chars)."""
    # Fetch all sessions and match by prefix
    result = await session.execute(
        select(AgentSession).order_by(AgentSession.created_at.desc()).limit(100)
    )
    sessions = result.scalars().all()
    for s in sessions:
        if s.id.lower().startswith(prefix.lower()):
            return s
    return None


async def list_active_sessions(
    session: AsyncSession,
) -> list[AgentSession]:
    """List all non-completed agent sessions."""
    result = await session.execute(
        select(AgentSession)
        .where(AgentSession.status.notin_(["completed", "failed"]))
        .order_by(AgentSession.created_at.desc())
    )
    return list(result.scalars().all())
