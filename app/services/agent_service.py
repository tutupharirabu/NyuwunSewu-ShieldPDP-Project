"""Agent session management service with real-time logging and Telegram notifications."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

import aiohttp
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import AgentSession, Finding

logger = logging.getLogger(__name__)


async def create_agent_session(
    session: AsyncSession,
    target_url: str,
    scan_id: str | None = None,
    agent_name: str = "phantom",
    organization_id: str | None = None,
) -> AgentSession:
    """Create a new agent exploration session."""
    agent_session = AgentSession(
        organization_id=organization_id,
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
    
    # Reassign a NEW list rather than appending in place: ``logs`` is a plain
    # JSON column without mutation tracking, so an in-place ``.append()`` is not
    # flagged dirty and is silently dropped on commit (only the first log, which
    # replaced an empty list, ever persisted). Same gotcha guarded in
    # scan_service._dispatch_webhooks.
    agent_session.logs = [*(agent_session.logs or []), log_entry]

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
    
    # Derive the real count from the findings table rather than trusting the
    # caller's value: agents routinely call complete without a count (the
    # endpoint default is 0), which used to overwrite the session to 0 even
    # when findings were submitted. Fall back to the supplied value only when
    # the scan has no agent findings yet.
    counts = await agent_finding_counts(session, [agent_session.scan_id])
    real_count = counts.get(agent_session.scan_id, findings_count)

    agent_session.status = "completed"
    agent_session.findings_count = real_count
    agent_session.completed_at = datetime.now(timezone.utc)

    await session.commit()
    await session.refresh(agent_session)

    await log_to_telegram(
        f"✅ Agent session completed: {session_id[:8]}\n"
        f"Findings submitted: {real_count}\n"
        f"Target: {agent_session.target_url}"
    )
    
    return agent_session


# Keeps references to in-flight notification tasks so they are not garbage
# collected before completing (asyncio holds only weak refs to tasks).
_telegram_tasks: set[asyncio.Task] = set()


async def log_to_telegram(message: str) -> None:
    """Schedule a fire-and-forget Telegram notification.

    Detached as a background task so request handlers (agent ingest / log /
    complete) return immediately instead of blocking on Telegram's network
    round-trip (up to the 10s client timeout). Delivery is best-effort.
    """
    settings = get_settings()
    telegram_token = getattr(settings, "telegram_bot_token", None)
    telegram_chat_id = getattr(settings, "telegram_chat_id", None)

    if not telegram_token or not telegram_chat_id:
        logger.debug("Telegram not configured, skipping log")
        return

    task = asyncio.create_task(
        _deliver_telegram(telegram_token, telegram_chat_id, message)
    )
    _telegram_tasks.add(task)
    task.add_done_callback(_telegram_tasks.discard)


async def _deliver_telegram(token: str, chat_id: str, message: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
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
    """Find the most recent agent session whose ID starts with ``prefix``."""
    prefix = prefix.lower()
    # Escape LIKE wildcards so a stray % or _ in the prefix can't broaden the
    # match, then push the prefix filter into SQL instead of scanning rows.
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    result = await session.execute(
        select(AgentSession)
        .where(func.lower(AgentSession.id).like(f"{escaped}%", escape="\\"))
        .order_by(AgentSession.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


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


async def agent_finding_counts(
    session: AsyncSession,
    scan_ids: list[str | None],
) -> dict[str, int]:
    """Map scan_id -> number of agent-submitted findings for that scan.

    The session's findings_count is derived from the findings table at read
    time (single source of truth) rather than a manually-reported column that
    can drift or be overwritten to 0. Only agent-sourced findings are counted
    (``evidence_summary.source == "agent"``), so the platform's own scanner
    findings never inflate an agent session's count.
    """
    ids = [scan_id for scan_id in scan_ids if scan_id]
    if not ids:
        return {}
    result = await session.execute(
        select(Finding.scan_id, func.count(Finding.id))
        .where(
            Finding.scan_id.in_(ids),
            Finding.evidence_summary["source"].as_string() == "agent",
        )
        .group_by(Finding.scan_id)
    )
    return {scan_id: count for scan_id, count in result.all()}


async def find_session_for_scan(
    session: AsyncSession,
    scan_id: str | None,
    agent_name: str = "phantom",
) -> AgentSession | None:
    """Return the most recent agent session for a scan + agent, if any."""
    if not scan_id:
        return None
    result = await session.execute(
        select(AgentSession)
        .where(
            AgentSession.scan_id == scan_id,
            AgentSession.agent_name == agent_name,
        )
        .order_by(AgentSession.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()
