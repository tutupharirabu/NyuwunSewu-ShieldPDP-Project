"""Telegram webhook handler for inbound commands (approve/deny agent actions)."""
import logging
from fastapi import APIRouter, Request

from app.core.config import get_settings
from app.database.session import get_session
from app.services import agent_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["telegram"])


@router.post("/telegram/webhook")
async def telegram_webhook(request: Request) -> dict:
    """Handle incoming Telegram messages.
    
    Supports commands:
      - approve <session_prefix> [notes...]
      - deny <session_prefix> [notes...]
      - status
    """
    try:
        body = await request.json()
    except Exception:
        return {"ok": False, "error": "invalid json"}

    # Extract message
    message = body.get("message", body.get("edited_message", {}))
    chat_id = message.get("chat", {}).get("id")
    text = (message.get("text") or "").strip()
    msg_id = message.get("message_id")

    if not text:
        return {"ok": True, "info": "no text"}

    # Verify chat is authorized
    settings = get_settings()
    allowed_chat = str(getattr(settings, "telegram_chat_id", ""))
    if allowed_chat and str(chat_id) != allowed_chat:
        logger.warning(f"Unauthorized telegram chat: {chat_id}")
        return {"ok": False, "error": "unauthorized"}

    # Parse commands
    parts = text.split()
    command = parts[0].lower() if parts else ""

    if command in ("approve", "deny") and len(parts) >= 2:
        session_prefix = parts[1].lower()
        notes = " ".join(parts[2:]) if len(parts) > 2 else None
        approved = command == "approve"

        # Find matching session by prefix
        async for session in get_session():
            result = await agent_service.find_session_by_prefix(session, session_prefix)
            if result is None:
                # Reply: session not found
                await _send_telegram_message(
                    f"❌ Session `{session_prefix}` not found.\n"
                    f"Use: {command} <session_id_prefix> [notes]",
                    chat_id=chat_id,
                )
                return {"ok": True, "action": "not_found"}

            approval_result = await agent_service.approve_action(
                session, result.id, approved=approved, notes=notes
            )
            if approval_result:
                status_emoji = "✅ Approved" if approved else "❌ Denied"
                action_name = approval_result.pending_action.get("action", "unknown") if approval_result.pending_action else "N/A"
                await _send_telegram_message(
                    f"{status_emoji}\n"
                    f"Session: {result.id[:8]}\n"
                    f"Action: {action_name}\n"
                    f"Notes: {notes or '(none)'}",
                    chat_id=chat_id,
                )
            break

        return {"ok": True, "action": command, "session_prefix": session_prefix}

    elif command == "status":
        # List active sessions
        async for session in get_session():
            sessions = await agent_service.list_active_sessions(session)
            if sessions:
                lines = [f"🤖 Active Sessions ({len(sessions)}):"]
                for s in sessions:
                    status_emoji = {"exploring": "🔍", "pending_approval": "🔒", "idle": "⏳"}.get(s.status, "📋")
                    lines.append(f"  {status_emoji} {s.id[:8]} — {s.status} — {s.target_url[:50]}")
                await _send_telegram_message("\n".join(lines), chat_id=chat_id)
            else:
                await _send_telegram_message("📋 No active agent sessions.", chat_id=chat_id)
            break

        return {"ok": True, "action": "status"}

    return {"ok": True, "info": "no matching command"}


async def _send_telegram_message(text: str, chat_id: int) -> None:
    """Send a message back to Telegram."""
    import aiohttp

    settings = get_settings()
    token = getattr(settings, "telegram_bot_token", None)
    if not token:
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "MarkdownV2",
    }

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as http_session:
            async with http_session.post(url, json=payload) as resp:
                if resp.status != 200:
                    logger.warning(f"Telegram reply error: {resp.status}")
    except Exception as e:
        logger.warning(f"Failed to send Telegram reply: {e}")
