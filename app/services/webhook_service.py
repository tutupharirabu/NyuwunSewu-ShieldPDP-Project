"""Webhook dispatch service for scan lifecycle events."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

import aiohttp

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def sign_payload(payload: str, secret: str) -> str:
    """HMAC-SHA256 signature for webhook payload."""
    return hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


async def dispatch_webhook(
    url: str,
    event: str,
    data: dict[str, Any],
    secret: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> int:
    """Send a webhook payload and return the HTTP status code."""
    payload = json.dumps(data, default=str)
    headers = {
        "content-type": "application/json",
        "user-agent": f"{get_settings().app_name}-Webhook/1.0",
        "x-nyuwunsewu-event": event,
    }
    if secret:
        headers["x-nyuwunsewu-signature"] = f"sha256={sign_payload(payload, secret)}"
    if extra_headers:
        headers.update(extra_headers)

    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, headers=headers, data=payload) as resp:
                return resp.status
    except aiohttp.ClientError as exc:
        logger.warning("Webhook delivery failed for %s: %s", url, exc)
        return 0
    except Exception as exc:
        logger.error("Unexpected webhook error for %s: %s", url, exc)
        return 0
