import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, status

from app.core.config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 390_000)
    return (
        base64.urlsafe_b64encode(salt).decode()
        + "$"
        + base64.urlsafe_b64encode(digest).decode()
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt_b64, digest_b64 = password_hash.split("$", 1)
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 390_000)
    return hmac.compare_digest(actual, expected)


def _b64_json(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64_json(data: str) -> dict[str, Any]:
    padded = data + "=" * (-len(data) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode()))


def create_access_token(
    subject: str,
    organization_id: str | None,
    role: str,
    extra: dict[str, Any] | None = None,
) -> str:
    settings = get_settings()
    now = utcnow()
    payload = {
        "sub": subject,
        "org": organization_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_ttl_minutes)).timestamp()),
    }
    if extra:
        payload.update(extra)
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_b64_json(header)}.{_b64_json(payload)}"
    signature = hmac.new(
        settings.secret_key.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return signing_input + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
        signing_input = f"{header_b64}.{payload_b64}"
        expected = hmac.new(
            settings.secret_key.encode(), signing_input.encode(), hashlib.sha256
        ).digest()
        actual = base64.urlsafe_b64decode(
            (signature_b64 + "=" * (-len(signature_b64) % 4)).encode()
        )
        if not hmac.compare_digest(expected, actual):
            raise ValueError("invalid signature")
        header = _unb64_json(header_b64)
        payload = _unb64_json(payload_b64)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
        ) from exc

    if header.get("alg") != "HS256":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unsupported token algorithm",
        )
    if int(payload.get("exp", 0)) < int(utcnow().timestamp()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token expired",
        )
    return payload


def stable_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()

