import re
from typing import Any

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[a-z0-9._\-+/=]{12,}"),
    re.compile(r"(?i)(api[_-]?key[\"'\s:=]+)[a-z0-9._\-]{12,}"),
    re.compile(r"(?i)(access[_-]?token[\"'\s:=]+)[a-z0-9._\-]{12,}"),
    re.compile(r"eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}"),
]


def redact_text(value: str, max_length: int = 4000) -> str:
    redacted = value[:max_length]
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: (match.group(1) if match.groups() else "") + "[REDACTED]", redacted)
    return redacted


def redact_headers(headers: dict[str, Any] | None) -> dict[str, Any]:
    if not headers:
        return {}
    safe: dict[str, Any] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADER_NAMES:
            safe[key] = "[REDACTED]"
        else:
            safe[key] = redact_text(str(value), max_length=512)
    return safe


def sanitize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(k): ("[REDACTED]" if str(k).lower() in SENSITIVE_HEADER_NAMES else sanitize_json(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [sanitize_json(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value

