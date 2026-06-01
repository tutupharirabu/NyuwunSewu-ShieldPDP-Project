import shlex
from typing import Any

from app.core.security import stable_hash
from app.utils.redaction import redact_headers, redact_text, sanitize_json


class EvidenceEngine:
    def build(
        self,
        *,
        method: str,
        url: str,
        request_headers: dict[str, Any] | None,
        request_body: str | None,
        response_status: int | None,
        response_headers: dict[str, Any] | None,
        response_body: str | None,
        steps: list[str],
        http_version: str = "HTTP/1.1",
        response_reason: str = "",
    ) -> dict[str, Any]:
        raw_request_full = {
            "method": method.upper(),
            "url": url,
            "http_version": http_version,
            "headers": request_headers or {},
            "body": request_body or "",
        }
        raw_response_full = {
            "status": response_status,
            "reason": response_reason,
            "http_version": http_version,
            "headers": response_headers or {},
            "body_sample": response_body or "",
        }
        safe_request = {
            "method": method.upper(),
            "url": url,
            "http_version": http_version,
            "headers": redact_headers(request_headers),
            "body": redact_text(request_body or "", max_length=12000),
        }
        safe_response = {
            "status": response_status,
            "reason": response_reason,
            "http_version": http_version,
            "headers": redact_headers(response_headers),
            "body_sample": redact_text(response_body or "", max_length=4000),
        }
        evidence_hash = stable_hash(
            {"request": safe_request, "response": safe_response, "steps": steps}
        )
        immutable_id = "evd_" + evidence_hash[:32]
        curl = self._curl(method, url, request_headers or {}, request_body)
        return {
            "immutable_id": immutable_id,
            "raw_request": sanitize_json(safe_request),
            "raw_response": sanitize_json(safe_response),
            "headers": redact_headers(response_headers),
            "reproduction_steps": steps,
            "curl_reproduction": curl,
            "evidence_hash": evidence_hash,
            "raw_request_full": raw_request_full,
            "raw_response_full": raw_response_full,
        }

    def _curl(
        self, method: str, url: str, headers: dict[str, Any], body: str | None
    ) -> str:
        parts = ["curl", "-i", "-X", shlex.quote(method.upper())]
        for key, value in redact_headers(headers).items():
            parts.extend(["-H", shlex.quote(f"{key}: {value}")])
        if body:
            parts.extend(["--data", shlex.quote(redact_text(body, max_length=12000))])
        parts.append(shlex.quote(url))
        return " ".join(parts)
