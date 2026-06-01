from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from urllib.parse import urljoin

import aiohttp

from app.recon import CrawledEndpoint
from app.services.policy_engine import PolicyEngine
from app.services.scope_guard import ScopeGuard
from app.utils.rate_limiter import AdaptiveRateLimiter
from app.validation.types import HttpObservation, ValidationResult


class UsernameEnumerationValidator:
    """Bounded login-response differential check using no valid password attempts."""

    LOGIN_PATH_RE = re.compile(r"(?i)/(?:login|signin|sign-in|session)/?$")
    FETCH_ACTION_RE = re.compile(r"""fetch\s*\(\s*["']([^"']+)["']""", re.I)
    INVALID_PASSWORD = "ShieldPDP_Invalid_Probe_Only!"

    def __init__(
        self,
        policy: PolicyEngine,
        scope_guard: ScopeGuard,
        rate_limiter: AdaptiveRateLimiter,
    ) -> None:
        self.policy = policy
        self.scope_guard = scope_guard
        self.rate_limiter = rate_limiter

    async def validate(
        self,
        endpoint: CrawledEndpoint,
        session: aiohttp.ClientSession,
        known_username: str | None,
    ) -> ValidationResult | None:
        if not self.policy.is_validation_allowed("auth") or not known_username:
            return None
        if not self.LOGIN_PATH_RE.search(endpoint.normalized_path):
            return None
        action = self._json_login_action(endpoint)
        if not action or not await self.scope_guard.is_url_allowed(action):
            return None

        control_username = f"shieldpdp_nonexistent_{uuid.uuid4().hex[:12]}"
        known_observations: list[HttpObservation] = []
        control_observations: list[HttpObservation] = []
        for _ in range(2):
            known = await self._post_invalid_login(session, action, known_username)
            control = await self._post_invalid_login(session, action, control_username)
            if known and control:
                known_observations.append(known)
                control_observations.append(control)

        if len(known_observations) != 2 or len(control_observations) != 2:
            return None
        known_fingerprints = {self._fingerprint(item) for item in known_observations}
        control_fingerprints = {self._fingerprint(item) for item in control_observations}
        if len(known_fingerprints) != 1 or len(control_fingerprints) != 1:
            return None
        if known_fingerprints == control_fingerprints:
            return None

        proof = known_observations[-1]
        return ValidationResult(
            finding_type="authentication_username_enumeration",
            title="Username Enumeration Through Authentication Response",
            severity="medium",
            confidence=91.0,
            endpoint=endpoint.url,
            description=(
                "A known assessment identity and a generated non-existent control produced "
                "stable, distinguishable authentication failure responses."
            ),
            reasoning=[
                "Only intentionally invalid passwords were submitted",
                "The known identity failure response was stable across two requests",
                "The generated control identity produced a distinct stable response fingerprint",
            ],
            evidence={
                "validation_mode": "bounded_invalid_password_response_comparison",
                "known_identity_source": "operator_supplied_scan_identity",
                "control_identity": "generated_nonexistent_control",
                "known_status": proof.status_code,
                "control_status": control_observations[-1].status_code,
                "payload": None,
            },
            remediation=(
                "Return identical status codes and generic response bodies for invalid username "
                "and invalid password conditions, with rate limiting and monitoring."
            ),
            request_method="POST",
            request_url=action,
            request_headers=proof.request_headers,
            request_body=json.dumps(
                {"username": "[OPERATOR-SUPPLIED-IDENTITY]", "password": "[INVALID-PROBE]"}
            ),
            response_status=proof.status_code,
            response_headers=proof.headers,
            response_body=proof.body_sample.replace(known_username, "[OPERATOR-SUPPLIED-IDENTITY]"),
            http_version=proof.http_version,
            response_reason=proof.response_reason,
        )

    def _json_login_action(self, endpoint: CrawledEndpoint) -> str | None:
        text = endpoint.response_body_sample
        lowered = text.lower()
        if "json.stringify" not in lowered or "application/json" not in lowered:
            return None
        match = self.FETCH_ACTION_RE.search(text)
        return urljoin(endpoint.url, match.group(1)) if match else None

    async def _post_invalid_login(
        self,
        session: aiohttp.ClientSession,
        url: str,
        username: str,
    ) -> HttpObservation | None:
        try:
            await self.rate_limiter.wait()
            started = time.perf_counter()
            async with session.post(
                url,
                json={"username": username, "password": self.INVALID_PASSWORD},
                allow_redirects=True,
            ) as response:
                body = await response.text(errors="replace")
                return HttpObservation(
                    url=str(response.url),
                    method="POST",
                    status_code=response.status,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body_sample=body[:12000],
                    content_length=len(body),
                    request_headers={
                        key.lower(): value for key, value in response.request_info.headers.items()
                    },
                    http_version=f"HTTP/{response.version.major}.{response.version.minor}",
                    response_reason=response.reason or "",
                )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            self.rate_limiter.record_anomaly()
            return None

    @staticmethod
    def _fingerprint(observation: HttpObservation) -> str:
        try:
            payload = json.loads(observation.body_sample)
        except json.JSONDecodeError:
            return f"{observation.status_code}:{observation.body_sample[:300]}"
        if isinstance(payload, dict):
            stable = {
                key: payload.get(key)
                for key in ("status", "message", "error", "code")
                if key in payload
            }
            return f"{observation.status_code}:{json.dumps(stable, sort_keys=True)}"
        return f"{observation.status_code}:{type(payload).__name__}"
