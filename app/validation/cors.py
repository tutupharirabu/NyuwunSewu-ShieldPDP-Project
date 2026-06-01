from __future__ import annotations

import asyncio
import re
import time

import aiohttp

from app.recon import CrawledEndpoint
from app.services.policy_engine import PolicyEngine
from app.services.scope_guard import ScopeGuard
from app.utils.rate_limiter import AdaptiveRateLimiter
from app.validation.types import HttpObservation, ValidationResult


class CorsValidationEngine:
    """Validates a discovered CORS test or cross-origin endpoint without credentials."""

    CORS_ROUTE_RE = re.compile(r"(?i)(?:^|/)(?:cors(?:-test)?|cross-origin)(?:/|$)")
    CONTROLLED_ORIGIN = "https://shieldpdp.invalid"

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
    ) -> ValidationResult | None:
        if not self.policy.is_validation_allowed("auth"):
            return None
        if not self.CORS_ROUTE_RE.search(endpoint.normalized_path):
            return None

        observation = await self._observe(session, endpoint.url)
        if observation is None:
            return None
        allow_origin = observation.headers.get("access-control-allow-origin", "")
        allow_credentials = observation.headers.get("access-control-allow-credentials", "").lower()
        if allow_origin != self.CONTROLLED_ORIGIN or allow_credentials != "true":
            return None

        return ValidationResult(
            finding_type="cors_credentials_misconfiguration",
            title="Credentialed CORS Reflects Arbitrary Origin",
            severity="high",
            confidence=96.0,
            endpoint=endpoint.url,
            description=(
                "The endpoint reflected an untrusted Origin value while explicitly permitting "
                "credentialed cross-origin requests."
            ),
            reasoning=[
                f"Controlled untrusted Origin was reflected: {self.CONTROLLED_ORIGIN}",
                "Access-Control-Allow-Credentials was enabled",
                "No authenticated cookie or token was supplied during this proof request",
            ],
            evidence={
                "validation_mode": "credential_free_cors_origin_reflection",
                "origin": self.CONTROLLED_ORIGIN,
                "allow_origin": allow_origin,
                "allow_credentials": allow_credentials,
                "payload": None,
            },
            remediation=(
                "Use an exact allowlist for trusted web application origins and do not permit "
                "credentials for arbitrary or reflected origins."
            ),
            request_method=observation.method,
            request_url=observation.url,
            request_headers=observation.request_headers,
            response_status=observation.status_code,
            response_headers=observation.headers,
            response_body=observation.body_sample,
            http_version=observation.http_version,
            response_reason=observation.response_reason,
        )

    async def _observe(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> HttpObservation | None:
        if not await self.scope_guard.is_url_allowed(url):
            return None
        try:
            await self.rate_limiter.wait()
            started = time.perf_counter()
            async with session.get(
                url,
                headers={"origin": self.CONTROLLED_ORIGIN},
                allow_redirects=True,
            ) as response:
                body = await response.text(errors="replace")
                return HttpObservation(
                    url=str(response.url),
                    method="GET",
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
