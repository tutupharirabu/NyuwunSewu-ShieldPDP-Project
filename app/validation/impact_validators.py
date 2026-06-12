from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import aiohttp

from app.recon import CrawledEndpoint
from app.services.policy_engine import PolicyEngine
from app.services.scope_guard import ScopeGuard
from app.utils.rate_limiter import AdaptiveRateLimiter
from app.validation.attack_knowledge import AttackKnowledgeEngine
from app.validation.types import HttpObservation, ValidationResult


class SSRFInBandValidator:
    """Bounded SSRF proof using operator-provided in-band canary responses."""

    BLOCKED_CANARY_HOSTS = {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata",
    }

    def __init__(
        self,
        policy: PolicyEngine,
        scope_guard: ScopeGuard,
        rate_limiter: AdaptiveRateLimiter,
    ) -> None:
        self.policy = policy
        self.scope_guard = scope_guard
        self.rate_limiter = rate_limiter
        self.knowledge = AttackKnowledgeEngine()

    async def validate(
        self,
        endpoint: CrawledEndpoint,
        session: aiohttp.ClientSession,
        headers: dict[str, str] | None,
        options: dict[str, Any] | None,
    ) -> ValidationResult | None:
        options = options or {}
        if not options.get("enabled") or not self.policy.is_validation_allowed("auth"):
            return None
        canary_urls = [str(item) for item in options.get("ssrf_canary_urls") or []]
        markers = [str(item) for item in options.get("ssrf_canary_markers") or []]
        if not canary_urls or not markers:
            return None
        if not any(candidate.technique == "ssrf_url_fetch" for candidate in self.knowledge.candidates(endpoint)):
            return None

        for method, action, field_name, body in self._requests(endpoint):
            if not await self.scope_guard.is_url_allowed(action):
                continue
            for canary_url in canary_urls[:5]:
                if not self._canary_allowed(canary_url, options):
                    continue
                request_body = None
                request_url = action
                observation: HttpObservation | None
                if method == "GET":
                    request_url = self._mutate_query(action, field_name, canary_url)
                    observation = await self._observe(
                        session, request_url, headers=headers, method="GET"
                    )
                else:
                    payload = {**body, field_name: canary_url}
                    request_body = json.dumps(payload, separators=(",", ":"))
                    observation = await self._observe(
                        session,
                        action,
                        headers=headers,
                        method="POST",
                        json_body=payload,
                    )
                result = self._confirmed_result(
                    endpoint=endpoint,
                    field_name=field_name,
                    canary_url=canary_url,
                    markers=markers,
                    observation=observation,
                    request_url=request_url,
                    request_body=request_body,
                )
                if result:
                    return result
        return None

    def _requests(
        self, endpoint: CrawledEndpoint
    ) -> list[tuple[str, str, str, dict[str, str]]]:
        requests: list[tuple[str, str, str, dict[str, str]]] = []
        parsed = urlparse(endpoint.url)
        for field_name in parse_qs(parsed.query, keep_blank_values=True):
            if self.knowledge.URL_FETCH_PARAM_RE.search(field_name):
                requests.append(("GET", endpoint.url, field_name, {}))

        for form in endpoint.forms:
            method = str(form.get("method") or "POST").upper()
            action = urljoin(endpoint.url, str(form.get("action") or endpoint.url))
            payload = {
                str(field.get("name")): str(field.get("value") or "")
                for field in form.get("fields", [])
                if field.get("name")
            }
            for field_name in payload:
                if self.knowledge.URL_FETCH_PARAM_RE.search(field_name):
                    requests.append(("POST" if method != "GET" else "GET", action, field_name, payload))
        return requests[:8]

    def _canary_allowed(self, canary_url: str, options: dict[str, Any]) -> bool:
        parsed = urlparse(canary_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        hostname = parsed.hostname.lower()
        if hostname in self.BLOCKED_CANARY_HOSTS:
            return False
        allowed_hosts = {str(item).lower() for item in options.get("ssrf_allowed_hosts") or []}
        loopback_hosts = {"127.0.0.1", "localhost", "::1"}
        return hostname in loopback_hosts or hostname in allowed_hosts

    def _confirmed_result(
        self,
        *,
        endpoint: CrawledEndpoint,
        field_name: str,
        canary_url: str,
        markers: list[str],
        observation: HttpObservation | None,
        request_url: str,
        request_body: str | None,
    ) -> ValidationResult | None:
        if observation is None or observation.status_code not in {200, 201, 202}:
            return None
        marker = next((item for item in markers if item and item in observation.body_sample), "")
        if not marker:
            return None

        return ValidationResult(
            finding_type="ssrf_inband_url_fetch",
            title="SSRF URL Fetch Confirmed With In-Band Canary",
            severity="high",
            confidence=94.0,
            endpoint=endpoint.url,
            description=(
                "A URL-like input caused the server to fetch an operator-approved canary URL "
                "and return the canary marker in-band."
            ),
            reasoning=[
                f"URL-like field '{field_name}' was identified on a scoped endpoint",
                "The canary host was restricted to loopback or an explicit allowlist",
                "The response contained the expected in-band canary marker",
            ],
            evidence={
                "validation_mode": "bounded_ssrf_inband_canary_validation",
                "field": field_name,
                "canary_host": urlparse(canary_url).hostname,
                "canary_marker_present": True,
                "payload": None,
            },
            remediation=(
                "Reject or strictly allowlist server-side fetch destinations, block loopback "
                "and metadata ranges, resolve and verify IPs after redirects, and fetch remote "
                "media through a hardened proxy."
            ),
            request_method=observation.method,
            request_url=request_url,
            request_headers=observation.request_headers,
            request_body=request_body,
            response_status=observation.status_code,
            response_headers=observation.headers,
            response_body=observation.body_sample,
            http_version=observation.http_version,
            response_reason=observation.response_reason,
        )

    def _mutate_query(self, url: str, parameter: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[parameter] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    async def _observe(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        headers: dict[str, str] | None,
        method: str,
        json_body: dict[str, Any] | None = None,
    ) -> HttpObservation | None:
        if not await self.scope_guard.is_url_allowed(url):
            return None
        try:
            await self.rate_limiter.wait()
            started = time.perf_counter()
            request = session.post if method == "POST" else session.get
            kwargs: dict[str, Any] = {"headers": headers or {}, "allow_redirects": True}
            if method == "POST":
                kwargs["json"] = json_body or {}
            async with request(url, **kwargs) as response:
                body = await response.text(errors="replace")
                request_headers = {
                    key.lower(): value for key, value in response.request_info.headers.items()
                }
                if method == "POST":
                    encoded = json.dumps(json_body or {}, separators=(",", ":"))
                    request_headers.setdefault("content-type", "application/json")
                    request_headers.setdefault("content-length", str(len(encoded.encode())))
                return HttpObservation(
                    url=str(response.url),
                    method=method,
                    status_code=response.status,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body_sample=body[:12000],
                    content_length=len(body),
                    request_headers=request_headers,
                    http_version=f"HTTP/{response.version.major}.{response.version.minor}",
                    response_reason=response.reason or "",
                )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            self.rate_limiter.record_anomaly()
            return None


class RateLimitRoleValidator:
    """Compare auth and anonymous rate-limit metadata without flooding."""

    ROLE_RE = re.compile(r'(?i)"?(role|auth(?:enticated)?|user_type|bucket)"?\s*[:=]\s*"?([a-z_\-]+)')

    def __init__(
        self,
        policy: PolicyEngine,
        scope_guard: ScopeGuard,
        rate_limiter: AdaptiveRateLimiter,
    ) -> None:
        self.policy = policy
        self.scope_guard = scope_guard
        self.rate_limiter = rate_limiter
        self.knowledge = AttackKnowledgeEngine()

    async def validate(
        self,
        endpoint: CrawledEndpoint,
        session: aiohttp.ClientSession,
        anonymous_session: aiohttp.ClientSession,
        primary_headers: dict[str, str] | None,
    ) -> ValidationResult | None:
        if not primary_headers or not self.policy.is_validation_allowed("auth"):
            return None
        if not any(candidate.technique == "rate_limit_role_misclassification" for candidate in self.knowledge.candidates(endpoint)):
            return None
        authenticated = await self._observe(session, endpoint.url, headers=primary_headers)
        anonymous = await self._observe(anonymous_session, endpoint.url, headers={})
        return self._mismatch_result(endpoint, authenticated, anonymous)

    def _mismatch_result(
        self,
        endpoint: CrawledEndpoint,
        authenticated: HttpObservation | None,
        anonymous: HttpObservation | None,
    ) -> ValidationResult | None:
        if authenticated is None or anonymous is None:
            return None
        if authenticated.status_code not in {200, 201} or anonymous.status_code not in {200, 201}:
            return None

        auth_role = self._role_label(authenticated.body_sample)
        anon_role = self._role_label(anonymous.body_sample)
        auth_looks_anon = auth_role in {"anonymous", "unauthenticated", "guest", "false"}
        same_bucket = bool(auth_role and anon_role and auth_role == anon_role)
        if not auth_looks_anon and not same_bucket:
            return None

        return ValidationResult(
            finding_type="rate_limit_role_misclassification",
            title="Rate Limit Metadata Misclassifies Authenticated Context",
            severity="medium",
            confidence=88.0,
            endpoint=endpoint.url,
            description=(
                "Authenticated and anonymous rate-limit metadata indicate the same or anonymous "
                "role bucket, which can weaken enforcement and audit attribution."
            ),
            reasoning=[
                "One authenticated metadata request and one anonymous metadata request were compared",
                f"Authenticated role/bucket label: {auth_role or 'not detected'}",
                f"Anonymous role/bucket label: {anon_role or 'not detected'}",
                "No quota exhaustion or request flooding was performed",
            ],
            evidence={
                "validation_mode": "bounded_rate_limit_role_comparison",
                "authenticated_status": authenticated.status_code,
                "anonymous_status": anonymous.status_code,
                "authenticated_role": auth_role,
                "anonymous_role": anon_role,
                "payload": None,
            },
            remediation=(
                "Bind rate-limit buckets to the authenticated principal and role after session "
                "validation, separate anonymous and authenticated quotas, and add audit logging for "
                "quota decisions."
            ),
            request_method=authenticated.method,
            request_url=authenticated.url,
            request_headers=authenticated.request_headers,
            response_status=authenticated.status_code,
            response_headers=authenticated.headers,
            response_body=authenticated.body_sample,
            http_version=authenticated.http_version,
            response_reason=authenticated.response_reason,
        )

    def _role_label(self, body: str) -> str:
        try:
            data = json.loads(body)
            for key in ("role", "user_type", "bucket", "auth", "authenticated"):
                if key in data:
                    return str(data[key]).lower()
        except (TypeError, ValueError):
            pass
        match = self.ROLE_RE.search(body or "")
        return match.group(2).lower() if match else ""

    async def _observe(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        headers: dict[str, str],
    ) -> HttpObservation | None:
        if not await self.scope_guard.is_url_allowed(url):
            return None
        try:
            await self.rate_limiter.wait()
            started = time.perf_counter()
            async with session.get(url, headers=headers, allow_redirects=True) as response:
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


class BusinessLogicImpactEvaluator:
    """Pure impact evaluator for state-changing workflows guarded by test data."""

    def negative_amount_transfer_result(
        self,
        *,
        endpoint_url: str,
        amount: float,
        source_before: float,
        source_after: float,
        destination_before: float,
        destination_after: float,
        observation: HttpObservation,
        request_body: str,
    ) -> ValidationResult | None:
        if amount >= 0:
            return None
        source_increased = source_after > source_before
        destination_decreased = destination_after < destination_before
        if not (source_increased and destination_decreased):
            return None

        return ValidationResult(
            finding_type="negative_amount_business_logic",
            title="Negative Amount Reversed Funds Between Test Accounts",
            severity="high",
            confidence=93.0,
            endpoint=endpoint_url,
            description=(
                "A negative amount was accepted in a test-account workflow and reversed the "
                "expected direction of balance movement."
            ),
            reasoning=[
                "The validation used operator-approved test accounts",
                "A negative amount was accepted by a financial workflow",
                "Before/after balances showed reverse movement",
            ],
            evidence={
                "validation_mode": "bounded_business_logic_test_account_comparison",
                "amount": amount,
                "source_before": source_before,
                "source_after": source_after,
                "destination_before": destination_before,
                "destination_after": destination_after,
                "payload": None,
            },
            remediation=(
                "Reject negative, zero, NaN, and overflow amounts server-side; enforce invariant "
                "checks around debit/credit direction; and wrap financial operations in audited "
                "transactions with test coverage."
            ),
            request_method=observation.method,
            request_url=observation.url,
            request_headers=observation.request_headers,
            request_body=request_body,
            response_status=observation.status_code,
            response_headers=observation.headers,
            response_body=observation.body_sample,
            http_version=observation.http_version,
            response_reason=observation.response_reason,
        )
