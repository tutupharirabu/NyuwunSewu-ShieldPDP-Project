import asyncio
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp
from bs4 import BeautifulSoup

from app.recon import CrawledEndpoint
from app.services.policy_engine import PolicyEngine
from app.services.scope_guard import ScopeGuard
from app.utils.rate_limiter import AdaptiveRateLimiter
from app.validation.types import HttpObservation, ValidationResult


class ReflectedHTMLInjectionValidator:
    """Validates unencoded HTML reflection with an inert, non-executing DOM canary."""

    def __init__(
        self,
        policy: PolicyEngine,
        scope_guard: ScopeGuard,
        rate_limiter: AdaptiveRateLimiter,
    ):
        self.policy = policy
        self.scope_guard = scope_guard
        self.rate_limiter = rate_limiter

    async def validate(
        self,
        endpoint: CrawledEndpoint,
        session: aiohttp.ClientSession,
        headers: dict[str, str] | None = None,
    ) -> ValidationResult | None:
        if not self.policy.is_validation_allowed("reflected_html"):
            return None
        parameters = list(parse_qs(urlparse(endpoint.url).query, keep_blank_values=True).keys())
        if not parameters:
            return None
        baseline = await self._observe(session, endpoint.url, headers)
        if baseline is None or "html" not in baseline.headers.get("content-type", "").lower():
            return None

        for parameter in parameters[:3]:
            marker = f"shieldpdp-{secrets.token_hex(5)}"
            payload = f'\"><span data-shieldpdp-probe="{marker}">{marker}</span>'
            candidate_url = self._mutate_query(endpoint.url, parameter, payload)
            first = await self._observe(session, candidate_url, headers)
            if first is None or self._contains_probe(baseline.body_sample, marker):
                continue
            if not self._contains_probe(first.body_sample, marker):
                continue
            await asyncio.sleep(0.1)
            confirmation = await self._observe(session, candidate_url, headers)
            if confirmation is None or not self._contains_probe(confirmation.body_sample, marker):
                continue
            return ValidationResult(
                finding_type="reflected_html_injection",
                title="Validated Reflected HTML Injection (XSS Risk)",
                severity="medium",
                confidence=92.0,
                endpoint=endpoint.url,
                description=(
                    "A query parameter reproducibly rendered an injected inert HTML element in "
                    "the response. JavaScript execution was not attempted."
                ),
                reasoning=[
                    f"Input '{parameter}' reflected an unencoded HTML canary into the parsed response",
                    "The reflected element was confirmed by a bounded repeat request",
                    "Inert validation avoids executing a cross-site scripting payload",
                ],
                evidence={
                    "validation_mode": "inert_reflected_html_canary_validation",
                    "parameter": parameter,
                    "injected_parameter": parameter,
                    "injection_location": "query_parameter",
                    "payload": payload,
                    "execution_attempted": False,
                    "marker": marker,
                    "validation_status": confirmation.status_code,
                },
                remediation=(
                    "Apply contextual output encoding for reflected values, validate input where "
                    "appropriate, and enforce a restrictive Content Security Policy."
                ),
                request_method="GET",
                request_url=candidate_url,
                request_headers=confirmation.request_headers,
                response_status=confirmation.status_code,
                response_headers=confirmation.headers,
                response_body=confirmation.body_sample,
                http_version=confirmation.http_version,
                response_reason=confirmation.response_reason,
            )
        return None

    def _mutate_query(self, url: str, parameter: str, payload: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        current = query.get(parameter, [""])[0]
        query[parameter] = [current + payload]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

    def _contains_probe(self, body: str, marker: str) -> bool:
        soup = BeautifulSoup(body, "lxml")
        element = soup.find("span", attrs={"data-shieldpdp-probe": marker})
        return bool(element and marker in element.get_text())

    async def _observe(
        self,
        session: aiohttp.ClientSession,
        url: str,
        headers: dict[str, str] | None,
    ) -> HttpObservation | None:
        if not await self.scope_guard.is_url_allowed(url):
            return None
        try:
            await self.rate_limiter.wait()
            start = time.perf_counter()
            async with session.get(url, headers=headers, allow_redirects=True) as response:
                body = await response.text(errors="replace")
                return HttpObservation(
                    url=str(response.url),
                    method="GET",
                    status_code=response.status,
                    elapsed_ms=(time.perf_counter() - start) * 1000,
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
