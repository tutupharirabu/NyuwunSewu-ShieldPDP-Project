import asyncio
import re
import time
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

import aiohttp

from app.recon import CrawledEndpoint
from app.services.policy_engine import PolicyEngine
from app.services.scope_guard import ScopeGuard
from app.utils.rate_limiter import AdaptiveRateLimiter
from app.validation.types import HttpObservation, ValidationResult


class PathTraversalValidator:
    """Bounded validation for endpoints that already expose file-like inputs."""

    FILE_PARAMETER_RE = re.compile(
        r"(?i)(?:^|[_-])(file|filename|filepath|path|page|template|include|document|"
        r"download|attachment|resource|folder|dir)(?:$|[_-])"
    )
    FILE_VALUE_RE = re.compile(
        r"(?i)(?:[/\\]|%2f|%5c|^\.{1,2}[/\\]).*\.(?:html?|txt|xml|json|pdf|csv|ini|log|conf|config)$"
    )
    PROBES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
        (
            "../../../../etc/hosts",
            "Unix host file content signature",
            re.compile(r"(?mi)^\s*127\.0\.0\.1\s+(?:localhost|localhost\.)"),
        ),
        (
            r"..\..\..\..\windows\win.ini",
            "Windows INI file content signature",
            re.compile(r"(?mi)^\s*\[(?:fonts|extensions)\]\s*$"),
        ),
    )

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
        if not self.policy.is_validation_allowed("path_traversal"):
            return None
        for method, url, parameter, baseline_data in self._candidates(endpoint)[:3]:
            baseline = await self._observe(session, url, method, baseline_data, headers)
            if baseline is None or baseline.status_code >= 500:
                continue
            for payload, signature_name, signature in self.PROBES:
                probe_url, probe_data = self._mutation(method, url, parameter, baseline_data, payload)
                first = await self._observe(session, probe_url, method, probe_data, headers)
                if first is None or signature.search(baseline.body_sample) or not signature.search(first.body_sample):
                    continue
                await asyncio.sleep(0.1)
                confirmation = await self._observe(session, probe_url, method, probe_data, headers)
                if confirmation is None or not signature.search(confirmation.body_sample):
                    continue
                return ValidationResult(
                    finding_type="path_traversal",
                    title="Validated Path Traversal File Disclosure",
                    severity="high",
                    confidence=94.0,
                    endpoint=url,
                    description=(
                        "A bounded path traversal request returned a reproducible operating-system "
                        "file signature. No file modification or broad file retrieval was attempted."
                    ),
                    reasoning=[
                        f"Input '{parameter}' has file or path handling characteristics",
                        f"{signature_name} appeared only after the traversal probe",
                        "The evidence was confirmed by a bounded repeat request",
                    ],
                    evidence={
                        "validation_mode": "bounded_path_traversal_file_signature_validation",
                        "parameter": parameter,
                        "injected_parameter": parameter,
                        "injection_location": "form_body" if method == "POST" else "query_parameter",
                        "payload": payload,
                        "baseline_status": baseline.status_code,
                        "validation_status": confirmation.status_code,
                        "signature": signature_name,
                    },
                    remediation=(
                        "Resolve files from server-side identifiers, reject traversal sequences, "
                        "canonicalize paths within an allowed directory, and apply least privilege."
                    ),
                    request_method=method,
                    request_url=probe_url,
                    request_headers=confirmation.request_headers,
                    request_body=urlencode(probe_data) if method == "POST" and probe_data else None,
                    response_status=confirmation.status_code,
                    response_headers=confirmation.headers,
                    response_body=confirmation.body_sample,
                    http_version=confirmation.http_version,
                    response_reason=confirmation.response_reason,
                )
        return None

    def _candidates(
        self, endpoint: CrawledEndpoint
    ) -> list[tuple[str, str, str, dict[str, str] | None]]:
        candidates: list[tuple[str, str, str, dict[str, str] | None]] = []
        query = parse_qs(urlparse(endpoint.url).query, keep_blank_values=True)
        for parameter, values in query.items():
            if self._file_candidate(parameter, values[0] if values else ""):
                candidates.append(("GET", endpoint.url, parameter, None))
        for form in endpoint.forms[:4]:
            method = str(form.get("method") or "GET").upper()
            if method not in {"GET", "POST"}:
                continue
            action = str(form.get("action") or endpoint.url)
            data = {
                str(field.get("name")): str(field.get("value") or "test")
                for field in form.get("fields", [])
                if field.get("name")
            }
            for parameter, value in data.items():
                if self._file_candidate(parameter, value):
                    candidates.append((method, action, parameter, data))
        return candidates

    def _file_candidate(self, parameter: str, value: str) -> bool:
        return bool(
            self.FILE_PARAMETER_RE.search(parameter)
            or self.FILE_VALUE_RE.search(unquote(value.strip()))
        )

    def _mutation(
        self,
        method: str,
        url: str,
        parameter: str,
        baseline_data: dict[str, str] | None,
        payload: str,
    ) -> tuple[str, dict[str, str] | None]:
        if method == "POST":
            data = dict(baseline_data or {})
            data[parameter] = payload
            return url, data
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[parameter] = [payload]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True))), None

    async def _observe(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        data: dict[str, str] | None,
        headers: dict[str, str] | None,
    ) -> HttpObservation | None:
        if not await self.scope_guard.is_url_allowed(url):
            return None
        try:
            await self.rate_limiter.wait()
            started = time.perf_counter()
            request = session.post if method == "POST" else session.get
            kwargs: dict[str, object] = {"headers": headers, "allow_redirects": True}
            if method == "POST":
                kwargs["data"] = data or {}
            async with request(url, **kwargs) as response:
                body = await response.text(errors="replace")
                request_headers = {
                    key.lower(): value for key, value in response.request_info.headers.items()
                }
                if method == "POST":
                    encoded_body = urlencode(data or {})
                    request_headers.setdefault("content-type", "application/x-www-form-urlencoded")
                    request_headers.setdefault("content-length", str(len(encoded_body.encode("utf-8"))))
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
