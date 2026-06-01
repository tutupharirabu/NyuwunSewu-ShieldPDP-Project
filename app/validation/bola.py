import asyncio
import re
import time
import uuid
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp

from app.recon import CrawledEndpoint
from app.services.policy_engine import PolicyEngine
from app.services.scope_guard import ScopeGuard
from app.utils.rate_limiter import AdaptiveRateLimiter
from app.validation.false_positive import FalsePositiveReducer, SignalSet, similarity
from app.validation.types import HttpObservation, ValidationResult


class BOLAValidator:
    NUMERIC_ID_RE = re.compile(r"(?P<prefix>/)(?P<id>[1-9][0-9]{0,12})(?P<suffix>(?:/|$))")
    UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
    SENSITIVE_FIELD_RE = re.compile(
        r"(?i)(email|phone|nik|npwp|rekening|account|address|token|customer|balance|amount|invoice)"
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
        self.reducer = FalsePositiveReducer()

    async def validate(
        self,
        endpoint: CrawledEndpoint,
        session: aiohttp.ClientSession,
        primary_headers: dict[str, str] | None = None,
        secondary_headers: dict[str, str] | None = None,
    ) -> ValidationResult | None:
        if not self.policy.is_validation_allowed("bola"):
            return None

        mutations = self._mutate_identifiers(endpoint.url)
        if not mutations:
            return None

        baseline = await self._observe(session, endpoint.url, primary_headers)
        if baseline is None or baseline.status_code != 200:
            return None

        observations: list[HttpObservation] = []
        signals = SignalSet()
        reasoning: list[str] = []
        proof_observation: HttpObservation | None = None
        proof_mutation_url: str | None = None
        proof_reason: str | None = None

        for mutation_url, mutation_reason in mutations[:2]:
            candidate = await self._observe(session, mutation_url, primary_headers)
            if candidate is None:
                continue
            observations.append(candidate)
            if candidate.status_code == 200 and self.SENSITIVE_FIELD_RE.search(candidate.body_sample):
                sim = similarity(baseline.body_sample, candidate.body_sample)
                if 0.25 <= sim <= 0.98:
                    signals.sensitive_fields = True
                    reasoning.append(f"Object ID mutation returned sensitive-looking content: {mutation_reason}")
                    proof_observation = candidate
                    proof_mutation_url = mutation_url
                    proof_reason = mutation_reason

            if secondary_headers:
                secondary = await self._observe(session, mutation_url, secondary_headers)
                if secondary:
                    observations.append(secondary)
                    if secondary.status_code == 200 and self.SENSITIVE_FIELD_RE.search(secondary.body_sample):
                        sim = similarity(candidate.body_sample, secondary.body_sample)
                        if sim > 0.65:
                            signals.auth_context_changed = True
                            signals.sensitive_fields = True
                            reasoning.append("Secondary authorization context accessed mutated object content")
                            proof_observation = secondary
                            proof_mutation_url = mutation_url
                            proof_reason = f"{mutation_reason} under secondary authorization context"
            await asyncio.sleep(0.05)

        decision = self.reducer.reduce(baseline, observations, signals, minimum_confidence=74.0)
        if not decision.accepted:
            return None
        proof_observation = proof_observation or observations[0]
        proof_mutation_url = proof_mutation_url or proof_observation.url

        return ValidationResult(
            finding_type="bola_idor",
            title="Possible BOLA / IDOR Authorization Weakness",
            severity="high" if decision.confidence >= 85 else "medium",
            confidence=decision.confidence,
            endpoint=endpoint.url,
            description=(
                "Object identifier mutation indicated that authorization may not be consistently "
                "enforcing resource ownership. Validation was limited to bounded object ID swaps."
            ),
            reasoning=reasoning + decision.reasoning,
            evidence={
                "validation_mode": "object_identifier_mutation",
                "payload": proof_mutation_url,
                "mutation_reason": proof_reason,
                "injection_location": "url_identifier",
                "mutations_tested": [url for url, _ in mutations[:2]],
                "baseline_status": baseline.status_code,
                "candidate_statuses": [obs.status_code for obs in observations],
                "anomaly_score": decision.anomaly_score,
            },
            remediation=(
                "Enforce server-side object ownership checks on every object read/write path. "
                "Use subject-bound authorization decisions instead of trusting object identifiers."
            ),
            request_method=proof_observation.method,
            request_url=proof_mutation_url,
            request_headers=proof_observation.request_headers,
            response_status=proof_observation.status_code,
            response_headers=proof_observation.headers,
            response_body=proof_observation.body_sample,
            http_version=proof_observation.http_version,
            response_reason=proof_observation.response_reason,
        )

    def _mutate_identifiers(self, url: str) -> list[tuple[str, str]]:
        parsed = urlparse(url)
        mutations: list[tuple[str, str]] = []

        def replace_numeric(match: re.Match[str]) -> str:
            value = int(match.group("id"))
            return f"{match.group('prefix')}{value + 1}{match.group('suffix')}"

        if self.NUMERIC_ID_RE.search(parsed.path):
            mutated_path = self.NUMERIC_ID_RE.sub(replace_numeric, parsed.path, count=1)
            mutations.append((urlunparse(parsed._replace(path=mutated_path)), "numeric path ID increment"))

        uuid_match = self.UUID_RE.search(parsed.path)
        if uuid_match:
            mutations.append(
                (
                    urlunparse(parsed._replace(path=parsed.path.replace(uuid_match.group(0), str(uuid.uuid4()), 1))),
                    "UUID path replacement",
                )
            )

        query = parse_qs(parsed.query, keep_blank_values=True)
        for key, values in query.items():
            value = values[0]
            if value.isdigit() and 0 < len(value) <= 13:
                mutated = dict(query)
                mutated[key] = [str(int(value) + 1)]
                mutations.append((urlunparse(parsed._replace(query=urlencode(mutated, doseq=True))), f"numeric query ID increment in {key}"))
                break
            if self.UUID_RE.fullmatch(value):
                mutated = dict(query)
                mutated[key] = [str(uuid.uuid4())]
                mutations.append((urlunparse(parsed._replace(query=urlencode(mutated, doseq=True))), f"UUID query replacement in {key}"))
                break
        return mutations

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
                elapsed = (time.perf_counter() - start) * 1000
                return HttpObservation(
                    url=str(response.url),
                    method="GET",
                    status_code=response.status,
                    elapsed_ms=elapsed,
                    headers={k.lower(): v for k, v in response.headers.items()},
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
