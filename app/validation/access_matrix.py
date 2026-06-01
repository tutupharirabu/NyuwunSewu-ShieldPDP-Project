import re
import time
import asyncio
import json
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

import aiohttp

from app.recon import CrawledEndpoint
from app.services.policy_engine import PolicyEngine
from app.services.scope_guard import ScopeGuard
from app.utils.rate_limiter import AdaptiveRateLimiter
from app.validation.false_positive import similarity
from app.validation.types import HttpObservation, ValidationResult


@dataclass(slots=True)
class RoleContext:
    name: str
    headers: dict[str, str]


class AccessControlMatrixValidator:
    SENSITIVE_ENDPOINT_RE = re.compile(
        r"(?i)/(?:[^/?#]+/)*(?:admin|manage|dashboard|users?|customers?|profile|accounts?|"
        r"invoices?|billing|bill-payments?|payments?|transactions?|transfers?|reports?|audit|"
        r"roles?|permissions?|virtual-cards?|sup3r_s3cr3t_admin)(?:/|$)"
    )
    SENSITIVE_FIELDS = {
        "email",
        "phone",
        "nik",
        "npwp",
        "address",
        "account",
        "account_number",
        "balance",
        "amount",
        "invoice",
        "role",
        "permission",
        "customer",
        "transactions",
        "payments",
        "card_number",
    }

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
        contexts: list[RoleContext],
        anonymous_session: aiohttp.ClientSession | None = None,
    ) -> tuple[ValidationResult | None, dict]:
        matrix: dict[str, dict] = {}
        if not self.policy.is_validation_allowed("auth") or len(contexts) < 2:
            return None, matrix
        if "{" in unquote(urlparse(endpoint.url).path):
            return None, matrix

        observations: dict[str, HttpObservation] = {}
        for context in contexts:
            context_session = (
                anonymous_session
                if context.name == "anonymous" and anonymous_session is not None
                else session
            )
            observed = await self._observe(context_session, endpoint.url, context.headers)
            if observed:
                observations[context.name] = observed
                matrix[context.name] = {
                    "status": observed.status_code,
                    "length": observed.content_length,
                    "sensitive_fields": self._contains_material_sensitive_data(observed),
                }

        if len(observations) < 2:
            return None, matrix

        admin_like = observations.get("admin") or observations.get("primary")
        lower_roles = [
            (role, obs)
            for role, obs in observations.items()
            if role not in {"admin", "primary"} and obs.status_code == 200
        ]
        if not admin_like or not lower_roles:
            return None, matrix

        findings: list[str] = []
        max_similarity = 0.0
        proof_observation: HttpObservation | None = None
        proof_role: str | None = None
        proof_has_sensitive_data = False
        for role, observed in lower_roles:
            body_similarity = similarity(admin_like.body_sample, observed.body_sample)
            max_similarity = max(max_similarity, body_similarity)
            has_sensitive_data = self._contains_material_sensitive_data(observed)
            if (
                body_similarity > 0.82
                and has_sensitive_data
                and admin_like.status_code == 200
            ):
                findings.append(
                    f"Role '{role}' received material sensitive data comparable to privileged context"
                )
                proof_observation = observed
                proof_role = role
                proof_has_sensitive_data = has_sensitive_data

        if not findings:
            return None, matrix

        confidence = min(94.0, 68.0 + len(findings) * 10 + max_similarity * 12)
        if confidence < 76:
            return None, matrix
        proof_observation = proof_observation or lower_roles[0][1]

        return (
            ValidationResult(
                finding_type="access_control_matrix",
                title="Access Control Matrix Inconsistency",
                severity="high" if confidence >= 85 and proof_has_sensitive_data else "medium",
                confidence=confidence,
                endpoint=endpoint.url,
                description=(
                    "Multi-role validation indicated that lower-privileged contexts may access "
                    "content comparable to a privileged context."
                ),
                reasoning=findings,
                evidence={
                    "validation_mode": "role_response_comparison",
                    "test_action": f"Requested endpoint as lower-privileged role '{proof_role or 'unknown'}'",
                    "payload": None,
                    "matrix": matrix,
                    "max_similarity": round(max_similarity, 3),
                },
                remediation=(
                    "Define an endpoint-by-role access matrix and enforce it server-side. "
                    "Deny access by default for roles without explicit authorization."
                ),
                request_method=proof_observation.method,
                request_url=proof_observation.url,
                request_headers=proof_observation.request_headers,
                response_status=proof_observation.status_code,
                response_headers=proof_observation.headers,
                response_body=proof_observation.body_sample,
                http_version=proof_observation.http_version,
                response_reason=proof_observation.response_reason,
            ),
            matrix,
        )

    def _contains_material_sensitive_data(self, observed: HttpObservation) -> bool:
        content_type = (observed.headers.get("content-type") or "").lower()
        if "json" not in content_type:
            return False
        try:
            payload = json.loads(observed.body_sample)
        except json.JSONDecodeError:
            return False

        def contains(value: object) -> bool:
            if isinstance(value, dict):
                for key, nested in value.items():
                    normalized = str(key).lower().replace("-", "_")
                    if normalized in self.SENSITIVE_FIELDS and self._has_material_value(nested):
                        return True
                    if contains(nested):
                        return True
            if isinstance(value, list):
                return any(contains(item) for item in value[:25])
            return False

        return contains(payload)

    @staticmethod
    def _has_material_value(value: object) -> bool:
        if value is None or value is False:
            return False
        if isinstance(value, str):
            stripped = value.strip()
            return bool(stripped and not (stripped.startswith("{") and stripped.endswith("}")))
        if isinstance(value, (list, dict)):
            return bool(value)
        return True

    async def _observe(
        self,
        session: aiohttp.ClientSession,
        url: str,
        headers: dict[str, str],
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
