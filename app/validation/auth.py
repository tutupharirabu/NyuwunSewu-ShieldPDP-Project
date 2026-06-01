import base64
import json
import re
import time
from urllib.parse import unquote, urlparse

import aiohttp

from app.recon import CrawledEndpoint
from app.services.policy_engine import PolicyEngine
from app.services.scope_guard import ScopeGuard
from app.utils.rate_limiter import AdaptiveRateLimiter
from app.validation.false_positive import FalsePositiveReducer, SignalSet, similarity
from app.validation.types import HttpObservation, ValidationResult


class AuthValidator:
    PUBLIC_ENDPOINT = "PUBLIC_ENDPOINT"
    AUTH_OPTIONAL = "AUTH_OPTIONAL"
    AUTH_REQUIRED = "AUTH_REQUIRED"

    JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
    ADMIN_ENDPOINT_RE = re.compile(r"(?i)/(?:admin|sup3r_s3cr3t_admin|manage)(?:/|$)")
    ADMIN_RESPONSE_RE = re.compile(r"(?i)(admin|approve|privilege|management|user administration)")
    PUBLIC_ROUTE_RE = re.compile(
        r"(?i)^/(?:$|login|signin|sign-in|register|signup|forgot-password|reset-password|"
        r"privacy(?:-policy)?|terms(?:-of-service)?|blog|careers?|about|contact)(?:/|$)"
    )
    PUBLIC_DOC_ROUTE_RE = re.compile(
        r"(?i)^/(?:docs?|documentation|api-docs|swagger(?:-ui)?|swagger-resources|redoc)(?:/|$)"
    )
    SWAGGER_STATIC_RE = re.compile(r"(?i)/(?:swagger-ui|webjars|redoc(?:\.standalone)?)(?:/|\.|-)")
    STATIC_ROUTE_RE = re.compile(r"(?i)^/(?:assets|static|public|images?|img|css|js|fonts?)(?:/|$)")
    STATIC_EXTENSION_RE = re.compile(
        r"(?i)\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|"
        r"txt|xml|pdf|zip|gz|br|mp4|webm|mp3|wav)$"
    )
    AUTH_REQUIRED_PATH_RE = re.compile(
        r"(?i)/(?:[^/?#]+/)*(?:admin|sup3r_s3cr3t_admin|manage|dashboard|profile|me|settings|"
        r"users?|customers?|accounts?|account|balances?|wallets?|cards?|virtual[-_]?accounts?|"
        r"virtual-cards?|transactions?|transfers?|payments?|invoices?|billing|orders?|reports?|"
        r"audit(?:-logs?)?|logs?|roles?|permissions?)(?:/|$)"
    )
    API_ROUTE_RE = re.compile(r"(?i)^/(?:api|v[0-9]+|graphql|gql)(?:/|$)")
    AUTH_REDIRECT_ROUTE_RE = re.compile(r"(?i)/(?:login|signin|sign-in|register)(?:/|$)")
    PROTECTED_FUNCTION_RE = re.compile(
        r"(?i)(admin dashboard|user administration|role management|permission management|audit logs?|"
        r"approve(?:\s+\w+)?|delete user|disable user|transfer funds?|account balance|"
        r"transaction history|billing portal|customer records?|personal data)"
    )
    LOGIN_PAGE_RE = re.compile(
        r"(?i)(<form[^>]+(?:login|signin|sign-in)|name=[\"']?(?:username|password)[\"']?|"
        r"type=[\"']?password[\"']?|log in to continue|sign in to continue)"
    )
    SENSITIVE_JSON_FIELDS = {
        "access_token",
        "account",
        "account_number",
        "address",
        "amount",
        "api_key",
        "balance",
        "billing",
        "card_number",
        "customer",
        "customers",
        "email",
        "iban",
        "invoice",
        "nik",
        "npwp",
        "payment",
        "payments",
        "permission",
        "permissions",
        "phone",
        "refresh_token",
        "role",
        "roles",
        "secret",
        "token",
        "transaction",
        "transactions",
        "transfer",
        "user",
        "user_id",
        "users",
        "virtual_account",
        "wallet",
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
        self.reducer = FalsePositiveReducer()

    def inspect_jwt(self, headers: dict[str, str] | None) -> list[ValidationResult]:
        token = self._extract_jwt(headers)
        if not token:
            return []

        header, payload = self._decode_unverified(token)
        if not header or not payload:
            return []

        weaknesses = self._jwt_weaknesses(header, payload)
        evidence = {
            "validation_mode": "offline_token_inspection",
            "decoded_header": header,
            "decoded_claims": self._redact_claims(payload),
            "claims_present": sorted(payload.keys()),
            "weakness_reason": weaknesses,
            "alg_none": str(header.get("alg", "")).lower() == "none",
            "missing_exp": "exp" not in payload,
            "weak_algorithm": self._weak_jwt_algorithm(header),
            "cracked_secret": False,
            "unsigned_token_accepted": False,
            "insecure_claims": self._insecure_claim_names(payload),
            "payload": None,
        }
        if not weaknesses:
            return [
                ValidationResult(
                    finding_type="jwt_observed",
                    title="JWT Observed in Authenticated Context",
                    severity="info",
                    confidence=45.0,
                    endpoint="authorization_header",
                    description=(
                        "A JWT was present in the supplied authenticated context. No token weakness "
                        "was confirmed from offline inspection."
                    ),
                    reasoning=["JWT structure decoded successfully; no accepted weakness rule matched"],
                    evidence=evidence,
                    remediation="Keep JWT validation policy enforced server-side and rotate signing keys routinely.",
                    exploitability_assessment="HEURISTIC_SIGNAL",
                    false_positive_likelihood="HIGH",
                )
            ]

        confidence = 88.0
        if evidence["alg_none"]:
            confidence = 96.0
        elif evidence["missing_exp"] and evidence["insecure_claims"]:
            confidence = 90.0
        return [
            ValidationResult(
                finding_type="jwt_weakness",
                title="JWT Weakness Detected",
                severity="high" if confidence >= 90 else "medium",
                confidence=min(96.0, confidence),
                endpoint="authorization_header",
                description="Authentication token structure contains a concrete JWT weakness.",
                reasoning=weaknesses,
                evidence=evidence,
                remediation="Require signed JWTs with explicit issuer, audience, expiration, and key rotation.",
            )
        ]

    def is_privilege_endpoint(self, endpoint: CrawledEndpoint) -> bool:
        return bool(self.ADMIN_ENDPOINT_RE.search(endpoint.normalized_path))

    def classify_endpoint_authorization(
        self,
        endpoint: CrawledEndpoint,
        observation: HttpObservation | None = None,
    ) -> str:
        if self._is_public_or_static_url(endpoint.url):
            return self.PUBLIC_ENDPOINT
        if self._has_sensitive_business_context(endpoint, observation):
            return self.AUTH_REQUIRED
        if self.API_ROUTE_RE.match(self._normalized_path(endpoint.url)):
            return self.AUTH_OPTIONAL
        return self.PUBLIC_ENDPOINT

    async def validate_tampered_privilege_claim(
        self,
        endpoint: CrawledEndpoint,
        session: aiohttp.ClientSession,
        headers: dict[str, str] | None,
    ) -> ValidationResult | None:
        if not self.policy.is_validation_allowed("auth") or not self.is_privilege_endpoint(endpoint):
            return None
        token = self._extract_jwt(headers)
        if not token:
            return None
        _, payload = self._decode_unverified(token)
        if payload.get("is_admin") is not False:
            return None

        tampered = self._tamper_boolean_claim_without_resigning(token, "is_admin", True)
        if not tampered:
            return None
        observation = await self._observe(
            session,
            endpoint.url,
            {
                "authorization": f"Bearer {tampered}",
                "cookie": f"token={tampered}",
            },
        )
        if (
            observation is None
            or observation.status_code != 200
            or not self.ADMIN_RESPONSE_RE.search(observation.body_sample)
        ):
            return None

        return ValidationResult(
            finding_type="jwt_claim_integrity_bypass",
            title="JWT Privilege Claim Accepted After Invalid Tampering",
            severity="critical",
            confidence=98.0,
            endpoint=endpoint.url,
            description=(
                "A non-administrator JWT was modified to request administrator privileges while "
                "retaining its invalidated signature, and the protected endpoint accepted it."
            ),
            reasoning=[
                "Original authenticated token carried is_admin=false",
                "Validation changed only is_admin to true and did not create a valid new signature",
                "The administrator endpoint returned privileged-looking content",
            ],
            evidence={
                "validation_mode": "invalid_signature_privilege_claim_negative_control",
                "claim": "is_admin",
                "original_value": False,
                "tested_value": True,
                "signature_strategy": "original_signature_retained_after_payload_change",
                "payload": None,
            },
            remediation=(
                "Verify JWT signatures before consuming claims, enforce server-side role lookup, "
                "and reject tokens whose payload or algorithm does not match policy."
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

    async def validate_missing_authorization(
        self,
        endpoint: CrawledEndpoint,
        session: aiohttp.ClientSession,
        headers: dict[str, str] | None,
        anonymous_session: aiohttp.ClientSession | None = None,
    ) -> ValidationResult | None:
        if not self.policy.is_validation_allowed("auth") or not headers:
            return None

        endpoint_classification = self.classify_endpoint_authorization(endpoint)
        if endpoint_classification != self.AUTH_REQUIRED:
            return None

        baseline = await self._observe(session, endpoint.url, headers)
        anonymous = await self._observe(anonymous_session or session, endpoint.url, {})
        if not baseline or not anonymous:
            return None
        if not self._is_success(baseline) or not self._is_success(anonymous):
            return None
        if self._is_public_or_static_url(anonymous.url) or self._looks_like_auth_redirect(anonymous):
            return None

        endpoint_classification = self.classify_endpoint_authorization(endpoint, baseline)
        if endpoint_classification != self.AUTH_REQUIRED:
            return None

        signals = SignalSet()
        reasoning: list[str] = []
        body_similarity = similarity(baseline.body_sample, anonymous.body_sample)
        proof = self._authorization_bypass_proof(endpoint, anonymous)
        if not any(proof.values()):
            return None

        if body_similarity < 0.35 and not proof["sensitive_data"]:
            return None

        signals.auth_context_changed = True
        signals.sensitive_fields = proof["sensitive_data"] or proof["protected_functionality"]
        if proof["sensitive_data"]:
            reasoning.append("Anonymous request returned material sensitive business data")
        if proof["protected_functionality"]:
            reasoning.append("Anonymous request exposed protected business functionality")
        if proof["state_changing_functionality"]:
            reasoning.append("Authenticated-only state-changing functionality was reachable anonymously")

        decision = self.reducer.reduce(baseline, [anonymous], signals, minimum_confidence=76.0)
        if not decision.accepted:
            return None

        return ValidationResult(
            finding_type="missing_authorization",
            title="Missing Authorization Check",
            severity="high" if decision.confidence >= 85 else "medium",
            confidence=decision.confidence,
            endpoint=endpoint.url,
            description="A protected endpoint returned material data or functionality without authentication headers.",
            reasoning=reasoning + decision.reasoning,
            evidence={
                "validation_mode": "authorization_context_comparison",
                "test_action": "Removed supplied authorization headers and repeated the endpoint request",
                "payload": None,
                "endpoint_classification": endpoint_classification,
                "authenticated_status": baseline.status_code,
                "anonymous_status": anonymous.status_code,
                "body_similarity": round(body_similarity, 3),
                "sensitive_data_visible_anonymously": proof["sensitive_data"],
                "protected_functionality_visible_anonymously": proof["protected_functionality"],
                "state_changing_functionality_visible_anonymously": proof["state_changing_functionality"],
                "anomaly_score": decision.anomaly_score,
            },
            remediation="Require authentication and authorization middleware before protected handlers execute.",
            request_method=anonymous.method,
            request_url=anonymous.url,
            request_headers=anonymous.request_headers,
            response_status=anonymous.status_code,
            response_headers=anonymous.headers,
            response_body=anonymous.body_sample,
            http_version=anonymous.http_version,
            response_reason=anonymous.response_reason,
        )

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
            async with session.get(url, headers=headers or {}, allow_redirects=True) as response:
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
        except Exception:
            self.rate_limiter.record_anomaly()
            return None

    def _decode_unverified(self, token: str) -> tuple[dict, dict]:
        try:
            header_b64, payload_b64, _ = token.split(".", 2)
            header = json.loads(base64.urlsafe_b64decode(self._pad(header_b64)))
            payload = json.loads(base64.urlsafe_b64decode(self._pad(payload_b64)))
            return header, payload
        except Exception:
            return {}, {}

    def _jwt_weaknesses(self, header: dict, payload: dict) -> list[str]:
        weaknesses: list[str] = []
        if str(header.get("alg", "")).lower() == "none":
            weaknesses.append("JWT header declares alg=none")
        if self._weak_jwt_algorithm(header):
            weaknesses.append(f"JWT uses weak or unsupported algorithm: {header.get('alg')}")
        if "exp" not in payload:
            weaknesses.append("JWT claims do not include exp")
        insecure_claims = self._insecure_claim_names(payload)
        if insecure_claims:
            weaknesses.append(f"JWT includes sensitive claims: {', '.join(insecure_claims)}")
        return weaknesses

    def _weak_jwt_algorithm(self, header: dict) -> bool:
        alg = str(header.get("alg", "")).lower()
        return alg in {"", "none", "hs1", "hs128", "rs1", "es1"} or "md5" in alg or "sha1" in alg

    def _insecure_claim_names(self, payload: dict) -> list[str]:
        sensitive = {"password", "passwd", "secret", "api_key", "access_token", "refresh_token"}
        return sorted(str(key) for key in payload if str(key).lower() in sensitive)

    def _redact_claims(self, payload: dict) -> dict:
        redacted: dict = {}
        for key, value in payload.items():
            if str(key).lower() in {"password", "passwd", "secret", "api_key", "access_token", "refresh_token"}:
                redacted[key] = "[REDACTED]"
            elif isinstance(value, str) and len(value) > 80:
                redacted[key] = f"{value[:8]}...[REDACTED]"
            else:
                redacted[key] = value
        return redacted

    def _extract_jwt(self, headers: dict[str, str] | None) -> str:
        if not headers:
            return ""
        sources = [
            headers.get("authorization") or headers.get("Authorization") or "",
            headers.get("cookie") or headers.get("Cookie") or "",
        ]
        for value in sources:
            match = self.JWT_RE.search(value)
            if match:
                return match.group(0)
        return ""

    def _tamper_boolean_claim_without_resigning(
        self,
        token: str,
        claim: str,
        value: bool,
    ) -> str | None:
        try:
            header_b64, payload_b64, signature_b64 = token.split(".", 2)
            payload = json.loads(base64.urlsafe_b64decode(self._pad(payload_b64)))
            if not isinstance(payload, dict):
                return None
            payload[claim] = value
            encoded_payload = base64.urlsafe_b64encode(
                json.dumps(payload, separators=(",", ":")).encode()
            ).decode().rstrip("=")
            return f"{header_b64}.{encoded_payload}.{signature_b64}"
        except Exception:
            return None

    def _pad(self, value: str) -> bytes:
        return (value + "=" * (-len(value) % 4)).encode()

    def _authorization_bypass_proof(
        self,
        endpoint: CrawledEndpoint,
        anonymous: HttpObservation,
    ) -> dict[str, bool]:
        sensitive_data = self._contains_material_sensitive_data(
            anonymous.body_sample,
            anonymous.headers,
        )
        protected_functionality = self._contains_protected_functionality(endpoint, anonymous)
        state_changing_functionality = (
            endpoint.method.upper() not in {"GET", "HEAD", "OPTIONS"}
            and anonymous.method.upper() == endpoint.method.upper()
            and self._is_success(anonymous)
            and not self._is_public_or_static_url(endpoint.url)
        )
        return {
            "sensitive_data": sensitive_data,
            "protected_functionality": protected_functionality,
            "state_changing_functionality": state_changing_functionality,
        }

    def _has_sensitive_business_context(
        self,
        endpoint: CrawledEndpoint,
        observation: HttpObservation | None = None,
    ) -> bool:
        path = self._normalized_path(endpoint.url)
        if self.AUTH_REQUIRED_PATH_RE.search(path):
            return True
        headers = observation.headers if observation else endpoint.response_headers
        body = observation.body_sample if observation else endpoint.response_body_sample
        return self._contains_material_sensitive_data(body, headers)

    def _contains_protected_functionality(
        self,
        endpoint: CrawledEndpoint,
        observation: HttpObservation,
    ) -> bool:
        body = observation.body_sample[:12000]
        if self._looks_like_auth_redirect(observation):
            return False
        return bool(self.PROTECTED_FUNCTION_RE.search(body))

    def _contains_material_sensitive_data(
        self,
        body: str,
        headers: dict[str, str] | None,
    ) -> bool:
        content_type = ((headers or {}).get("content-type") or "").lower()
        if "json" not in content_type:
            return False
        try:
            payload = json.loads(body)
        except (TypeError, json.JSONDecodeError):
            return False

        def contains(value: object) -> bool:
            if isinstance(value, dict):
                for key, nested in value.items():
                    normalized = str(key).lower().replace("-", "_")
                    if normalized in self.SENSITIVE_JSON_FIELDS and self._has_material_value(nested):
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
            lowered = stripped.lower()
            if not stripped:
                return False
            if stripped.startswith("{") and stripped.endswith("}"):
                return False
            if lowered in {"test", "dummy", "example", "sample", "null", "none", "n/a", "redacted"}:
                return False
            return True
        if isinstance(value, (list, dict)):
            return bool(value)
        return True

    def _is_public_or_static_url(self, url: str) -> bool:
        path = self._normalized_path(url)
        if path in {"/openapi.json", "/swagger.json", "/api/openapi.json", "/robots.txt", "/sitemap.xml"}:
            return True
        if self.PUBLIC_ROUTE_RE.match(path) or self.PUBLIC_DOC_ROUTE_RE.match(path):
            return True
        if self.STATIC_ROUTE_RE.match(path) or self.STATIC_EXTENSION_RE.search(path):
            return True
        return bool(self.SWAGGER_STATIC_RE.search(path))

    def _looks_like_auth_redirect(self, observation: HttpObservation) -> bool:
        if self.AUTH_REDIRECT_ROUTE_RE.search(self._normalized_path(observation.url)):
            return True
        content_type = (observation.headers.get("content-type") or "").lower()
        if "html" not in content_type:
            return False
        return bool(self.LOGIN_PAGE_RE.search(observation.body_sample[:8000]))

    @staticmethod
    def _is_success(observation: HttpObservation) -> bool:
        return 200 <= observation.status_code < 300

    @staticmethod
    def _normalized_path(url: str) -> str:
        path = unquote(urlparse(url).path or "/")
        if path != "/" and path.endswith("/"):
            return path.rstrip("/")
        return path
