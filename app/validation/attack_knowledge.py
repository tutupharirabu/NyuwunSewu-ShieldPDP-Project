from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

from app.recon import CrawledEndpoint


@dataclass(slots=True)
class AttackTechniqueCandidate:
    technique: str
    confidence: int
    risk: str
    risk_score: float
    impact_hypothesis: str
    prerequisites: list[str]
    evidence_needed: list[str]
    safe_validation: list[str]
    reasoning: list[str] = field(default_factory=list)

    def as_classification(self) -> dict[str, object]:
        return {
            "classification": f"attack_candidate:{self.technique}",
            "confidence": self.confidence,
            "risk": self.risk,
            "risk_score": self.risk_score,
            "reasoning": self.reasoning,
            "impact_hypothesis": self.impact_hypothesis,
            "prerequisites": self.prerequisites,
            "evidence_needed": self.evidence_needed,
            "safe_validation": self.safe_validation,
        }


class AttackKnowledgeEngine:
    """Map learned exploit evidence patterns into bounded validation candidates.

    This layer does not execute exploit payloads. It tells the scanner and UI when
    an endpoint looks like a relevant place to run an existing safe validator.
    """

    URL_FETCH_PARAM_RE = re.compile(
        r"(?i)(url|uri|link|image_url|avatar_url|profile_picture_url|callback|webhook|redirect|import|feed)"
    )
    LOGIN_PATH_RE = re.compile(r"(?i)(^|/)(login|signin|sign-in|session|auth)(/|$)")
    USER_FIELD_RE = re.compile(r"(?i)(user(?:name)?|email|login|account)")
    PASSWORD_FIELD_RE = re.compile(r"(?i)pass(?:word)?")
    AMOUNT_FIELD_RE = re.compile(
        r"(?i)(amount|nominal|total|balance|price|quantity|qty|transfer|refund|credit|debit)"
    )
    FINANCIAL_PATH_RE = re.compile(
        r"(?i)(transfer|payment|wallet|balance|topup|withdraw|refund|invoice|billing|transaction)"
    )
    RATE_LIMIT_RE = re.compile(r"(?i)(rate.?limit|quota|throttle|usage|ai/.+status|limit-status)")
    ROLE_HINT_RE = re.compile(r"(?i)(role|admin|authenticated|anonymous|unauthenticated|is_admin)")

    def candidates(self, endpoint: CrawledEndpoint) -> list[AttackTechniqueCandidate]:
        candidates = [
            self._sqli_auth_bypass_candidate(endpoint),
            self._ssrf_url_fetch_candidate(endpoint),
            self._negative_amount_candidate(endpoint),
            self._rate_limit_role_candidate(endpoint),
        ]
        return [candidate for candidate in candidates if candidate is not None]

    def classification_dicts(self, endpoint: CrawledEndpoint) -> list[dict[str, object]]:
        return [candidate.as_classification() for candidate in self.candidates(endpoint)]

    def _sqli_auth_bypass_candidate(
        self, endpoint: CrawledEndpoint
    ) -> AttackTechniqueCandidate | None:
        path = urlparse(endpoint.url).path
        form_fields = self._form_field_names(endpoint)
        query_fields = set(parse_qs(urlparse(endpoint.url).query).keys())
        has_login_path = bool(self.LOGIN_PATH_RE.search(path))
        has_user = any(self.USER_FIELD_RE.search(name) for name in form_fields | query_fields)
        has_password = any(self.PASSWORD_FIELD_RE.search(name) for name in form_fields)
        body_hint = endpoint.response_body_sample[:12000]
        has_json_login = bool(
            has_login_path and re.search(r"(?i)fetch\s*\(|application/json|password", body_hint)
        )

        if not (has_login_path or (has_user and has_password) or has_json_login):
            return None

        score = 58
        reasoning = []
        if has_login_path:
            score += 12
            reasoning.append("Login/session path matches learned SQLi auth-bypass pattern")
        if has_user and has_password:
            score += 18
            reasoning.append("Username/email and password inputs are present")
        if has_json_login:
            score += 8
            reasoning.append("Page hints at JSON login submission")

        return AttackTechniqueCandidate(
            technique="sqli_auth_bypass",
            confidence=min(score, 96),
            risk="high" if score >= 75 else "medium",
            risk_score=min(float(score), 92.0),
            impact_hypothesis=(
                "If authentication SQL is built by string concatenation, a bounded "
                "validation may prove unauthorized authenticated state without dumping data."
            ),
            prerequisites=[
                "Endpoint is in authorized scope",
                "Login flow accepts a username/email and password style credential",
                "Validation must stop at authenticated-state proof",
            ],
            evidence_needed=[
                "Control failed-login response",
                "Validation response that changes authentication state",
                "Optional protected route check using the resulting session",
            ],
            safe_validation=[
                "Use the existing bounded SQLi login validator",
                "Do not enumerate tables, extract rows, or run stacked queries",
                "Store sanitized request/response only",
            ],
            reasoning=reasoning,
        )

    def _ssrf_url_fetch_candidate(
        self, endpoint: CrawledEndpoint
    ) -> AttackTechniqueCandidate | None:
        path = urlparse(endpoint.url).path
        form_fields = self._form_field_names(endpoint)
        query_fields = set(parse_qs(urlparse(endpoint.url).query).keys())
        fields = form_fields | query_fields
        has_url_field = any(self.URL_FETCH_PARAM_RE.search(name) for name in fields)
        path_hint = bool(re.search(r"(?i)(upload|import|avatar|profile|webhook|callback|proxy|fetch|image)", path))

        if not (has_url_field or path_hint):
            return None

        score = 54
        reasoning = []
        if has_url_field:
            score += 22
            reasoning.append("URL-like parameter matches learned SSRF import pattern")
        if path_hint:
            score += 12
            reasoning.append("Path suggests server-side fetch/import behavior")

        return AttackTechniqueCandidate(
            technique="ssrf_url_fetch",
            confidence=min(score, 94),
            risk="high" if score >= 74 else "medium",
            risk_score=min(float(score), 88.0),
            impact_hypothesis=(
                "If the server fetches caller-supplied URLs, it may reach internal or "
                "loopback resources and expose the fetched result in-band."
            ),
            prerequisites=[
                "Endpoint accepts a URL-like value",
                "Validation uses only loopback or operator-approved internal lab targets",
                "No external callback or secret exfiltration is used",
            ],
            evidence_needed=[
                "Request containing the URL-like field",
                "Response showing in-band fetch result or stored internal content",
                "Control response for a benign URL if available",
            ],
            safe_validation=[
                "Use loopback-only or explicitly configured canary endpoints",
                "No external callback or out-of-band exfiltration endpoint",
                "Block cloud metadata and private ranges unless policy explicitly allows a lab target",
                "Stop at in-band proof and redact response content",
            ],
            reasoning=reasoning,
        )

    def _negative_amount_candidate(
        self, endpoint: CrawledEndpoint
    ) -> AttackTechniqueCandidate | None:
        path = urlparse(endpoint.url).path
        form_fields = self._form_field_names(endpoint)
        query_fields = set(parse_qs(urlparse(endpoint.url).query).keys())
        fields = form_fields | query_fields
        has_amount = any(self.AMOUNT_FIELD_RE.search(name) for name in fields)
        financial_path = bool(self.FINANCIAL_PATH_RE.search(path))

        if not (has_amount and financial_path):
            return None

        score = 82 if endpoint.method.upper() != "GET" else 70
        reasoning = [
            "Financial workflow path with amount-like input matches learned business-logic pattern"
        ]
        if endpoint.method.upper() != "GET":
            reasoning.append("State-changing method increases impact relevance")

        return AttackTechniqueCandidate(
            technique="negative_amount_business_logic",
            confidence=min(score, 95),
            risk="high",
            risk_score=min(float(score), 90.0),
            impact_hypothesis=(
                "If negative or malformed amounts are accepted, funds, balances, "
                "refunds, or quantities may move in the reverse direction."
            ),
            prerequisites=[
                "Use only operator-approved test accounts or seeded lab balances",
                "Endpoint performs a financial or quantity-changing operation",
                "Validation can compare before/after state safely",
            ],
            evidence_needed=[
                "Before/after state for both test objects/accounts",
                "Request with bounded non-production amount mutation",
                "After-state proving unexpected reverse movement or accepted invalid value",
            ],
            safe_validation=[
                "Require explicit runtime option for state-changing business-logic validation",
                "Use small bounded values and rollback/reset when possible",
                "Never run against real customer accounts",
            ],
            reasoning=reasoning,
        )

    def _rate_limit_role_candidate(
        self, endpoint: CrawledEndpoint
    ) -> AttackTechniqueCandidate | None:
        haystack = " ".join(
            [
                endpoint.url,
                endpoint.title or "",
                endpoint.response_body_sample[:4000],
            ]
        )
        if not self.RATE_LIMIT_RE.search(haystack):
            return None

        score = 62
        reasoning = ["Endpoint exposes rate-limit/quota state"]
        if self.ROLE_HINT_RE.search(haystack):
            score += 16
            reasoning.append("Response/path mentions role or authenticated-state handling")

        return AttackTechniqueCandidate(
            technique="rate_limit_role_misclassification",
            confidence=min(score, 90),
            risk="medium" if score < 78 else "high",
            risk_score=min(float(score), 82.0),
            impact_hypothesis=(
                "If authenticated and anonymous roles are confused, rate-limit controls "
                "may be bypassed, denied incorrectly, or audited under the wrong identity."
            ),
            prerequisites=[
                "Endpoint returns quota/rate-limit state",
                "Scanner has at least one authenticated context and one anonymous control",
            ],
            evidence_needed=[
                "Authenticated role response",
                "Anonymous role response",
                "Diff showing wrong role label, quota bucket, or enforcement state",
            ],
            safe_validation=[
                "Compare metadata responses only",
                "Do not flood the endpoint to exhaust quota",
                "Record role mismatch as impact only when responses are stable",
            ],
            reasoning=reasoning,
        )

    def _form_field_names(self, endpoint: CrawledEndpoint) -> set[str]:
        names: set[str] = set()
        for form in endpoint.forms:
            for field in form.get("fields", []):
                name = str(field.get("name") or "").strip()
                if name:
                    names.add(name)
        return names
