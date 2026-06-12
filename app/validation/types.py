from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class HttpObservation:
    url: str
    method: str
    status_code: int
    elapsed_ms: float
    headers: dict[str, str]
    body_sample: str
    content_length: int
    request_headers: dict[str, str] = field(default_factory=dict)
    http_version: str = "HTTP/1.1"
    response_reason: str = ""


@dataclass(slots=True)
class ValidationResult:
    finding_type: str
    title: str
    severity: str
    confidence: float
    endpoint: str
    description: str
    reasoning: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)
    dbms: str | None = None
    remediation: str = ""
    pii_types: list[str] = field(default_factory=list)
    request_method: str | None = None
    request_url: str | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str | None = None
    http_version: str = "HTTP/1.1"
    response_reason: str = ""
    confidence_level: str = ""
    exploitability_assessment: str = ""
    reproduction_stability: str = ""
    evidence_quality: str = ""
    false_positive_likelihood: str = ""

    def __post_init__(self) -> None:
        self.confidence_level = self.confidence_level or confidence_level(self.confidence)
        self.evidence_quality = self.evidence_quality or evidence_quality(
            confidence=self.confidence,
            has_replayable_request=bool(self.request_url or self.request_body),
            validation_mode=str(self.evidence.get("validation_mode") or ""),
        )
        self.reproduction_stability = self.reproduction_stability or reproduction_stability(
            validation_mode=str(self.evidence.get("validation_mode") or ""),
            confidence_level=self.confidence_level,
            has_replayable_request=bool(self.request_url or self.request_body),
        )
        self.exploitability_assessment = self.exploitability_assessment or exploitability_assessment(
            self.finding_type,
            self.evidence,
        )
        self.false_positive_likelihood = self.false_positive_likelihood or false_positive_likelihood(
            confidence=self.confidence,
            evidence_quality=self.evidence_quality,
            exploitability=self.exploitability_assessment,
        )


@dataclass(slots=True)
class ReductionDecision:
    accepted: bool
    confidence: float
    anomaly_score: float
    reasoning: list[str]


def confidence_level(score: float) -> str:
    if score >= 95:
        return "CONFIRMED"
    if score >= 85:
        return "HIGH_CONFIDENCE"
    if score >= 65:
        return "SUSPECTED"
    return "LOW_CONFIDENCE"


def evidence_quality(
    *,
    confidence: float,
    has_replayable_request: bool,
    validation_mode: str,
) -> str:
    active_modes = (
        "validation",
        "probe",
        "execution",
        "comparison",
        "negative_control",
        "mutation",
        "origin_reflection",
    )
    if has_replayable_request and confidence >= 85 and any(token in validation_mode for token in active_modes):
        return "HIGH"
    if confidence >= 70 and (has_replayable_request or validation_mode):
        return "MEDIUM"
    return "LOW"


def reproduction_stability(
    *,
    validation_mode: str,
    confidence_level: str,
    has_replayable_request: bool,
) -> str:
    if "bounded" in validation_mode or "comparison" in validation_mode or "mutation" in validation_mode:
        return "BOUNDED_RETEST"
    if confidence_level == "CONFIRMED" and has_replayable_request:
        return "REPLAYABLE"
    if has_replayable_request:
        return "SINGLE_OBSERVATION"
    return "PASSIVE_ONLY"


def exploitability_assessment(finding_type: str, evidence: dict[str, Any]) -> str:
    confirmed_exploit_types = {
        "jwt_privilege_escalation_execution",
        "jwt_claim_integrity_bypass",
        "jwt_forge_endpoint_exposed",
        "sqli_auth_bypass",
        "sqli_confirmed",
        "ssrf_inband_url_fetch",
        "negative_amount_business_logic",
    }
    validated_exposure_types = {
        "unauthenticated_sensitive_api_exposure",
        "bola_idor",
        "access_control_matrix",
        "missing_authorization",
        "path_traversal",
        "reflected_html_injection",
        "pii_exposure",
        "authentication_cookie_protection",
        "client_side_auth_token_storage",
        "oauth_open_redirect_authorization_code_theft",
        "cors_credentials_misconfiguration",
        "rate_limit_role_misclassification",
    }
    attack_surface_types = {
        "internal_api_discovery",
        "segmentation_exposure",
        "graphql_schema_exposure",
        "modern_vuln_bank_attack_surface",
    }
    if finding_type in confirmed_exploit_types:
        return "CONFIRMED_EXPLOIT"
    if evidence.get("authentication_bypass_signal") or evidence.get("attack_status") in {200, 201, 202}:
        return "CONFIRMED_EXPLOIT"
    if finding_type in validated_exposure_types:
        return "VALIDATED_EXPOSURE"
    if finding_type in attack_surface_types:
        return "ATTACK_SURFACE_IDENTIFIED"
    return "HEURISTIC_SIGNAL"


def false_positive_likelihood(
    *,
    confidence: float,
    evidence_quality: str,
    exploitability: str,
) -> str:
    if confidence >= 90 and evidence_quality == "HIGH" and exploitability in {
        "CONFIRMED_EXPLOIT",
        "VALIDATED_EXPOSURE",
    }:
        return "LOW"
    if confidence >= 70 and evidence_quality in {"HIGH", "MEDIUM"}:
        return "MEDIUM"
    return "HIGH"
