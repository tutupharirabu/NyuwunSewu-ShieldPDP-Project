import re
from urllib.parse import urlparse

from app.recon import CrawledEndpoint
from app.validation.types import ValidationResult


class DiscoveryValidationService:
    INTERNAL_ROUTE_RE = re.compile(
        r"(?i)(/internal|/private|/admin|/debug|/actuator|/metrics|/graphql|/staging|/dev|/test)"
    )
    INTERNAL_HOST_RE = re.compile(
        r"(?i)\b(?:[a-z0-9-]+\.)*(?:internal|corp|local|lan|staging|dev)\b|"
        r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|"
        r"\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b|"
        r"\b192\.168\.\d{1,3}\.\d{1,3}\b"
    )
    SENSITIVE_INTERNAL_RE = re.compile(
        r"(?i)(debug|stack trace|exception|secret|api[_-]?key|password|token|admin|internal config|database)"
    )

    def internal_api_finding(self, endpoint: CrawledEndpoint) -> ValidationResult | None:
        parsed = urlparse(endpoint.url)
        signals: list[str] = []
        if self.INTERNAL_ROUTE_RE.search(parsed.path):
            signals.append("Endpoint path matches internal/admin/debug API routing patterns")
        if "graphql" in endpoint.response_body_sample.lower() or parsed.path.lower().endswith("/graphql"):
            signals.append("GraphQL route or response marker discovered")
        if not signals:
            return None
        protected = endpoint.status_code in {401, 403}
        exposed_sensitive = endpoint.status_code == 200 and bool(
            self.SENSITIVE_INTERNAL_RE.search(endpoint.response_body_sample[:12000])
        )
        if protected:
            return ValidationResult(
                finding_type="protected_internal_surface",
                title="Protected Internal Surface",
                severity="info",
                confidence=68.0,
                endpoint=endpoint.url,
                description=(
                    "Recon identified an internal, admin, debug, or operational route, but the "
                    "endpoint returned an authorization boundary rather than exploitable access."
                ),
                reasoning=[*signals, f"Endpoint returned HTTP {endpoint.status_code}"],
                evidence={
                    "validation_mode": "passive_endpoint_discovery",
                    "path": parsed.path,
                    "status_code": endpoint.status_code,
                    "content_type": endpoint.content_type,
                    "protected": True,
                    "payload": None,
                },
                remediation="Keep authorization enforced and review whether the route should be externally discoverable.",
                exploitability_assessment="ATTACK_SURFACE_IDENTIFIED",
                evidence_quality="LOW",
                false_positive_likelihood="MEDIUM",
            )
        return ValidationResult(
            finding_type="internal_api_discovery",
            title=(
                "Exposed Sensitive Internal Surface"
                if exposed_sensitive
                else "Attack Surface Identified: Internal or Undocumented API"
            ),
            severity="medium" if exposed_sensitive else "low",
            confidence=84.0 if exposed_sensitive else 70.0,
            endpoint=endpoint.url,
            description=(
                "Recon discovered an API route with internal, admin, debug, staging, or operational "
                "characteristics. Endpoint existence alone is tracked as attack surface, not proof of exploitability."
            ),
            reasoning=signals,
            evidence={
                "validation_mode": "passive_endpoint_discovery",
                "path": parsed.path,
                "status_code": endpoint.status_code,
                "content_type": endpoint.content_type,
                "exposed_sensitive_markers": exposed_sensitive,
                "payload": None,
            },
            remediation=(
                "Confirm the endpoint is intended for this exposure level. Require authentication, "
                "role checks, and remove debug or staging routes from production."
            ),
            exploitability_assessment="ATTACK_SURFACE_IDENTIFIED",
            evidence_quality="LOW" if not exposed_sensitive else "MEDIUM",
            false_positive_likelihood="MEDIUM" if exposed_sensitive else "HIGH",
        )

    def segmentation_finding(self, endpoint: CrawledEndpoint) -> ValidationResult | None:
        matches = sorted(set(match.group(0) for match in self.INTERNAL_HOST_RE.finditer(endpoint.response_body_sample)))
        if not matches:
            return None
        return ValidationResult(
            finding_type="segmentation_exposure",
            title="Attack Surface Identified: Internal Service Metadata",
            severity="low",
            confidence=72.0,
            endpoint=endpoint.url,
            description=(
                "The response disclosed internal hostnames, environment labels, or private network "
                "addresses. This is tracked as attack surface metadata unless paired with exploitable access."
            ),
            reasoning=["Internal network or environment metadata was present in response content"],
            evidence={
                "validation_mode": "passive_metadata_discovery",
                "leaked_indicators": matches[:20],
                "payload": None,
            },
            remediation=(
                "Remove internal routing metadata from client-facing responses and verify network "
                "segmentation between public, staging, and internal services."
            ),
            exploitability_assessment="ATTACK_SURFACE_IDENTIFIED",
            evidence_quality="LOW",
            false_positive_likelihood="MEDIUM",
        )
