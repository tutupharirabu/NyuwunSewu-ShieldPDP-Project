"""Severity normalization and finding-scoring helpers for ScanRunner.

Pure, self-contained mapping logic extracted from the runner as a mixin.
"""

from __future__ import annotations

from typing import Any

from app.validation.types import ValidationResult


class _ScoringMixin:
    def _finding_metadata(self, result: ValidationResult) -> dict[str, Any]:
        return {
            "confidence_score": round(float(result.confidence), 1),
            "confidence_level": result.confidence_level,
            "exploitability_assessment": result.exploitability_assessment,
            "reproduction_stability": result.reproduction_stability,
            "evidence_quality": result.evidence_quality,
            "false_positive_likelihood": result.false_positive_likelihood,
        }

    def _normalize_severity(
        self, result: ValidationResult, metadata: dict[str, Any]
    ) -> str:
        requested = (result.severity or "info").lower()
        finding_type = result.finding_type
        confidence = float(result.confidence or 0)
        exploitability = str(metadata.get("exploitability_assessment") or "")
        false_positive_likelihood = str(
            metadata.get("false_positive_likelihood") or "HIGH"
        )

        if confidence < 65 or false_positive_likelihood == "HIGH":
            requested = min(requested, "low", key=self._severity_rank)

        if finding_type in {"jwt_observed", "swagger_metadata", "framework_disclosure"}:
            return "info"
        if finding_type == "protected_internal_surface":
            return "info"
        if finding_type == "internal_api_discovery":
            return (
                "medium" if result.evidence.get("exposed_sensitive_markers") else "low"
            )
        if finding_type == "segmentation_exposure":
            return "low" if requested not in {"info"} else requested
        if finding_type == "graphql_schema_exposure":
            return "medium" if requested in {"critical", "high", "medium"} else "low"
        if finding_type == "client_side_auth_token_storage":
            return "medium"
        if finding_type == "modern_vuln_bank_attack_surface":
            return "low"
        if finding_type == "jwt_weakness":
            return (
                "high"
                if result.evidence.get("alg_none")
                or result.evidence.get("unsigned_token_accepted")
                else "medium"
            )
        if finding_type == "sqli":
            return (
                "high"
                if confidence >= 90
                and result.evidence.get("confirmed_signal_count", 0) >= 2
                else "medium"
            )
        if finding_type == "sqli_auth_bypass":
            return (
                "critical"
                if confidence >= 95 and exploitability == "CONFIRMED_EXPLOIT"
                else "high"
            )
        if finding_type in {
            "jwt_privilege_escalation_execution",
            "jwt_claim_integrity_bypass",
            "jwt_forge_endpoint_exposed",
        }:
            return (
                "critical"
                if exploitability == "CONFIRMED_EXPLOIT" and confidence >= 95
                else "high"
            )
        if finding_type in {
            "unauthenticated_sensitive_api_exposure",
            "cors_credentials_misconfiguration",
            "oauth_open_redirect_authorization_code_theft",
            "access_control_matrix",
            "missing_authorization",
            "bola_idor",
        }:
            return "high" if confidence >= 85 else "medium"
        return requested

    def _severity_rank(self, severity: str) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
            severity, 0
        )

    def _severity_score_cap(self, severity: str) -> float:
        return {
            "critical": 100.0,
            "high": 89.0,
            "medium": 74.0,
            "low": 49.0,
            "info": 24.0,
        }.get(severity, 24.0)

    def _business_impact(self, severity: str, metadata: dict[str, Any]) -> str:
        if severity == "critical":
            return "Immediate executive attention; confirmed exploitability with replayable evidence."
        if severity == "high":
            return "High-priority remediation; validated exposure with material security or privacy impact."
        if severity == "medium":
            return "Track in remediation roadmap; evidence indicates a bounded security weakness."
        if severity == "low":
            return "Attack surface or hardening signal; review through normal backlog."
        return "Informational signal for governance visibility."

