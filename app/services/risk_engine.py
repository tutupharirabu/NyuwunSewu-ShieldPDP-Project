from dataclasses import dataclass


@dataclass(slots=True)
class RiskResult:
    risk_score: float
    severity: str
    business_impact: str


class RiskPrioritizationEngine:
    def score(
        self,
        *,
        endpoint_risk: float,
        confidence: float,
        has_pii: bool,
        auth_weakness: bool,
        public_exposure: bool,
        compliance_impact_count: int,
    ) -> RiskResult:
        score = endpoint_risk * 0.25 + confidence * 0.35
        if has_pii:
            score += 14
        if auth_weakness:
            score += 12
        if public_exposure:
            score += 8
        score += min(12, compliance_impact_count * 4)
        score = max(0.0, min(100.0, score))

        if score >= 90:
            severity = "critical"
            impact = "Immediate executive attention; likely audit and privacy impact."
        elif score >= 75:
            severity = "high"
            impact = "High-priority remediation; material compliance or customer risk."
        elif score >= 50:
            severity = "medium"
            impact = "Track in remediation roadmap and validate compensating controls."
        elif score >= 25:
            severity = "low"
            impact = "Low business impact; remediate through normal backlog."
        else:
            severity = "info"
            impact = "Informational signal for governance visibility."
        return RiskResult(score, severity, impact)

