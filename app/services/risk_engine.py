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


@dataclass(slots=True)
class FinancialExposure:
    max_penalty: float
    estimated_exposure: float
    penalty_per_finding: list
    severity_weight: float


@dataclass(slots=True)
class ReputationalRisk:
    score: float
    level: str
    factors: list[str]
    customer_impact: str


@dataclass(slots=True)
class ComprehensiveRiskResult:
    technical_score: float
    technical_severity: str
    financial_exposure: FinancialExposure
    reputational_risk: ReputationalRisk
    overall_score: float
    overall_severity: str
    executive_summary: str
    recommended_actions: list[str]


_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}


class FinancialRiskEngine:
    def calculate_financial_exposure(
        self,
        findings: list[dict],
        annual_revenue: float = 1_000_000_000_000,
    ) -> FinancialExposure:
        if not findings:
            return FinancialExposure(
                max_penalty=annual_revenue * 0.02,
                estimated_exposure=0.0,
                penalty_per_finding=[],
                severity_weight=0.0,
            )

        max_penalty = annual_revenue * 0.02
        penalty_per_finding = []
        weighted_sum = 0.0

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            weight = _SEVERITY_WEIGHTS.get(severity, 0.1)
            individual_exposure = max_penalty * weight
            penalty_per_finding.append(
                {
                    "finding_type": finding.get("finding_type", "unknown"),
                    "severity": severity,
                    "individual_exposure": individual_exposure,
                }
            )
            weighted_sum += weight

        severity_weight = weighted_sum / len(findings)
        finding_count = len(findings)
        estimated_exposure = (
            max_penalty * severity_weight * min(1.0, finding_count / 10)
        )

        return FinancialExposure(
            max_penalty=max_penalty,
            estimated_exposure=estimated_exposure,
            penalty_per_finding=penalty_per_finding,
            severity_weight=severity_weight,
        )

    def calculate_reputational_risk(
        self,
        findings: list[dict],
        has_pii_exposure: bool = False,
        has_public_exposure: bool = False,
    ) -> ReputationalRisk:
        score = 0.0
        factors: list[str] = []
        has_critical = False
        has_high = False

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity == "critical":
                score += 25
                has_critical = True
            elif severity == "high":
                score += 15
                has_high = True
            elif severity == "medium":
                score += 8

        if has_pii_exposure:
            score += 20
        if has_public_exposure:
            score += 15

        score = min(100.0, score)

        if has_critical:
            factors.append("Critical severity findings detected")
        if has_pii_exposure:
            factors.append("Personal data exposure confirmed")
        if has_public_exposure:
            factors.append("Publicly accessible attack surface")
        if has_high:
            factors.append("High severity findings present")

        if score >= 76:
            level = "severe"
            customer_impact = "Likely customer notification required; potential loss of trust and regulatory scrutiny."
        elif score >= 51:
            level = "significant"
            customer_impact = "Customer confidence may be affected; proactive communication recommended."
        elif score >= 26:
            level = "moderate"
            customer_impact = "Limited customer impact; monitor for escalation."
        else:
            level = "minimal"
            customer_impact = "Negligible direct customer impact."

        return ReputationalRisk(
            score=score,
            level=level,
            factors=factors,
            customer_impact=customer_impact,
        )

    def assess_comprehensive(
        self,
        *,
        findings: list[dict],
        annual_revenue: float = 1_000_000_000_000,
        has_pii_exposure: bool = False,
        has_public_exposure: bool = False,
        technical_engine: RiskPrioritizationEngine | None = None,
    ) -> ComprehensiveRiskResult:
        # Determine technical score and severity
        if technical_engine is not None and findings:
            # Build a representative technical score from findings
            # Use average endpoint_risk-like signal from confidence values
            avg_confidence = sum(f.get("confidence", 0.5) for f in findings) / len(
                findings
            )
            avg_compliance = len(
                [f for f in findings if f.get("severity") in ("critical", "high")]
            )
            # Infer endpoint_risk as an average severity-weighted signal
            severity_signal = sum(
                _SEVERITY_WEIGHTS.get(f.get("severity", "info").lower(), 0.1)
                for f in findings
            ) / len(findings)
            tech_result = technical_engine.score(
                endpoint_risk=severity_signal,
                confidence=avg_confidence,
                has_pii=has_pii_exposure,
                auth_weakness=any(
                    f.get("severity", "info").lower() in ("critical", "high")
                    for f in findings
                ),
                public_exposure=has_public_exposure,
                compliance_impact_count=avg_compliance,
            )
            technical_score = tech_result.risk_score
            technical_severity = tech_result.severity
        else:
            if findings:
                avg_weight = sum(
                    _SEVERITY_WEIGHTS.get(f.get("severity", "info").lower(), 0.1)
                    for f in findings
                ) / len(findings)
                technical_score = avg_weight * 100
            else:
                technical_score = 0.0
            if technical_score >= 90:
                technical_severity = "critical"
            elif technical_score >= 75:
                technical_severity = "high"
            elif technical_score >= 50:
                technical_severity = "medium"
            elif technical_score >= 25:
                technical_severity = "low"
            else:
                technical_severity = "info"

        financial_exposure = self.calculate_financial_exposure(findings, annual_revenue)
        reputational_risk = self.calculate_reputational_risk(
            findings, has_pii_exposure, has_public_exposure
        )

        overall_score = (
            technical_score * 0.4
            + (financial_exposure.severity_weight * 100) * 0.35
            + reputational_risk.score * 0.25
        )

        if overall_score >= 90:
            overall_severity = "critical"
        elif overall_score >= 75:
            overall_severity = "high"
        elif overall_score >= 50:
            overall_severity = "medium"
        elif overall_score >= 25:
            overall_severity = "low"
        else:
            overall_severity = "info"

        # Build executive summary
        critical_count = sum(
            1 for f in findings if f.get("severity", "info").lower() == "critical"
        )
        exposure = financial_exposure.estimated_exposure
        exec_summary = (
            f"Critical risk: {critical_count} critical findings with "
            f"IDR {exposure:,.0f} estimated exposure and "
            f"{reputational_risk.level} reputational impact."
        )

        # Build recommended actions
        actions: list[str] = []

        high_count = sum(
            1 for f in findings if f.get("severity", "info").lower() == "high"
        )

        if critical_count > 0:
            actions.append(
                f"Immediately address {critical_count} critical findings with data breach potential"
            )
        if high_count > 0:
            actions.append(
                f"Remediate {high_count} high-severity findings within 30 days"
            )
        if has_pii_exposure:
            actions.append(
                "Implement enhanced data protection controls for personal data"
            )
        if financial_exposure.estimated_exposure > 0:
            actions.append(
                f"Engage legal team for UU PDP compliance review "
                f"(potential exposure: IDR {financial_exposure.estimated_exposure:,.0f})"
            )
        actions.append("Schedule follow-up assessment after remediation")

        return ComprehensiveRiskResult(
            technical_score=technical_score,
            technical_severity=technical_severity,
            financial_exposure=financial_exposure,
            reputational_risk=reputational_risk,
            overall_score=overall_score,
            overall_severity=overall_severity,
            executive_summary=exec_summary,
            recommended_actions=actions,
        )
