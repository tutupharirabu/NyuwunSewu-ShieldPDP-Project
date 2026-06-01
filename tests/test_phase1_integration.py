"""Integration tests for Phase 1: Compliance Mapping, Risk Engine, Data Rights."""

import pytest

from app.compliance.engine import COMPLIANCE_WEIGHTS, ComplianceMappingEngine
from app.services.risk_engine import (
    ComprehensiveRiskResult,
    FinancialExposure,
    FinancialRiskEngine,
    ReputationalRisk,
    RiskPrioritizationEngine,
)

# ── Compliance Engine Tests ──────────────────────────────────────────────


class TestExtendedComplianceMapping:
    def test_pasal_35_still_mapped_for_sqli(self):
        engine = ComplianceMappingEngine()
        impacts = engine.map_finding("sqli")
        pasal_35 = [i for i in impacts if i.article_or_control == "Pasal 35"]
        assert len(pasal_35) == 1

    def test_pasal_46_mapped_for_sqli(self):
        engine = ComplianceMappingEngine()
        impacts = engine.map_finding("sqli")
        pasal_46 = [i for i in impacts if i.article_or_control == "Pasal 46"]
        assert len(pasal_46) == 1

    def test_pasal_57_mapped_for_all_findings(self):
        engine = ComplianceMappingEngine()
        for finding_type in [
            "sqli",
            "bola",
            "path_traversal",
            "pii_exposure",
            "jwt_auth_issue",
            "cors_credentials_misconfiguration",
        ]:
            impacts = engine.map_finding(finding_type)
            pasal_57 = [i for i in impacts if i.article_or_control == "Pasal 57"]
            assert len(pasal_57) == 1, f"Pasal 57 missing for {finding_type}"

    def test_pasal_20_for_auth_issues(self):
        engine = ComplianceMappingEngine()
        impacts = engine.map_finding("jwt_auth_issue")
        pasal_20 = [i for i in impacts if i.article_or_control == "Pasal 20"]
        assert len(pasal_20) == 1

    def test_pasal_22_for_bola_idor(self):
        engine = ComplianceMappingEngine()
        impacts = engine.map_finding("bola")
        pasal_22 = [i for i in impacts if i.article_or_control == "Pasal 22"]
        assert len(pasal_22) == 1

    def test_pasal_67_with_pii_types(self):
        engine = ComplianceMappingEngine()
        impacts = engine.map_finding("sqli", pii_types=["NIK", "NPWP"])
        pasal_67 = [i for i in impacts if i.article_or_control == "Pasal 67"]
        assert len(pasal_67) == 1

    def test_pasal_67_without_pii(self):
        engine = ComplianceMappingEngine()
        impacts = engine.map_finding("sqli")
        pasal_67 = [i for i in impacts if i.article_or_control == "Pasal 67"]
        assert len(pasal_67) == 0

    def test_owasp_asvs_still_mapped(self):
        engine = ComplianceMappingEngine()
        impacts = engine.map_finding("sqli")
        owasp = [i for i in impacts if i.framework == "OWASP ASVS"]
        assert len(owasp) >= 1

    def test_multi_article_count_for_bola_with_pii(self):
        engine = ComplianceMappingEngine()
        impacts = engine.map_finding("bola", pii_types=["email"])
        uu_pdp_impacts = [i for i in impacts if i.framework == "UU PDP"]
        # Pasal 22, 35, 46, 57, 67 = 5 articles
        assert len(uu_pdp_impacts) >= 4

    def test_reflected_html_no_pasal_46(self):
        engine = ComplianceMappingEngine()
        impacts = engine.map_finding("reflected_html")
        pasal_46 = [i for i in impacts if i.article_or_control == "Pasal 46"]
        assert len(pasal_46) == 0

    def test_compliance_weights_exist(self):
        assert "Pasal_20" in COMPLIANCE_WEIGHTS
        assert "Pasal_22" in COMPLIANCE_WEIGHTS
        assert "Pasal_35" in COMPLIANCE_WEIGHTS
        assert "Pasal_46" in COMPLIANCE_WEIGHTS
        assert "Pasal_57" in COMPLIANCE_WEIGHTS
        assert "Pasal_67" in COMPLIANCE_WEIGHTS
        assert COMPLIANCE_WEIGHTS["Pasal_35"] == 2.0

    def test_calculate_compliance_score_no_findings(self):
        engine = ComplianceMappingEngine()
        result = engine.calculate_compliance_score([])
        assert result["overall_score"] == 100.0
        assert result["total_findings"] == 0
        assert result["compliant_articles"] == 6

    def test_calculate_compliance_score_with_findings(self):
        engine = ComplianceMappingEngine()
        findings = [
            {"type": "sqli", "severity": "critical"},
            {"type": "bola", "severity": "high"},
            {"type": "pii_exposure", "severity": "high"},
            {"type": "jwt_auth_issue", "severity": "medium"},
        ]
        result = engine.calculate_compliance_score(findings)
        assert result["overall_score"] < 100.0
        assert result["total_findings"] == 4
        assert result["overall_score"] > 0.0
        # Pasal 35 should be affected
        assert result["article_scores"]["Pasal_35"]["score"] < 100.0


# ── Risk Engine Tests ────────────────────────────────────────────────────


class TestRiskEngineBackwardCompat:
    def test_existing_score_still_works(self):
        engine = RiskPrioritizationEngine()
        result = engine.score(
            endpoint_risk=50.0,
            confidence=0.8,
            has_pii=True,
            auth_weakness=True,
            public_exposure=True,
            compliance_impact_count=3,
        )
        assert 0 <= result.risk_score <= 100
        assert result.severity in ("critical", "high", "medium", "low", "info")
        assert result.business_impact


class TestFinancialExposure:
    def test_no_findings(self):
        engine = FinancialRiskEngine()
        result = engine.calculate_financial_exposure([])
        assert result.max_penalty == 1_000_000_000_000 * 0.02
        assert result.estimated_exposure == 0.0
        assert result.severity_weight == 0.0
        assert result.penalty_per_finding == []

    def test_single_critical_finding(self):
        engine = FinancialRiskEngine()
        result = engine.calculate_financial_exposure(
            [{"finding_type": "sqli", "severity": "critical"}]
        )
        assert result.severity_weight == 1.0
        assert len(result.penalty_per_finding) == 1
        assert result.penalty_per_finding[0]["severity"] == "critical"

    def test_multiple_findings(self):
        engine = FinancialRiskEngine()
        findings = [
            {"finding_type": "sqli", "severity": "critical"},
            {"finding_type": "pii_exposure", "severity": "high"},
            {"finding_type": "cors_misconfig", "severity": "medium"},
        ]
        result = engine.calculate_financial_exposure(findings)
        assert len(result.penalty_per_finding) == 3
        assert result.severity_weight > 0
        assert result.estimated_exposure > 0

    def test_custom_revenue(self):
        engine = FinancialRiskEngine()
        result = engine.calculate_financial_exposure(
            [{"finding_type": "sqli", "severity": "high"}],
            annual_revenue=100_000_000_000,
        )
        assert result.max_penalty == 100_000_000_000 * 0.02


class TestReputationalRisk:
    def test_no_findings(self):
        engine = FinancialRiskEngine()
        result = engine.calculate_reputational_risk([])
        assert result.score == 0
        assert result.level == "minimal"

    def test_critical_findings(self):
        engine = FinancialRiskEngine()
        findings = [
            {"finding_type": "sqli", "severity": "critical"},
            {"finding_type": "bola", "severity": "critical"},
        ]
        result = engine.calculate_reputational_risk(
            findings, has_pii_exposure=True, has_public_exposure=True
        )
        assert result.score >= 76
        assert result.level == "severe"

    def test_pii_exposure_bonus(self):
        engine = FinancialRiskEngine()
        result_with_pii = engine.calculate_reputational_risk([], has_pii_exposure=True)
        result_without_pii = engine.calculate_reputational_risk(
            [], has_pii_exposure=False
        )
        assert result_with_pii.score > result_without_pii.score


class TestComprehensiveAssessment:
    def test_full_assessment(self):
        risk_eng = FinancialRiskEngine()
        tech_eng = RiskPrioritizationEngine()
        findings = [
            {"finding_type": "sqli", "severity": "critical", "confidence": 0.9},
            {"finding_type": "pii_exposure", "severity": "high", "confidence": 0.8},
            {"finding_type": "bola", "severity": "medium", "confidence": 0.7},
        ]
        result = risk_eng.assess_comprehensive(
            findings=findings,
            annual_revenue=1_000_000_000_000,
            has_pii_exposure=True,
            has_public_exposure=True,
            technical_engine=tech_eng,
        )
        assert isinstance(result, ComprehensiveRiskResult)
        assert 0 <= result.technical_score <= 100
        assert 0 <= result.overall_score <= 100
        assert result.financial_exposure.estimated_exposure > 0
        assert result.reputational_risk.level in (
            "minimal",
            "moderate",
            "significant",
            "severe",
        )
        assert len(result.recommended_actions) > 0
        assert "IDR" in result.executive_summary

    def test_no_findings_assessment(self):
        risk_eng = FinancialRiskEngine()
        result = risk_eng.assess_comprehensive(
            findings=[],
            annual_revenue=1_000_000_000_000,
            has_pii_exposure=False,
            has_public_exposure=False,
        )
        assert result.technical_score == 0.0
        assert result.overall_score == 0.0
        assert result.reputational_risk.level == "minimal"
