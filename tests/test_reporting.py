from datetime import datetime, timezone
from types import SimpleNamespace

from app.reporting.engine import ReportingEngine


def test_report_html_includes_scan_paths_exploits_and_compliance():
    engine = ReportingEngine()
    endpoint = SimpleNamespace(
        id="endpoint-1",
        url="https://example.com/admin?debug=1",
        method="GET",
        normalized_path="/admin",
        status_code=200,
        content_type="text/html",
        query_parameters=["debug"],
        forms=[],
        tech_stack=["access:authenticated"],
        classifications=[{"classification": "admin_interface"}],
        risk_score=87.0,
        created_at=datetime.now(timezone.utc),
    )
    finding = SimpleNamespace(
        id="finding-1",
        endpoint_id="endpoint-1",
        title="JWT Claim Manipulation Executed Privileged Access",
        finding_type="jwt_privilege_escalation_execution",
        severity="critical",
        status="Open",
        confidence=98.0,
        risk_score=94.0,
        description="Admin route accepted a manipulated JWT.",
        reasoning=["is_admin was changed to true", "Admin route returned HTTP 200"],
        evidence_summary={"validation_mode": "scoped_jwt_privilege_execution", "attack_status": 200},
        compliance=[
            {
                "framework": "OWASP ASVS",
                "article_or_control": "V2",
                "privacy_risk": "Unauthorized access",
                "legal_risk": "Access control weakness",
                "business_risk": "Account takeover",
            }
        ],
        remediation_guidance="Verify JWT signatures and load authorization server-side.",
        created_at=datetime.now(timezone.utc),
    )
    evidence = SimpleNamespace(
        immutable_id="evd_test",
        evidence_hash="abc123",
        raw_request={
            "method": "GET",
            "url": "https://example.com/admin?debug=1",
            "http_version": "HTTP/1.1",
            "headers": {
                "user-agent": "NyuwunSewu-MVP/1.0",
                "authorization": "Bearer secret.jwt.token",
            },
            "body": "",
        },
        raw_response={
            "status": 200,
            "reason": "OK",
            "http_version": "HTTP/1.1",
            "headers": {"content-type": "text/html; charset=utf-8"},
            "body_sample": "<title>Admin Panel</title>",
        },
    )

    html = engine.render_html(
        title="NyuwunSewu Technical Report",
        findings=[finding],
        report_type="Technical Report",
        context={
            "project": SimpleNamespace(id="project-1", name="Example"),
            "target": SimpleNamespace(base_url="https://example.com", allowed_domains=["example.com"]),
            "scan": SimpleNamespace(
                id="scan-1",
                status="completed",
                started_at=None,
                finished_at=None,
                created_at=None,
                error=None,
                stats={},
            ),
            "policy": SimpleNamespace(
                name="Lab Policy",
                max_requests_per_second=5,
                max_depth=2,
                max_pages=100,
                allow_sqli_validation=True,
                allow_auth_validation=True,
                allow_timing_validation=False,
                excluded_paths=[],
                forbidden_paths=[],
                scope_boundaries=[],
            ),
            "generated_by": SimpleNamespace(email="tester@example.com"),
            "endpoints": [endpoint],
            "evidence_by_finding_id": {"finding-1": evidence},
        },
    )

    assert "Affected Items / Discovered Paths" in html
    assert "/admin?debug=1" in html
    assert "Confirmed Exploits and Attack Chains" in html
    assert "scoped_jwt_privilege_execution" in html
    assert "OWASP ASVS" in html
    assert "Evidence Summary" not in html
    assert "HTTP Evidence Request" in html
    assert "GET /admin?debug=1 HTTP/1.1" in html
    assert "authorization: [REDACTED]" in html
    assert "HTTP Evidence Response" in html
    assert "HTTP/1.1 200 OK" in html
    assert "Compliance Analysis" in html
    assert "EXECUTIVE RISK SUMMARY" in html
    assert "POTENTIAL DATA PROTECTION IMPACT" in html
    assert "Authentication Tokens" in html
    assert "BUSINESS IMPACT" in html
    assert "AFFECTED ASSETS" in html
    assert "COMPLIANCE GAP ANALYSIS" in html
    assert "REGULATORY & CONTROL ANALYSIS" in html
    assert "ISO/IEC 27001:2022" in html
    assert "Annex A 8.5 Secure Authentication" in html
    assert "ATTACK SCENARIO" in html
    assert "WORST CASE SCENARIO" in html
    assert "COMPLIANCE CONFIDENCE" in html
    assert "REMEDIATION PRIORITY" in html
    assert "Data breach occurred" not in html
    assert "Data was stolen" not in html
    assert "Personal data was exposed" not in html
    assert "Contoh Code Aman" in html


def test_report_pdf_is_multisection_pdf_document():
    engine = ReportingEngine()
    pdf = engine.render_pdf_from_context(
        title="NyuwunSewu Executive Summary",
        findings=[],
        report_type="Executive Summary",
        context={"endpoints": []},
    ).encode("latin-1")

    assert pdf.startswith(b"%PDF-1.4")
    assert b"Executive Summary" in pdf
    assert b"Affected Items" in pdf


def test_report_pdf_includes_same_http_evidence_sections():
    engine = ReportingEngine()
    finding = SimpleNamespace(
        id="finding-1",
        endpoint_id=None,
        title="JWT Claim Manipulation Executed Privileged Access",
        finding_type="jwt_privilege_escalation_execution",
        severity="critical",
        status="Open",
        confidence=98.0,
        risk_score=94.0,
        description="Admin route accepted a manipulated JWT.",
        reasoning=["is_admin was changed to true", "Admin route returned HTTP 200"],
        evidence_summary={"validation_mode": "scoped_jwt_privilege_execution"},
        compliance=[],
        remediation_guidance="Verify JWT signatures and load authorization server-side.",
        created_at=datetime.now(timezone.utc),
    )
    evidence = SimpleNamespace(
        immutable_id="evd_test",
        evidence_hash="abc123",
        raw_request={
            "method": "GET",
            "url": "https://example.com/admin",
            "http_version": "HTTP/1.1",
            "headers": {"host": "example.com"},
            "body": "",
        },
        raw_response={
            "status": 200,
            "reason": "OK",
            "http_version": "HTTP/1.1",
            "headers": {"content-type": "text/html"},
            "body_sample": "Admin Panel",
        },
    )

    pdf = engine.render_pdf_from_context(
        title="NyuwunSewu Technical Report",
        findings=[finding],
        report_type="Technical Report",
        context={"endpoints": [], "evidence_by_finding_id": {"finding-1": evidence}},
    )

    assert "%PDF-1.4" in pdf
    assert "HTTP Evidence Request" in pdf
    assert "GET /admin HTTP/1.1" in pdf
    assert "HTTP Evidence Response" in pdf
    assert "HTTP/1.1 200 OK" in pdf
    assert "Potential Data Protection Impact" in pdf
    assert "Business Impact" in pdf
    assert "Compliance Gap Analysis" in pdf
    assert "Regulatory and Control Analysis" in pdf
    assert "ISO/IEC 27001:2022" in pdf
    assert "Attack Scenario" in pdf
    assert "Worst Case Scenario" in pdf
    assert "Compliance Confidence" in pdf
    assert "Remediation Priority" in pdf
