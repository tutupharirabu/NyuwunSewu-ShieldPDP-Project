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
        },
    )

    assert "Affected Items / Discovered Paths" in html
    assert "/admin?debug=1" in html
    assert "Confirmed Exploits and Attack Chains" in html
    assert "scoped_jwt_privilege_execution" in html
    assert "OWASP ASVS" in html


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
