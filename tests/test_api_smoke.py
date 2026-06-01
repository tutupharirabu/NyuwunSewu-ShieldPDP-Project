import asyncio

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database.session import AsyncSessionLocal
from app.main import app
from app.models import ComplianceMapping, Finding, Policy, Project, RemediationTracking, Report, Scan, Target, User


def test_health_endpoint_and_bootstrap_login():
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "healthy"

        login = client.post(
            "/auth/login",
            json={
                "email": "admin@nyuwunsewu.local",
                "password": "ChangeMe123!",
                "organization_slug": "default-organization",
            },
        )
        assert login.status_code == 200
        assert login.json()["token_type"] == "bearer"


def test_compliance_intelligence_can_be_scoped_to_one_target():
    async def seed_target_data() -> tuple[str, str]:
        async with AsyncSessionLocal() as session:
            admin = (
                await session.execute(select(User).where(User.email == "admin@nyuwunsewu.local"))
            ).scalar_one()
            project = Project(
                organization_id=admin.organization_id,
                owner_id=admin.id,
                name="Target Scope Regression",
            )
            session.add(project)
            await session.flush()
            policy = Policy(
                organization_id=admin.organization_id,
                project_id=project.id,
                name="Target Scope Policy",
            )
            target_a = Target(
                organization_id=admin.organization_id,
                project_id=project.id,
                base_url="https://alpha.example",
            )
            target_b = Target(
                organization_id=admin.organization_id,
                project_id=project.id,
                base_url="https://beta.example",
            )
            session.add_all([policy, target_a, target_b])
            await session.flush()
            scan_a = Scan(
                organization_id=admin.organization_id,
                project_id=project.id,
                target_id=target_a.id,
                policy_id=policy.id,
                started_by_id=admin.id,
            )
            scan_b = Scan(
                organization_id=admin.organization_id,
                project_id=project.id,
                target_id=target_b.id,
                policy_id=policy.id,
                started_by_id=admin.id,
            )
            session.add_all([scan_a, scan_b])
            await session.flush()
            finding_a = Finding(
                organization_id=admin.organization_id,
                project_id=project.id,
                target_id=target_a.id,
                scan_id=scan_a.id,
                finding_type="bola",
                title="Alpha critical exposure",
                severity="critical",
                confidence=97,
                risk_score=98,
                description="Alpha-only test finding",
                remediation_guidance="Enforce object ownership",
            )
            finding_b = Finding(
                organization_id=admin.organization_id,
                project_id=project.id,
                target_id=target_b.id,
                scan_id=scan_b.id,
                finding_type="pii",
                title="Beta low exposure",
                severity="low",
                confidence=85,
                risk_score=20,
                description="Beta-only test finding",
                remediation_guidance="Minimize response fields",
            )
            session.add_all([finding_a, finding_b])
            await session.flush()
            session.add_all(
                [
                    ComplianceMapping(
                        organization_id=admin.organization_id,
                        finding_id=finding_a.id,
                        framework="UU PDP",
                        article_or_control="Pasal 35",
                        privacy_risk="High",
                        legal_risk="High",
                        business_risk="High",
                    ),
                    ComplianceMapping(
                        organization_id=admin.organization_id,
                        finding_id=finding_b.id,
                        framework="OWASP ASVS",
                        article_or_control="V8",
                        privacy_risk="Low",
                        legal_risk="Low",
                        business_risk="Low",
                    ),
                    RemediationTracking(
                        organization_id=admin.organization_id,
                        finding_id=finding_a.id,
                    ),
                    RemediationTracking(
                        organization_id=admin.organization_id,
                        finding_id=finding_b.id,
                    ),
                    Report(
                        organization_id=admin.organization_id,
                        project_id=project.id,
                        scan_id=scan_a.id,
                        generated_by_id=admin.id,
                        title="Alpha report",
                        report_type="compliance",
                        export_format="html",
                        content="alpha",
                        report_hash="a" * 64,
                    ),
                    Report(
                        organization_id=admin.organization_id,
                        project_id=project.id,
                        scan_id=scan_b.id,
                        generated_by_id=admin.id,
                        title="Beta report",
                        report_type="compliance",
                        export_format="html",
                        content="beta",
                        report_hash="b" * 64,
                    ),
                ]
            )
            await session.commit()
            return target_a.id, target_b.id

    with TestClient(app) as client:
        login = client.post(
            "/auth/login",
            json={
                "email": "admin@nyuwunsewu.local",
                "password": "ChangeMe123!",
                "organization_slug": "default-organization",
            },
        )
        headers = {"authorization": f"Bearer {login.json()['access_token']}"}
        target_a, target_b = asyncio.run(seed_target_data())

        alpha_findings = client.get(f"/findings?target_id={target_a}", headers=headers).json()
        beta_findings = client.get(f"/findings?target_id={target_b}", headers=headers).json()
        assert [finding["title"] for finding in alpha_findings] == ["Alpha critical exposure"]
        assert alpha_findings[0]["created_at"]
        assert [finding["title"] for finding in beta_findings] == ["Beta low exposure"]

        alpha_dashboard = client.get(f"/dashboard?target_id={target_a}", headers=headers).json()
        beta_dashboard = client.get(f"/dashboard?target_id={target_b}", headers=headers).json()
        assert alpha_dashboard["critical_findings"] == 1
        assert beta_dashboard["critical_findings"] == 0

        alpha_mapping = client.get(f"/compliance?target_id={target_a}", headers=headers).json()
        beta_mapping = client.get(f"/compliance?target_id={target_b}", headers=headers).json()
        assert alpha_mapping["mappings"][0]["article_or_control"] == "Pasal 35"
        assert beta_mapping["mappings"][0]["article_or_control"] == "V8"

        alpha_reports = client.get(f"/reports?target_id={target_a}", headers=headers).json()
        alpha_remediations = client.get(f"/remediations?target_id={target_a}", headers=headers).json()
        assert [report["title"] for report in alpha_reports] == ["Alpha report"]
        assert [item["title"] for item in alpha_remediations] == ["Alpha critical exposure"]

        delete_report = client.delete(f"/reports/{alpha_reports[0]['id']}", headers=headers)
        assert delete_report.status_code == 204
        assert client.get(f"/reports?target_id={target_a}", headers=headers).json() == []
        assert client.get(f"/findings?target_id={target_a}", headers=headers).json()[0]["title"] == "Alpha critical exposure"
