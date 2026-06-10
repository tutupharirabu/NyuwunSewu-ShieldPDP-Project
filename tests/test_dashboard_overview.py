"""Characterization test for DashboardService.overview.

Locks the aggregate numbers before the 5-sequential-query implementation is
collapsed into a single conditional-aggregation query (request-burden cleanup).
"""

import asyncio

from app.database.session import get_sessionmaker
from app.models import Finding


def _finding(org, **kw):
    base = dict(
        organization_id=org,
        project_id="p",
        target_id="t",
        scan_id="s",
        finding_type="x",
        title="t",
        description="d",
        remediation_guidance="r",
        severity="info",
        status="Open",
        confidence=100.0,
        is_false_positive=False,
    )
    base.update(kw)
    return Finding(**base)


def test_overview_aggregates():
    from app.dashboard.service import DashboardService

    org = "dash-test-org"

    async def _run():
        async with get_sessionmaker()() as session:
            session.add_all(
                [
                    _finding(org, severity="critical", confidence=90.0, status="Open"),
                    _finding(org, severity="high", status="Open"),
                    # critical but low confidence -> not counted as critical
                    _finding(org, severity="critical", confidence=50.0, status="Open"),
                    # closed
                    _finding(org, severity="low", status="Closed"),
                    # false positive -> excluded from open/critical
                    _finding(
                        org,
                        severity="critical",
                        confidence=95.0,
                        status="Open",
                        is_false_positive=True,
                    ),
                ]
            )
            await session.commit()

        async with get_sessionmaker()() as session:
            data = await DashboardService(session).overview(org)

        assert data["unresolved_findings"] == 3  # 2 open + 1 low-conf critical
        assert data["critical_findings"] == 1  # only the conf>=70, non-fp critical
        assert data["remediation_progress"] == 20  # 1 closed / 5 total
        assert data["severity_breakdown"]["critical"] == 3
        assert data["severity_breakdown"]["high"] == 1
        assert data["severity_breakdown"]["low"] == 1
        # 100 - open*6 - critical*12 ; 100 - open*5 - critical*15
        assert data["compliance_score"] == 70
        assert data["security_score"] == 70

    asyncio.run(_run())
