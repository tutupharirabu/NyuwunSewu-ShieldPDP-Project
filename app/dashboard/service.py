from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, FindingStatus, Severity


class DashboardService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def overview(self, organization_id: str, target_id: str | None = None) -> dict:
        scope = [Finding.organization_id == organization_id]
        if target_id:
            scope.append(Finding.target_id == target_id)

        not_closed = Finding.status != FindingStatus.CLOSED.value
        not_fp = Finding.is_false_positive.is_(False)
        open_pred = and_(not_closed, not_fp)
        critical_pred = and_(
            Finding.severity == Severity.CRITICAL.value,
            not_closed,
            not_fp,
            Finding.confidence >= 70,
        )
        closed_pred = Finding.status == FindingStatus.CLOSED.value

        # Single round-trip for all four counts via conditional aggregation
        # (was four sequential COUNT queries). COUNT(CASE WHEN pred THEN 1) is
        # portable across SQLite and Postgres; the unmatched branch is NULL and
        # therefore not counted.
        total_findings, open_findings, critical_findings, closed = (
            await self.session.execute(
                select(
                    func.count(Finding.id),
                    func.count(case((open_pred, 1))),
                    func.count(case((critical_pred, 1))),
                    func.count(case((closed_pred, 1))),
                ).where(*scope)
            )
        ).one()
        compliance_score = 100 if total_findings == 0 else max(0, round(100 - open_findings * 6 - critical_findings * 12))
        security_score = 100 if total_findings == 0 else max(0, round(100 - open_findings * 5 - critical_findings * 15))
        remediation_progress = 100 if total_findings == 0 else round((closed / total_findings) * 100)

        result = await self.session.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(*scope)
            .group_by(Finding.severity)
        )
        severity_breakdown = {severity: count for severity, count in result.all()}

        return {
            "compliance_score": compliance_score,
            "security_score": security_score,
            "unresolved_findings": open_findings,
            "critical_findings": critical_findings,
            "remediation_progress": remediation_progress,
            "severity_breakdown": severity_breakdown,
        }
