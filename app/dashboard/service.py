from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, FindingStatus, Severity


class DashboardService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def overview(self, organization_id: str, target_id: str | None = None) -> dict:
        scope = [Finding.organization_id == organization_id]
        if target_id:
            scope.append(Finding.target_id == target_id)

        total_findings = await self._count(*scope)
        open_findings = await self._count(
            *scope,
            Finding.status != FindingStatus.CLOSED.value,
            Finding.is_false_positive.is_(False),
        )
        critical_findings = await self._count(
            *scope,
            Finding.severity == Severity.CRITICAL.value,
            Finding.status != FindingStatus.CLOSED.value,
            Finding.is_false_positive.is_(False),
            Finding.confidence >= 70,
        )
        closed = await self._count(
            *scope,
            Finding.status == FindingStatus.CLOSED.value,
        )
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

    async def _count(self, *criteria) -> int:
        result = await self.session.execute(select(func.count(Finding.id)).where(*criteria))
        return int(result.scalar_one())
