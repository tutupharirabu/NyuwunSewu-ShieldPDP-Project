from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AuditLog,
    Endpoint,
    Finding,
    Organization,
    Policy,
    Project,
    RemediationTracking,
    Report,
    Role,
    Scan,
    Target,
    User,
)


class DomainRepository:
    """Focused repository methods that enforce tenant-scoped lookups."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def role_by_name(self, name: str) -> Role | None:
        result = await self.session.execute(select(Role).where(Role.name == name))
        return result.scalar_one_or_none()

    async def user_by_email(self, email: str, organization_id: str | None = None) -> User | None:
        stmt = select(User).where(User.email == email)
        if organization_id is not None:
            stmt = stmt.where(User.organization_id == organization_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def org_by_slug(self, slug: str) -> Organization | None:
        result = await self.session.execute(select(Organization).where(Organization.slug == slug))
        return result.scalar_one_or_none()

    async def project_for_org(self, project_id: str, organization_id: str) -> Project | None:
        result = await self.session.execute(
            select(Project).where(Project.id == project_id, Project.organization_id == organization_id)
        )
        return result.scalar_one_or_none()

    async def target_for_org(self, target_id: str, organization_id: str) -> Target | None:
        result = await self.session.execute(
            select(Target).where(Target.id == target_id, Target.organization_id == organization_id)
        )
        return result.scalar_one_or_none()

    async def policy_for_org(self, policy_id: str, organization_id: str) -> Policy | None:
        result = await self.session.execute(
            select(Policy).where(Policy.id == policy_id, Policy.organization_id == organization_id)
        )
        return result.scalar_one_or_none()

    async def scan_for_org(self, scan_id: str, organization_id: str) -> Scan | None:
        result = await self.session.execute(
            select(Scan).where(Scan.id == scan_id, Scan.organization_id == organization_id)
        )
        return result.scalar_one_or_none()

    async def findings_for_org(
        self,
        organization_id: str,
        project_id: str | None = None,
        scan_id: str | None = None,
        target_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Finding]:
        stmt = select(Finding).where(Finding.organization_id == organization_id)
        if project_id:
            stmt = stmt.where(Finding.project_id == project_id)
        if scan_id:
            stmt = stmt.where(Finding.scan_id == scan_id)
        if target_id:
            stmt = stmt.where(Finding.target_id == target_id)
        if status:
            stmt = stmt.where(Finding.status == status)
        result = await self.session.execute(
            stmt.order_by(desc(Finding.risk_score), desc(Finding.created_at))
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def reports_for_org(
        self,
        organization_id: str,
        project_id: str | None = None,
        target_id: str | None = None,
        limit: int = 50,
    ) -> list[Report]:
        stmt = select(Report).where(Report.organization_id == organization_id)
        if project_id:
            stmt = stmt.where(Report.project_id == project_id)
        if target_id:
            stmt = stmt.join(Scan, Scan.id == Report.scan_id).where(
                Scan.target_id == target_id,
                Scan.organization_id == organization_id,
            )
        result = await self.session.execute(stmt.order_by(desc(Report.created_at)).limit(limit))
        return list(result.scalars().all())

    async def latest_audit_hash(self) -> str | None:
        result = await self.session.execute(
            select(AuditLog.entry_hash).order_by(desc(AuditLog.timestamp)).limit(1)
        )
        return result.scalar_one_or_none()

    async def endpoints_for_scan(self, scan_id: str, organization_id: str) -> list[Endpoint]:
        result = await self.session.execute(
            select(Endpoint).where(
                Endpoint.scan_id == scan_id, Endpoint.organization_id == organization_id
            )
        )
        return list(result.scalars().all())

    async def remediation_for_finding(
        self, finding_id: str, organization_id: str
    ) -> RemediationTracking | None:
        result = await self.session.execute(
            select(RemediationTracking).where(
                RemediationTracking.finding_id == finding_id,
                RemediationTracking.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()
