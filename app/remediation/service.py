from datetime import timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import utcnow
from app.models import Finding, FindingStatus, RemediationTracking, User
from app.repositories.domain import DomainRepository
from app.services.audit_service import AuditService


ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    FindingStatus.OPEN.value: {FindingStatus.ASSIGNED.value, FindingStatus.FALSE_POSITIVE.value},
    FindingStatus.ASSIGNED.value: {FindingStatus.IN_PROGRESS.value, FindingStatus.OPEN.value},
    FindingStatus.IN_PROGRESS.value: {FindingStatus.RETEST.value, FindingStatus.ASSIGNED.value},
    FindingStatus.RETEST.value: {FindingStatus.CLOSED.value, FindingStatus.IN_PROGRESS.value},
    FindingStatus.CLOSED.value: set(),
    FindingStatus.FALSE_POSITIVE.value: {FindingStatus.OPEN.value},
}


class RemediationService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = DomainRepository(session)
        self.audit = AuditService(session)

    async def update_status(
        self,
        *,
        finding: Finding,
        user: User,
        status: str,
        assignee_id: str | None = None,
        notes: str | None = None,
        ip_address: str | None = None,
    ) -> RemediationTracking:
        current = finding.status
        if status not in ALLOWED_TRANSITIONS.get(current, set()) and status != current:
            raise ValueError(f"Invalid remediation transition from {current} to {status}")

        remediation = await self.repo.remediation_for_finding(finding.id, finding.organization_id)
        if remediation is None:
            remediation = RemediationTracking(
                organization_id=finding.organization_id,
                finding_id=finding.id,
            )
            self.session.add(remediation)
            await self.session.flush()

        remediation.status = status
        remediation.assignee_id = assignee_id or remediation.assignee_id
        remediation.notes = notes or remediation.notes
        finding.status = status
        finding.is_false_positive = status == FindingStatus.FALSE_POSITIVE.value
        if status == FindingStatus.CLOSED.value:
            remediation.closed_at = utcnow().astimezone(timezone.utc)

        await self.audit.log(
            action="remediation.status_change",
            resource_type="finding",
            resource_id=finding.id,
            user=user,
            ip_address=ip_address,
            metadata={"from": current, "to": status},
        )
        await self.session.commit()
        return remediation

