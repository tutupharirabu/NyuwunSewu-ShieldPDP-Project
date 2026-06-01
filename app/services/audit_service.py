from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import stable_hash
from app.models import AuditLog, User
from app.repositories.domain import DomainRepository
from app.utils.redaction import sanitize_json


class AuditService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = DomainRepository(session)

    async def log(
        self,
        *,
        action: str,
        resource_type: str,
        user: User | None = None,
        organization_id: str | None = None,
        resource_id: str | None = None,
        ip_address: str | None = None,
        metadata: dict | None = None,
    ) -> AuditLog:
        previous_hash = await self.repo.latest_audit_hash()
        payload = {
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "user_id": user.id if user else None,
            "organization_id": organization_id or (user.organization_id if user else None),
            "ip_address": ip_address,
            "metadata": sanitize_json(metadata or {}),
            "previous_hash": previous_hash,
        }
        entry_hash = stable_hash(payload)
        log = AuditLog(
            user_id=user.id if user else None,
            organization_id=payload["organization_id"],
            ip_address=ip_address,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata_json=payload["metadata"],
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )
        self.session.add(log)
        await self.session.flush()
        return log

