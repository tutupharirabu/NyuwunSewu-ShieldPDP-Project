from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import Permission
from app.database.session import get_session
from app.models import ComplianceMapping, Finding, User

router = APIRouter(tags=["compliance"])


@router.get("/compliance")
async def compliance(
    framework: str | None = None,
    target_id: str | None = None,
    user: User = Depends(require_permission(Permission.READ_COMPLIANCE)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    stmt = select(
        ComplianceMapping.framework,
        ComplianceMapping.article_or_control,
        func.count(ComplianceMapping.id),
    ).where(ComplianceMapping.organization_id == user.organization_id)
    if target_id:
        stmt = stmt.join(Finding, Finding.id == ComplianceMapping.finding_id).where(
            Finding.organization_id == user.organization_id,
            Finding.target_id == target_id,
        )
    if framework:
        stmt = stmt.where(ComplianceMapping.framework == framework)
    stmt = stmt.group_by(ComplianceMapping.framework, ComplianceMapping.article_or_control)
    result = await session.execute(stmt)
    mappings = [
        {
            "framework": row[0],
            "article_or_control": row[1],
            "finding_count": row[2],
        }
        for row in result.all()
    ]
    return {"organization_id": user.organization_id, "mappings": mappings}
