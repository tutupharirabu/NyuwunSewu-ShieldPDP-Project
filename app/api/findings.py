from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import Permission
from app.database.session import get_session
from app.models import Endpoint, Evidence, Finding, User
from app.repositories.domain import DomainRepository
from app.schemas.finding import (
    FindingEvidencePeekResponse,
    FindingEvidenceResponse,
    FindingResponse,
)

router = APIRouter(tags=["findings"])


@router.get("/findings", response_model=list[FindingResponse])
async def findings(
    project_id: str | None = None,
    scan_id: str | None = None,
    target_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
    user: User = Depends(require_permission(Permission.READ_FINDINGS)),
    session: AsyncSession = Depends(get_session),
) -> list[FindingResponse]:
    repo = DomainRepository(session)
    rows = await repo.findings_for_org(
        user.organization_id,
        project_id=project_id,
        scan_id=scan_id,
        target_id=target_id,
        status=status,
        limit=min(limit, 500),
        offset=offset,
    )
    endpoint_ids = [row.endpoint_id for row in rows if row.endpoint_id]
    endpoint_urls: dict[str, str] = {}
    if endpoint_ids:
        result = await session.execute(
            select(Endpoint.id, Endpoint.url).where(
                Endpoint.organization_id == user.organization_id,
                Endpoint.id.in_(endpoint_ids),
            )
        )
        endpoint_urls = {endpoint_id: url for endpoint_id, url in result.all()}
    response: list[FindingResponse] = []
    for row in rows:
        payload = FindingResponse.model_validate(row).model_dump()
        payload["endpoint_url"] = endpoint_urls.get(row.endpoint_id or "")
        response.append(FindingResponse(**payload))
    return response


@router.get("/findings/{finding_id}/evidence", response_model=FindingEvidenceResponse)
async def finding_evidence(
    finding_id: str,
    user: User = Depends(require_permission(Permission.EVIDENCE_ACCESS)),
    session: AsyncSession = Depends(get_session),
) -> FindingEvidenceResponse:
    result = await session.execute(
        select(Evidence)
        .join(Finding, Finding.id == Evidence.finding_id)
        .where(
            Finding.id == finding_id,
            Finding.organization_id == user.organization_id,
            Evidence.organization_id == user.organization_id,
        )
        .order_by(Evidence.captured_at.desc())
    )
    evidence = result.scalars().first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found"
        )
    return FindingEvidenceResponse.model_validate(evidence)


@router.get(
    "/findings/{finding_id}/evidence/peek",
    response_model=FindingEvidencePeekResponse,
)
async def finding_evidence_peek(
    finding_id: str,
    user: User = Depends(require_permission(Permission.EVIDENCE_ACCESS)),
    session: AsyncSession = Depends(get_session),
) -> FindingEvidencePeekResponse:
    """Return the unredacted (full) request/response for a finding.

    This data is not intended for long-term storage or audit purposes; it exposes
    sensitive headers (e.g. authorization, cookie) for debugging during active
    assessment sessions.
    """
    result = await session.execute(
        select(Evidence)
        .join(Finding, Finding.id == Evidence.finding_id)
        .where(
            Finding.id == finding_id,
            Finding.organization_id == user.organization_id,
            Evidence.organization_id == user.organization_id,
        )
        .order_by(Evidence.captured_at.desc())
    )
    evidence = result.scalars().first()
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found"
        )
    return FindingEvidencePeekResponse.model_validate(evidence)
