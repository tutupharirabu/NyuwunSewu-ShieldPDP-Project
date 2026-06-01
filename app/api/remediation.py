from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_ip, require_permission
from app.core.rbac import Permission
from app.database.session import get_session
from app.models import Finding, FindingStatus, RemediationTracking, Scan, User
from app.remediation.service import RemediationService
from app.schemas.remediation import (
    RemediationResponse,
    RemediationUpdateRequest,
    RetestRequest,
    RetestResponse,
)
from app.services.scan_service import run_scan_by_id

router = APIRouter(tags=["remediation"])


@router.put("/remediation/{finding_id}", response_model=RemediationResponse)
async def update_remediation(
    finding_id: str,
    payload: RemediationUpdateRequest,
    request: Request,
    user: User = Depends(require_permission(Permission.REMEDIATION_UPDATE)),
    session: AsyncSession = Depends(get_session),
) -> RemediationResponse:
    finding = await _finding(session, user.organization_id, finding_id)
    try:
        remediation = await RemediationService(session).update_status(
            finding=finding,
            user=user,
            status=payload.status,
            assignee_id=payload.assignee_id,
            notes=payload.notes,
            ip_address=current_ip(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return RemediationResponse.model_validate(remediation)


@router.post("/retest", response_model=RetestResponse)
async def retest(
    payload: RetestRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    user: User = Depends(require_permission(Permission.REMEDIATION_UPDATE)),
    session: AsyncSession = Depends(get_session),
) -> RetestResponse:
    finding = await _finding(session, user.organization_id, payload.finding_id)
    remediation = await RemediationService(session).update_status(
        finding=finding,
        user=user,
        status=FindingStatus.RETEST.value,
        ip_address=current_ip(request),
    )
    scan_id: str | None = None
    if payload.run_scan:
        original = await session.get(Scan, finding.scan_id)
        if original is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Original scan not found")
        new_scan = Scan(
            organization_id=original.organization_id,
            project_id=original.project_id,
            target_id=original.target_id,
            policy_id=original.policy_id,
            started_by_id=user.id,
            status="queued",
            stats={"message": "Queued for remediation retest"},
        )
        session.add(new_scan)
        await session.flush()
        remediation.retest_scan_id = new_scan.id
        await session.commit()
        scan_id = new_scan.id
        background_tasks.add_task(run_scan_by_id, new_scan.id, {})
    return RetestResponse(remediation_id=remediation.id, status=remediation.status, scan_id=scan_id)


async def _finding(session: AsyncSession, organization_id: str, finding_id: str) -> Finding:
    result = await session.execute(
        select(Finding).where(Finding.id == finding_id, Finding.organization_id == organization_id)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding

