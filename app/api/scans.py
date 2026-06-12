from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Request, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_ip, require_permission
from app.core.config import get_settings
from app.core.rbac import Permission
from app.database.session import get_session
from app.models import EngagementMode, RoeDocument, Scan, User
from app.repositories.domain import DomainRepository
from app.schemas.scan import (
    RoeUploadResponse,
    ScanStartRequest,
    ScanStartResponse,
    ScanStatusResponse,
    ScanStopRequest,
)
from app.utils.roe_extract import UnsupportedRoeFile, extract_roe_text

ROE_MAX_UPLOAD_BYTES = 2 * 1024 * 1024
from app.services.scan_service import ScanService, run_scan_by_id
from app.utils.redaction import redact_headers

router = APIRouter(tags=["scans"])


@router.post("/scan/start", response_model=ScanStartResponse)
async def start_scan(
    payload: ScanStartRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    user: User = Depends(require_permission(Permission.SCAN_CREATE)),
    session: AsyncSession = Depends(get_session),
) -> ScanStartResponse:
    settings = get_settings()
    if settings.use_celery and payload.credential_auth:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential form authentication is available only for in-process local scans; use secret-managed headers for worker execution.",
        )
    service = ScanService(session)
    try:
        scan = await service.create_scan(
            user=user,
            target_url=payload.target_url,
            project_name=payload.project_name,
            project_id=payload.project_id,
            policy_payload=payload.policy.model_dump(),
            allowed_domains=payload.allowed_domains,
            ip_address=current_ip(request),
            engagement_mode=payload.engagement_mode.value,
            roe_document_id=payload.roe_document_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    runtime_options = {
        "initial_paths": payload.initial_paths,
        "credential_auth": payload.credential_auth.model_dump() if payload.credential_auth else None,
        "primary_headers": payload.primary_headers,
        "secondary_headers": payload.secondary_headers,
        "admin_headers": payload.admin_headers,
        "auditor_headers": payload.auditor_headers,
        "custom_role_headers": payload.custom_role_headers,
        "exploit_chains": payload.exploit_chains.model_dump(),
    }
    if settings.use_celery:
        from worker.tasks import run_scan_task

        task = run_scan_task.delay(scan.id, runtime_options)
        scan.celery_task_id = task.id
        await session.commit()
    else:
        background_tasks.add_task(run_scan_by_id, scan.id, runtime_options)

    return ScanStartResponse(
        scan_id=scan.id,
        status=scan.status,
        message="Scan queued with policy-enforced safe validation",
    )


@router.post("/scan/roe", response_model=RoeUploadResponse)
async def upload_roe(
    file: UploadFile = File(...),
    engagement_mode: str = Form(...),
    user: User = Depends(require_permission(Permission.SCAN_CREATE)),
    session: AsyncSession = Depends(get_session),
) -> RoeUploadResponse:
    if engagement_mode != EngagementMode.EXTERNAL.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="RoE documents apply only to external engagements",
        )
    if not user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User must belong to an organization",
        )
    raw = await file.read()
    if len(raw) > ROE_MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="RoE file exceeds 2 MB limit",
        )
    try:
        extracted = extract_roe_text(file.filename or "roe", raw)
    except UnsupportedRoeFile as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    doc = RoeDocument(
        organization_id=user.organization_id,
        filename=file.filename or "roe",
        extracted_text=extracted.text,
        char_count=extracted.char_count,
        extraction_warning=extracted.extraction_warning,
    )
    session.add(doc)
    await session.commit()
    return RoeUploadResponse(
        roe_document_id=doc.id,
        filename=doc.filename,
        char_count=doc.char_count,
        extraction_warning=doc.extraction_warning,
    )


@router.post("/scan/stop", response_model=ScanStatusResponse)
async def stop_scan(
    payload: ScanStopRequest,
    request: Request,
    user: User = Depends(require_permission(Permission.SCAN_STOP)),
    session: AsyncSession = Depends(get_session),
) -> ScanStatusResponse:
    repo = DomainRepository(session)
    scan = await repo.scan_for_org(payload.scan_id, user.organization_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    scan = await ScanService(session).request_stop(scan=scan, user=user, ip_address=current_ip(request))
    return _scan_response(scan)


@router.get("/scan/status", response_model=ScanStatusResponse)
async def scan_status(
    scan_id: str,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> ScanStatusResponse:
    repo = DomainRepository(session)
    scan = await repo.scan_for_org(scan_id, user.organization_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _scan_response(scan)


def _scan_response(scan: Scan) -> ScanStatusResponse:
    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        target_id=scan.target_id,
        project_id=scan.project_id,
        stats=scan.stats,
        error=scan.error,
    )
