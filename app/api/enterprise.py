from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import Permission
from app.database.session import get_session
from app.models import AuditLog, Endpoint, Finding, Project, RemediationTracking, Report, Scan, Target, User
from app.schemas.enterprise import (
    AuditLogResponse,
    EndpointInventoryResponse,
    ProjectSummaryResponse,
    RemediationListResponse,
    ScanDetailResponse,
    ScanListResponse,
    TargetSummaryResponse,
)

router = APIRouter(tags=["enterprise"])


@router.get("/projects", response_model=list[ProjectSummaryResponse])
async def list_projects(
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> list[ProjectSummaryResponse]:
    result = await session.execute(
        select(
            Project,
            func.count(func.distinct(Target.id)).label("target_count"),
            func.count(func.distinct(Scan.id)).label("scan_count"),
            func.count(func.distinct(Finding.id)).label("finding_count"),
        )
        .outerjoin(Target, Target.project_id == Project.id)
        .outerjoin(Scan, Scan.project_id == Project.id)
        .outerjoin(Finding, Finding.project_id == Project.id)
        .where(Project.organization_id == user.organization_id)
        .group_by(Project.id)
        .order_by(Project.created_at.desc())
    )
    return [
        ProjectSummaryResponse(
            id=project.id,
            name=project.name,
            description=project.description,
            is_active=project.is_active,
            targets=target_count,
            scans=scan_count,
            findings=finding_count,
            created_at=project.created_at,
        )
        for project, target_count, scan_count, finding_count in result.all()
    ]


@router.get("/targets", response_model=list[TargetSummaryResponse])
async def list_targets(
    project_id: str | None = None,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> list[TargetSummaryResponse]:
    stmt = (
        select(
            Target,
            func.count(func.distinct(Scan.id)).label("scan_count"),
            func.count(func.distinct(Finding.id)).label("finding_count"),
        )
        .outerjoin(Scan, Scan.target_id == Target.id)
        .outerjoin(Finding, Finding.target_id == Target.id)
        .where(Target.organization_id == user.organization_id)
        .group_by(Target.id)
        .order_by(Target.created_at.desc())
    )
    if project_id:
        stmt = stmt.where(Target.project_id == project_id)
    result = await session.execute(stmt)
    return [
        TargetSummaryResponse(
            id=target.id,
            project_id=target.project_id,
            base_url=target.base_url,
            allowed_domains=target.allowed_domains,
            is_active=target.is_active,
            scans=scan_count,
            findings=finding_count,
            created_at=target.created_at,
        )
        for target, scan_count, finding_count in result.all()
    ]


@router.get("/scans", response_model=list[ScanListResponse])
async def list_scans(
    project_id: str | None = None,
    limit: int = 50,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> list[ScanListResponse]:
    stmt = (
        select(Scan, Target.base_url, Project.name)
        .join(Target, Target.id == Scan.target_id)
        .join(Project, Project.id == Scan.project_id)
        .where(Scan.organization_id == user.organization_id)
    )
    if project_id:
        stmt = stmt.where(Scan.project_id == project_id)
    result = await session.execute(stmt.order_by(Scan.created_at.desc()).limit(min(limit, 200)))
    return [
        ScanListResponse(
            id=scan.id,
            project_id=scan.project_id,
            project_name=project_name,
            target_id=scan.target_id,
            target_url=target_url,
            status=scan.status,
            stats=scan.stats,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            created_at=scan.created_at,
            error=scan.error,
        )
        for scan, target_url, project_name in result.all()
    ]


@router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: str,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> ScanDetailResponse:
    result = await session.execute(
        select(Scan, Target.base_url, Project.name)
        .join(Target, Target.id == Scan.target_id)
        .join(Project, Project.id == Scan.project_id)
        .where(Scan.id == scan_id, Scan.organization_id == user.organization_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    scan, target_url, project_name = row
    return ScanDetailResponse(
        id=scan.id,
        project_id=scan.project_id,
        project_name=project_name,
        target_id=scan.target_id,
        target_url=target_url,
        policy_id=scan.policy_id,
        stop_requested=scan.stop_requested,
        status=scan.status,
        stats=scan.stats,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        created_at=scan.created_at,
        error=scan.error,
    )


@router.get("/scans/{scan_id}/endpoints", response_model=list[EndpointInventoryResponse])
async def list_scan_endpoints(
    scan_id: str,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> list[EndpointInventoryResponse]:
    scan_result = await session.execute(
        select(Scan.id).where(Scan.id == scan_id, Scan.organization_id == user.organization_id)
    )
    if scan_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    endpoint_result = await session.execute(
        select(Endpoint)
        .where(Endpoint.scan_id == scan_id, Endpoint.organization_id == user.organization_id)
        .order_by(Endpoint.risk_score.desc(), Endpoint.created_at.asc())
    )
    endpoints = list(endpoint_result.scalars().all())
    if not endpoints:
        return []

    finding_result = await session.execute(
        select(
            Finding.endpoint_id,
            Finding.severity,
            Finding.confidence,
            Finding.finding_type,
            Finding.title,
        ).where(
            Finding.scan_id == scan_id,
            Finding.organization_id == user.organization_id,
            Finding.endpoint_id.in_([endpoint.id for endpoint in endpoints]),
        )
    )
    findings_by_endpoint: dict[str, list[tuple[str, float, str, str]]] = {}
    for endpoint_id, severity, confidence, finding_type, title in finding_result.all():
        if endpoint_id:
            findings_by_endpoint.setdefault(endpoint_id, []).append(
                (severity, float(confidence), finding_type, title)
            )

    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    def strongest(items: list[tuple[str, float, str, str]]) -> tuple[str | None, float | None]:
        if not items:
            return None, None
        severity, confidence, _, _ = max(
            items,
            key=lambda item: (severity_rank.get(item[0].lower(), 0), item[1]),
        )
        return severity, confidence

    return [
        EndpointInventoryResponse(
            id=endpoint.id,
            scan_id=endpoint.scan_id,
            url=endpoint.url,
            method=endpoint.method,
            normalized_path=endpoint.normalized_path,
            status_code=endpoint.status_code,
            title=endpoint.title,
            content_type=endpoint.content_type,
            query_parameters=endpoint.query_parameters,
            forms=endpoint.forms,
            tech_stack=endpoint.tech_stack,
            classifications=endpoint.classifications,
            risk_score=endpoint.risk_score,
            finding_count=len(findings_by_endpoint.get(endpoint.id, [])),
            highest_severity=strongest(findings_by_endpoint.get(endpoint.id, []))[0],
            highest_confidence=strongest(findings_by_endpoint.get(endpoint.id, []))[1],
            finding_types=sorted(
                {finding_type for _, _, finding_type, _ in findings_by_endpoint.get(endpoint.id, [])}
            ),
            finding_titles=[
                title for _, _, _, title in findings_by_endpoint.get(endpoint.id, [])[:5]
            ],
            created_at=endpoint.created_at,
        )
        for endpoint in endpoints
    ]


@router.get("/remediations", response_model=list[RemediationListResponse])
async def list_remediations(
    target_id: str | None = None,
    user: User = Depends(require_permission(Permission.READ_FINDINGS)),
    session: AsyncSession = Depends(get_session),
) -> list[RemediationListResponse]:
    stmt = (
        select(RemediationTracking, Finding)
        .join(Finding, Finding.id == RemediationTracking.finding_id)
        .where(RemediationTracking.organization_id == user.organization_id)
    )
    if target_id:
        stmt = stmt.where(
            Finding.organization_id == user.organization_id,
            Finding.target_id == target_id,
        )
    result = await session.execute(stmt.order_by(RemediationTracking.updated_at.desc()))
    return [
        RemediationListResponse(
            id=row.id,
            finding_id=row.finding_id,
            title=finding.title,
            severity=finding.severity,
            status=row.status,
            assignee_id=row.assignee_id,
            notes=row.notes,
            retest_scan_id=row.retest_scan_id,
            updated_at=row.updated_at,
        )
        for row, finding in result.all()
    ]


@router.get("/audit-logs", response_model=list[AuditLogResponse])
async def list_audit_logs(
    limit: int = 100,
    target_id: str | None = None,
    user: User = Depends(require_permission(Permission.ADMIN)),
    session: AsyncSession = Depends(get_session),
) -> list[AuditLogResponse]:
    stmt = select(AuditLog).where(AuditLog.organization_id == user.organization_id)
    if target_id:
        scan_ids = select(Scan.id).where(
            Scan.organization_id == user.organization_id,
            Scan.target_id == target_id,
        )
        finding_ids = select(Finding.id).where(
            Finding.organization_id == user.organization_id,
            Finding.target_id == target_id,
        )
        report_ids = (
            select(Report.id)
            .join(Scan, Scan.id == Report.scan_id)
            .where(
                Report.organization_id == user.organization_id,
                Scan.organization_id == user.organization_id,
                Scan.target_id == target_id,
            )
        )
        stmt = stmt.where(
            or_(
                and_(AuditLog.resource_type == "scan", AuditLog.resource_id.in_(scan_ids)),
                and_(AuditLog.resource_type == "finding", AuditLog.resource_id.in_(finding_ids)),
                and_(AuditLog.resource_type == "report", AuditLog.resource_id.in_(report_ids)),
            )
        )
    result = await session.execute(
        stmt.order_by(AuditLog.timestamp.desc()).limit(min(limit, 500))
    )
    return [
        AuditLogResponse(
            id=row.id,
            timestamp=row.timestamp,
            user_id=row.user_id,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            ip_address=row.ip_address,
            metadata_json=row.metadata_json,
            entry_hash=row.entry_hash,
        )
        for row in result.scalars().all()
    ]
