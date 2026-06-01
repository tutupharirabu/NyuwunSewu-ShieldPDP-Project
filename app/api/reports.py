from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_ip, require_permission
from app.core.rbac import Permission
from app.database.session import get_session
from app.models import Endpoint, Finding, Policy, Project, Report, Scan, Target, User
from app.repositories.domain import DomainRepository
from app.reporting.engine import ReportingEngine
from app.schemas.report import ReportGenerateRequest, ReportResponse
from app.services.audit_service import AuditService

router = APIRouter(tags=["reports"])


@router.get("/reports", response_model=list[ReportResponse])
async def list_reports(
    project_id: str | None = None,
    target_id: str | None = None,
    include_content: bool = False,
    user: User = Depends(require_permission(Permission.REPORT_EXPORT)),
    session: AsyncSession = Depends(get_session),
) -> list[ReportResponse]:
    rows = await DomainRepository(session).reports_for_org(
        user.organization_id, project_id, target_id=target_id
    )
    return [
        ReportResponse(
            id=row.id,
            project_id=row.project_id,
            scan_id=row.scan_id,
            title=row.title,
            report_type=row.report_type,
            export_format=row.export_format,
            report_hash=row.report_hash,
            content=row.content if include_content else None,
        )
        for row in rows
    ]


@router.get("/reports/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: str,
    request: Request,
    user: User = Depends(require_permission(Permission.REPORT_EXPORT)),
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    result = await session.execute(
        select(Report).where(Report.id == report_id, Report.organization_id == user.organization_id)
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    await AuditService(session).log(
        action="report.export",
        resource_type="report",
        resource_id=report.id,
        user=user,
        ip_address=current_ip(request),
    )
    await session.commit()
    return ReportResponse.model_validate(report)


@router.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: str,
    request: Request,
    user: User = Depends(require_permission(Permission.REPORT_EXPORT)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    result = await session.execute(
        select(Report).where(Report.id == report_id, Report.organization_id == user.organization_id)
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    await AuditService(session).log(
        action="report.delete",
        resource_type="report",
        resource_id=report.id,
        user=user,
        ip_address=current_ip(request),
        metadata={
            "report_type": report.report_type,
            "format": report.export_format,
            "project_id": report.project_id,
            "scan_id": report.scan_id,
            "report_hash": report.report_hash,
        },
    )
    await session.delete(report)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/reports/generate", response_model=ReportResponse)
async def generate_report(
    payload: ReportGenerateRequest,
    request: Request,
    user: User = Depends(require_permission(Permission.REPORT_EXPORT)),
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    stmt = select(Finding).where(
        Finding.organization_id == user.organization_id,
        Finding.project_id == payload.project_id,
    )
    if payload.scan_id:
        stmt = stmt.where(Finding.scan_id == payload.scan_id)
    result = await session.execute(stmt)
    findings = list(result.scalars().all())
    engine = ReportingEngine()
    context = await _report_context(
        session=session,
        organization_id=user.organization_id,
        project_id=payload.project_id,
        scan_id=payload.scan_id,
        generated_by=user,
    )
    html = engine.render_html(
        title=f"NyuwunSewu {payload.report_type}",
        findings=findings,
        report_type=payload.report_type,
        context=context,
    )
    content = (
        engine.render_pdf_from_context(
            title=f"NyuwunSewu {payload.report_type}",
            findings=findings,
            report_type=payload.report_type,
            context=context,
        )
        if payload.export_format == "pdf"
        else html
    )
    report = engine.build_report_row(
        organization_id=user.organization_id,
        project_id=payload.project_id,
        scan_id=payload.scan_id,
        generated_by_id=user.id,
        report_type=payload.report_type,
        export_format=payload.export_format,
        title=payload.report_type,
        content=content,
    )
    session.add(report)
    await session.flush()
    await AuditService(session).log(
        action="report.export",
        resource_type="report",
        resource_id=report.id,
        user=user,
        ip_address=current_ip(request),
        metadata={"report_type": payload.report_type, "format": payload.export_format},
    )
    await session.commit()
    await session.refresh(report)
    return ReportResponse.model_validate(report)


async def _report_context(
    *,
    session: AsyncSession,
    organization_id: str,
    project_id: str,
    scan_id: str | None,
    generated_by: User | None = None,
) -> dict:
    project_result = await session.execute(
        select(Project).where(Project.id == project_id, Project.organization_id == organization_id)
    )
    project = project_result.scalar_one_or_none()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    scan = None
    target = None
    policy = None
    if scan_id:
        scan_result = await session.execute(
            select(Scan, Target, Policy)
            .join(Target, Target.id == Scan.target_id)
            .join(Policy, Policy.id == Scan.policy_id)
            .where(
                Scan.id == scan_id,
                Scan.organization_id == organization_id,
                Scan.project_id == project_id,
            )
        )
        row = scan_result.one_or_none()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        scan, target, policy = row
    else:
        latest_result = await session.execute(
            select(Scan, Target, Policy)
            .join(Target, Target.id == Scan.target_id)
            .join(Policy, Policy.id == Scan.policy_id)
            .where(Scan.organization_id == organization_id, Scan.project_id == project_id)
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        latest = latest_result.one_or_none()
        if latest:
            scan, target, policy = latest

    endpoints_stmt = select(Endpoint).where(
        Endpoint.organization_id == organization_id,
        Endpoint.project_id == project_id,
    )
    if scan_id:
        endpoints_stmt = endpoints_stmt.where(Endpoint.scan_id == scan_id)
    endpoints_result = await session.execute(
        endpoints_stmt.order_by(Endpoint.risk_score.desc(), Endpoint.created_at.asc())
    )
    return {
        "project": project,
        "target": target,
        "scan": scan,
        "policy": policy,
        "generated_by": generated_by,
        "endpoints": list(endpoints_result.scalars().all()),
    }


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    request: Request,
    user: User = Depends(require_permission(Permission.REPORT_EXPORT)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    result = await session.execute(
        select(Report).where(Report.id == report_id, Report.organization_id == user.organization_id)
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    await AuditService(session).log(
        action="report.export",
        resource_type="report",
        resource_id=report.id,
        user=user,
        ip_address=current_ip(request),
    )
    await session.commit()
    if report.export_format == "pdf":
        return Response(
            content=report.content.encode("latin-1", errors="replace"),
            media_type="application/pdf",
            headers={"content-disposition": f'attachment; filename="{report.id}.pdf"'},
        )
    return Response(
        content=report.content,
        media_type="text/html",
        headers={"content-disposition": f'attachment; filename="{report.id}.html"'},
    )
