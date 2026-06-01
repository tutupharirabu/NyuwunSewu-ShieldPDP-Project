from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import Permission
from app.database.session import get_session
from app.models import (
    BreachNotification,
    ComplianceMapping,
    Finding,
    Organization,
    User,
)
from app.reporting.engine import ReportingEngine
from app.services.breach_notification import (
    BreachAssessment,
    BreachNotificationService,
)

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
    stmt = stmt.group_by(
        ComplianceMapping.framework, ComplianceMapping.article_or_control
    )
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


# --- Breach Notification Endpoints (Pasal 46 UU PDP) ---


class BreachAssessRequest(BaseModel):
    finding_ids: list[str]


class BreachNotifyRequest(BaseModel):
    breach_id: str
    channels: list[str] = ["telegram"]
    contact_info: str = ""


class BreachDismissRequest(BaseModel):
    reason: str


@router.post("/compliance/breach-assess")
async def assess_breach(
    req: BreachAssessRequest,
    user: User = Depends(require_permission(Permission.READ_COMPLIANCE)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Assess whether the given findings constitute a notifiable data breach.

    Per Pasal 46 UU PDP, this determines if the 3x24h notification SLA applies.
    """
    # Fetch findings from database
    stmt = select(Finding).where(
        Finding.id.in_(req.finding_ids),
        Finding.organization_id == user.organization_id,
    )
    result = await session.execute(stmt)
    findings = result.scalars().all()

    if not findings:
        raise HTTPException(
            status_code=404, detail="No findings found for the given IDs"
        )

    # Convert ORM findings to dicts for the service
    finding_dicts = [
        {
            "id": f.id,
            "finding_type": f.finding_type,
            "severity": f.severity,
            "title": f.title,
            "evidence_summary": f.evidence_summary,
            "compliance": f.compliance,
        }
        for f in findings
    ]

    assessment = BreachNotificationService.detect_breach(finding_dicts)

    return {
        "is_breach": assessment.is_breach,
        "requires_notification": assessment.requires_notification,
        "severity": assessment.severity,
        "finding_ids": assessment.finding_ids,
        "pii_types": assessment.pii_types,
        "breach_type": assessment.breach_type,
        "description": assessment.description,
        "data_subjects_estimate": assessment.data_subjects_estimate,
        "reasons": assessment.reasons,
        "sla_deadline_hours": BreachNotificationService.NOTIFICATION_DEADLINE_HOURS,
    }


@router.post("/compliance/breach-create")
async def create_breach_notification(
    req: BreachAssessRequest,
    user: User = Depends(require_permission(Permission.MANAGE_COMPLIANCE)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Create a breach notification record from findings.

    This records the breach detection and starts the 3x24h SLA clock.
    """
    # Fetch findings
    stmt = select(Finding).where(
        Finding.id.in_(req.finding_ids),
        Finding.organization_id == user.organization_id,
    )
    result = await session.execute(stmt)
    findings = result.scalars().all()

    if not findings:
        raise HTTPException(
            status_code=404, detail="No findings found for the given IDs"
        )

    # Convert to dicts
    finding_dicts = [
        {
            "id": f.id,
            "finding_type": f.finding_type,
            "severity": f.severity,
            "title": f.title,
            "evidence_summary": f.evidence_summary,
        }
        for f in findings
    ]

    assessment = BreachNotificationService.detect_breach(finding_dicts)

    # Get organization name
    org_stmt = select(Organization).where(Organization.id == user.organization_id)
    org_result = await session.execute(org_stmt)
    org = org_result.scalar_one_or_none()
    org_name = org.name if org else ""

    # Generate notification text
    notification_text = BreachNotificationService.generate_notification_text(
        assessment, organization_name=org_name
    )

    now = datetime.now(timezone.utc)
    sla_deadline = now + timedelta(
        hours=BreachNotificationService.NOTIFICATION_DEADLINE_HOURS
    )

    # Create breach notification record
    breach = BreachNotification(
        organization_id=user.organization_id,
        finding_ids=req.finding_ids,
        breach_title=assessment.breach_type or "Data breach assessment",
        description=assessment.description,
        breach_type=assessment.breach_type,
        severity=assessment.severity,
        status="assessing",
        detected_at=now,
        sla_deadline=sla_deadline,
        pii_types_affected=assessment.pii_types,
        data_subjects_estimate=assessment.data_subjects_estimate,
        notification_text=notification_text,
        actions_taken=["Automated breach assessment completed"],
        contact_info="",
        compliance_evidence={
            "assessment_reasons": assessment.reasons,
            "finding_severities": {f.id: f.severity for f in findings},
        },
    )

    session.add(breach)
    await session.commit()
    await session.refresh(breach)

    return {
        "breach_id": breach.id,
        "status": breach.status,
        "severity": breach.severity,
        "sla_deadline": breach.sla_deadline.isoformat(),
        "hours_remaining": BreachNotificationService.check_sla_compliance(
            breach.detected_at
        ).hours_remaining,
        "notification_preview": notification_text[:500] + "...",
    }


@router.post("/compliance/breach-notify")
async def notify_breach(
    req: BreachNotifyRequest,
    user: User = Depends(require_permission(Permission.MANAGE_COMPLIANCE)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Send breach notification via specified channels.

    Marks the breach as notified and records the notification timestamp for SLA compliance.
    """
    stmt = select(BreachNotification).where(
        BreachNotification.id == req.breach_id,
        BreachNotification.organization_id == user.organization_id,
    )
    result = await session.execute(stmt)
    breach = result.scalar_one_or_none()

    if not breach:
        raise HTTPException(status_code=404, detail="Breach notification not found")

    if breach.status == "notified":
        return {"message": "Notification already sent", "breach_id": breach.id}

    # Send via requested channels
    channel_results: list[dict] = []
    now = datetime.now(timezone.utc)

    if "telegram" in req.channels:
        org_stmt = select(Organization).where(Organization.id == user.organization_id)
        org_result = await session.execute(org_stmt)
        org = org_result.scalar_one_or_none()

        msg = BreachNotificationService.build_telegram_message(
            BreachAssessment(
                is_breach=True,
                severity=breach.severity,
                finding_ids=breach.finding_ids,
                pii_types=breach.pii_types_affected,
                breach_type=breach.breach_type,
                description=breach.description,
                data_subjects_estimate=breach.data_subjects_estimate,
                requires_notification=True,
            ),
            organization_name=org.name if org else "",
        )

        telegram_result = await BreachNotificationService.send_telegram_notification(
            msg
        )
        channel_results.append(telegram_result)

    # Update breach record
    breach.notified_at = now
    breach.status = "notified"
    breach.notification_channels = req.channels
    breach.compliance_evidence["notification_sent_at"] = now.isoformat()
    breach.compliance_evidence["channels"] = req.channels
    breach.compliance_evidence["channel_results"] = channel_results
    breach.contact_info = req.contact_info or breach.contact_info

    # Check SLA compliance
    sla = BreachNotificationService.check_sla_compliance(
        breach.detected_at, breach.notified_at
    )
    breach.compliance_evidence["sla_compliant"] = sla.is_compliant

    await session.commit()
    await session.refresh(breach)

    return {
        "breach_id": breach.id,
        "status": breach.status,
        "notified_at": now.isoformat(),
        "channels": req.channels,
        "channel_results": channel_results,
        "sla_compliant": sla.is_compliant,
        "sla_hours_remaining": sla.hours_remaining,
    }


@router.post("/compliance/breach-dismiss")
async def dismiss_breach(
    req: BreachDismissRequest,
    breach_id: str,
    user: User = Depends(require_permission(Permission.MANAGE_COMPLIANCE)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Dismiss a breach notification as non-notifiable.

    Requires a reason for audit trail purposes.
    """
    stmt = select(BreachNotification).where(
        BreachNotification.id == breach_id,
        BreachNotification.organization_id == user.organization_id,
    )
    result = await session.execute(stmt)
    breach = result.scalar_one_or_none()

    if not breach:
        raise HTTPException(status_code=404, detail="Breach notification not found")

    if breach.status in ("notified", "dismissed"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot dismiss breach with status '{breach.status}'",
        )

    breach.status = "dismissed"
    breach.dismissed_reason = req.reason
    breach.compliance_evidence["dismissed_at"] = datetime.now(timezone.utc).isoformat()
    breach.compliance_evidence["dismissed_reason"] = req.reason

    await session.commit()

    return {
        "breach_id": breach.id,
        "status": "dismissed",
        "reason": req.reason,
    }


@router.get("/compliance/breach/{breach_id}")
async def get_breach_notification(
    breach_id: str,
    user: User = Depends(require_permission(Permission.READ_COMPLIANCE)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get details of a specific breach notification record."""
    stmt = select(BreachNotification).where(
        BreachNotification.id == breach_id,
        BreachNotification.organization_id == user.organization_id,
    )
    result = await session.execute(stmt)
    breach = result.scalar_one_or_none()

    if not breach:
        raise HTTPException(status_code=404, detail="Breach notification not found")

    sla = BreachNotificationService.check_sla_compliance(
        breach.detected_at, breach.notified_at
    )

    return {
        "breach_id": breach.id,
        "finding_ids": breach.finding_ids,
        "breach_title": breach.breach_title,
        "description": breach.description,
        "breach_type": breach.breach_type,
        "severity": breach.severity,
        "status": breach.status,
        "detected_at": breach.detected_at.isoformat(),
        "sla_deadline": breach.sla_deadline.isoformat(),
        "notified_at": breach.notified_at.isoformat() if breach.notified_at else None,
        "notification_channels": breach.notification_channels,
        "pii_types_affected": breach.pii_types_affected,
        "data_subjects_estimate": breach.data_subjects_estimate,
        "notification_text": breach.notification_text,
        "actions_taken": breach.actions_taken,
        "contact_info": breach.contact_info,
        "dismissed_reason": breach.dismissed_reason,
        "sla_status": {
            "is_compliant": sla.is_compliant,
            "hours_remaining": sla.hours_remaining,
            "is_overdue": sla.is_overdue,
        },
        "compliance_evidence": breach.compliance_evidence,
        "created_at": breach.created_at.isoformat(),
        "updated_at": breach.updated_at.isoformat(),
    }


@router.get("/compliance/breaches")
async def list_breach_notifications(
    status: str | None = None,
    user: User = Depends(require_permission(Permission.READ_COMPLIANCE)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """List all breach notifications for the organization."""
    stmt = select(BreachNotification).where(
        BreachNotification.organization_id == user.organization_id
    )
    if status:
        stmt = stmt.where(BreachNotification.status == status)
    stmt = stmt.order_by(BreachNotification.detected_at.desc())

    result = await session.execute(stmt)
    breaches = result.scalars().all()

    items = []
    for b in breaches:
        sla = BreachNotificationService.check_sla_compliance(
            b.detected_at, b.notified_at
        )
        items.append(
            {
                "breach_id": b.id,
                "breach_title": b.breach_title,
                "severity": b.severity,
                "status": b.status,
                "detected_at": b.detected_at.isoformat(),
                "sla_deadline": b.sla_deadline.isoformat(),
                "notified_at": b.notified_at.isoformat() if b.notified_at else None,
                "sla_compliant": sla.is_compliant,
                "hours_remaining": sla.hours_remaining,
                "is_overdue": sla.is_overdue,
                "pii_types_count": len(b.pii_types_affected),
            }
        )

    return {
        "organization_id": user.organization_id,
        "breaches": items,
        "total": len(items),
    }


# --- Remediation Matrix Endpoint ---


@router.get("/compliance/remediation-matrix")
async def remediation_matrix(
    scan_id: str | None = None,
    target_id: str | None = None,
    user: User = Depends(require_permission(Permission.READ_COMPLIANCE)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get the aggregated, prioritized remediation action plan.

    Groups findings by remediation domain with priority ranking,
    effort estimates, and timeline recommendations.
    """
    stmt = select(Finding).where(
        Finding.organization_id == user.organization_id,
        Finding.is_false_positive == False,  # noqa: E712
    )
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if target_id:
        stmt = stmt.where(Finding.target_id == target_id)
    stmt = stmt.order_by(Finding.risk_score.desc())
    result = await session.execute(stmt)
    findings = result.scalars().all()

    if not findings:
        return {"matrix": [], "total_findings": 0, "total_items": 0}

    engine = ReportingEngine()
    matrix = engine._build_remediation_matrix(list(findings))

    return {
        "organization_id": user.organization_id,
        "matrix": matrix,
        "total_findings": len(findings),
        "total_items": len(matrix),
    }
