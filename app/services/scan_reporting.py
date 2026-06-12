"""Report generation, scan-stats aggregation, and webhook dispatch for ScanRunner.

Extracted from the runner as a mixin; relies on runner instance state
(``self.session``, ``self.reporting``) resolved at call time via the MRO.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select

from app.core.security import utcnow
from app.models import (
    ComplianceMapping,
    Endpoint,
    Finding,
    Policy,
    Project,
    Report,
    Scan,
    ScanStatus,
    Target,
    User,
)
from app.reporting.evidence_loader import load_evidence_by_finding_id
from app.services.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)


class _ReportingMixin:
    async def _generate_default_reports(self, scan: Scan) -> None:
        result = await self.session.execute(
            select(Finding).where(
                Finding.scan_id == scan.id,
                Finding.organization_id == scan.organization_id,
            )
        )
        findings = list(result.scalars().all())
        if not findings:
            return
        endpoint_result = await self.session.execute(
            select(Endpoint)
            .where(
                Endpoint.scan_id == scan.id,
                Endpoint.organization_id == scan.organization_id,
            )
            .order_by(Endpoint.risk_score.desc(), Endpoint.created_at.asc())
        )
        context = {
            "project": await self.session.get(Project, scan.project_id),
            "target": await self.session.get(Target, scan.target_id),
            "policy": await self.session.get(Policy, scan.policy_id),
            "scan": scan,
            "generated_by": await self.session.get(User, scan.started_by_id),
            "endpoints": list(endpoint_result.scalars().all()),
            "evidence_by_finding_id": await load_evidence_by_finding_id(
                self.session,
                organization_id=scan.organization_id,
                findings=findings,
            ),
        }
        html = self.reporting.render_html(
            title="NyuwunSewu Security Validation Report",
            findings=findings,
            report_type="Technical Report",
            context=context,
        )
        report = self.reporting.build_report_row(
            organization_id=scan.organization_id,
            project_id=scan.project_id,
            scan_id=scan.id,
            generated_by_id=scan.started_by_id,
            report_type="Technical Report",
            export_format="html",
            title="Security Validation Technical Report",
            content=html,
        )
        self.session.add(report)
        executive_html = self.reporting.render_html(
            title="NyuwunSewu Executive Summary",
            findings=findings,
            report_type="Executive Summary",
            context=context,
        )
        self.session.add(
            self.reporting.build_report_row(
                organization_id=scan.organization_id,
                project_id=scan.project_id,
                scan_id=scan.id,
                generated_by_id=scan.started_by_id,
                report_type="Executive Summary",
                export_format="html",
                title="Executive Summary",
                content=executive_html,
            )
        )
        await self.session.flush()

    async def _scan_stats(
        self, scan: Scan, phase: str, progress: int
    ) -> dict[str, Any]:
        endpoint_count = await self.session.scalar(
            select(func.count(Endpoint.id)).where(Endpoint.scan_id == scan.id)
        )
        finding_count = await self.session.scalar(
            select(func.count(Finding.id)).where(Finding.scan_id == scan.id)
        )
        report_count = await self.session.scalar(
            select(func.count(Report.id)).where(Report.scan_id == scan.id)
        )
        max_risk = await self.session.scalar(
            select(func.max(Finding.risk_score)).where(Finding.scan_id == scan.id)
        )
        compliance_count = await self.session.scalar(
            select(func.count(ComplianceMapping.id)).where(
                ComplianceMapping.finding_id.in_(
                    select(Finding.id).where(Finding.scan_id == scan.id)
                )
            )
        )
        previous = scan.stats or {}
        return {
            **previous,
            "message": "Completed",
            "phase": phase,
            "progress_percentage": progress,
            "endpoints": endpoint_count or 0,
            "endpoints_discovered": endpoint_count or 0,
            "findings": finding_count or 0,
            "findings_discovered": finding_count or 0,
            "reports": report_count or 0,
            "risk_score": round(float(max_risk or 0), 2),
            "compliance_impact": compliance_count or 0,
            "coverage_status": "complete",
        }

    def _progress(
        self, *, phase: str, progress: int, message: str, **extra: Any
    ) -> dict[str, Any]:
        return {
            "phase": phase,
            "progress_percentage": max(0, min(100, progress)),
            "message": message,
            "endpoints_discovered": extra.pop("endpoints_discovered", 0),
            "parameters_discovered": extra.pop("parameters_discovered", 0),
            "findings_discovered": extra.pop("findings_discovered", 0),
            "active_validations": extra.pop("active_validations", []),
            "risk_score": extra.pop("risk_score", 0),
            "compliance_impact": extra.pop("compliance_impact", 0),
            "coverage_status": "running",
            **extra,
        }

    def _active_validations(self, policy: PolicyEngine) -> list[str]:
        validations = ["pii_detection", "segmentation"]
        if policy.is_validation_allowed("sqli"):
            validations.append("sqli")
        if policy.is_validation_allowed("path_traversal"):
            validations.append("path_traversal")
        if policy.is_validation_allowed("reflected_html"):
            validations.append("reflected_html_injection")
        if policy.is_validation_allowed("timing"):
            validations.append("timing")
        if policy.is_validation_allowed("auth"):
            validations.extend(
                [
                    "auth",
                    "access_matrix",
                    "bola_idor",
                    "api_exposure",
                    "cors",
                    "username_enumeration",
                    "jwt_integrity_negative_control",
                ]
            )
        return validations

    async def _fail_no_coverage(
        self,
        scan: Scan,
        *,
        reason: str,
        diagnostics: dict[str, Any] | None = None,
    ) -> None:
        scan.status = ScanStatus.FAILED.value
        scan.finished_at = utcnow()
        scan.error = reason
        scan.stats = self._progress(
            phase="No Coverage",
            progress=100,
            message=reason,
            diagnostics=diagnostics or {},
        ) | {
            "coverage_status": "no_coverage",
            "endpoints": 0,
            "findings": 0,
            "reports": 0,
        }
        await self.session.commit()
        await self._dispatch_webhooks(scan, "scan.failed")

    async def _dispatch_webhooks(self, scan: Scan, event: str) -> None:
        """Fire matching webhook subscriptions for a scan lifecycle event."""
        try:
            from sqlalchemy import select as sel

            from app.models import WebhookSubscription
            from app.services.webhook_service import dispatch_webhook

            result = await self.session.execute(
                sel(WebhookSubscription).where(
                    WebhookSubscription.organization_id == scan.organization_id,
                    WebhookSubscription.is_active.is_(True),
                )
            )
            subscriptions = list(result.scalars().all())

            scan_stats = scan.stats or {}
            target = (
                await self.session.get(Target, scan.target_id)
                if scan.target_id
                else None
            )
            payload = {
                "event": event,
                "scan_id": scan.id,
                "target_url": target.base_url if target else None,
                "project_id": scan.project_id,
                "status": scan.status,
                "stats": scan_stats,
                "error": scan.error,
                "findings_count": scan_stats.get("findings", 0),
                "endpoints_count": scan_stats.get("endpoints", 0),
                "finished_at": scan.finished_at.isoformat()
                if scan.finished_at
                else None,
            }

            delivery_errors: list[str] = []
            for sub in subscriptions:
                if event not in (sub.events or []):
                    continue
                status_code = await dispatch_webhook(
                    url=sub.url,
                    event=event,
                    data=payload,
                    secret=sub.secret,
                    extra_headers=sub.headers or None,
                )
                sub.last_delivery_at = utcnow()
                sub.last_delivery_status = status_code
                # dispatch_webhook returns 0 on connection failure and the raw
                # HTTP status otherwise. Anything outside 2xx is a failed
                # delivery that must NOT be swallowed: log it and record it on
                # the scan so a down/misconfigured receiver is visible.
                if not 200 <= status_code < 300:
                    detail = (
                        f"HTTP {status_code}"
                        if status_code
                        else "no response (connection error/timeout)"
                    )
                    msg = f"{event} -> {sub.url}: {detail}"
                    logger.warning("Webhook delivery failed: %s", msg)
                    delivery_errors.append(msg)
                else:
                    logger.info(
                        "Webhook delivered: %s -> %s (HTTP %s)",
                        event,
                        sub.url,
                        status_code,
                    )

            if delivery_errors:
                # Reassign (don't mutate in place): scan.stats is a plain JSON
                # column without mutation tracking, so an in-place append would
                # not be persisted.
                stats = dict(scan.stats or {})
                stats["_webhook_errors"] = (
                    list(stats.get("_webhook_errors") or []) + delivery_errors
                )
                scan.stats = stats
            await self.session.commit()
        except Exception as exc:
            logger.error(
                "Webhook dispatch failed for scan %s (%s): %s",
                scan.id,
                event,
                exc,
                exc_info=True,
            )
            # Best-effort: persist the failure on the scan so it is visible,
            # without letting a follow-on error crash scan completion.
            try:
                stats = dict(scan.stats or {})
                stats["_webhook_errors"] = list(
                    stats.get("_webhook_errors") or []
                ) + [f"{event}: {exc}"]
                scan.stats = stats
                await self.session.commit()
            except Exception:
                logger.exception(
                    "Failed to record webhook dispatch error on scan %s", scan.id
                )
