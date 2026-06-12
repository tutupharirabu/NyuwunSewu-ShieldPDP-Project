"""Scan CRUD / lifecycle (API-facing).

Split from ``scan_service`` so the request-path create/stop logic lives apart
from the long-running ``ScanRunner`` execution engine.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import Policy, Project, Scan, ScanStatus, Target, User
from app.services.audit_service import AuditService


class ScanService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.audit = AuditService(session)

    async def create_scan(
        self,
        *,
        user: User,
        target_url: str,
        project_name: str | None,
        project_id: str | None,
        policy_payload: dict[str, Any] | None,
        allowed_domains: list[str] | None,
        ip_address: str | None,
        engagement_mode: str = "internal",
        roe_document_id: str | None = None,
    ) -> Scan:
        if not user.organization_id:
            raise ValueError("User must belong to an organization to start scans")
        roe_basis: str | None = None
        if engagement_mode == "internal":
            if roe_document_id:
                raise ValueError("RoE documents apply only to external engagements")
        elif engagement_mode == "external":
            if roe_document_id:
                from app.models import RoeDocument

                doc = await self.session.get(RoeDocument, roe_document_id)
                if doc is None or doc.organization_id != user.organization_id:
                    raise ValueError("RoE document not found in organization scope")
                roe_basis = "document"
            else:
                roe_basis = "default_roe_v1"
        else:
            raise ValueError(f"Unknown engagement_mode: {engagement_mode}")
        project = await self._resolve_project(user, project_id, project_name)
        target = await self._resolve_target(
            user.organization_id, project.id, target_url, allowed_domains
        )
        policy = await self._create_policy(
            user.organization_id, project.id, policy_payload
        )

        scan = Scan(
            organization_id=user.organization_id,
            project_id=project.id,
            target_id=target.id,
            policy_id=policy.id,
            started_by_id=user.id,
            status=ScanStatus.QUEUED.value,
            engagement_mode=engagement_mode,
            roe_document_id=roe_document_id if engagement_mode == "external" else None,
            roe_basis=roe_basis,
            stats={
                "phase": "Queued",
                "progress_percentage": 0,
                "message": "Queued for validation",
                "coverage_status": "queued",
                "endpoints_discovered": 0,
                "parameters_discovered": 0,
                "findings_discovered": 0,
            },
        )
        self.session.add(scan)
        await self.session.flush()
        await self.audit.log(
            action="scan.start",
            resource_type="scan",
            resource_id=scan.id,
            user=user,
            ip_address=ip_address,
            metadata={"target": target.base_url, "project_id": project.id},
        )
        await self.session.commit()
        return scan

    async def request_stop(
        self, *, scan: Scan, user: User, ip_address: str | None
    ) -> Scan:
        scan.stop_requested = True
        scan.status = ScanStatus.STOPPING.value
        await self.audit.log(
            action="scan.stop",
            resource_type="scan",
            resource_id=scan.id,
            user=user,
            ip_address=ip_address,
        )
        await self.session.commit()
        return scan

    async def _resolve_project(
        self, user: User, project_id: str | None, project_name: str | None
    ) -> Project:
        if project_id:
            result = await self.session.execute(
                select(Project).where(
                    Project.id == project_id,
                    Project.organization_id == user.organization_id,
                    Project.is_active.is_(True),
                )
            )
            project = result.scalar_one_or_none()
            if not project:
                raise ValueError("Project not found in organization scope")
            return project

        name = project_name or "Default Security Validation Project"
        result = await self.session.execute(
            select(Project).where(
                Project.organization_id == user.organization_id,
                Project.name == name,
            )
        )
        project = result.scalar_one_or_none()
        if project is None:
            project = Project(
                organization_id=user.organization_id,
                owner_id=user.id,
                name=name,
                description="Created by scan start workflow",
            )
            self.session.add(project)
            await self.session.flush()
        return project

    async def _resolve_target(
        self,
        organization_id: str,
        project_id: str,
        target_url: str,
        allowed_domains: list[str] | None,
    ) -> Target:
        result = await self.session.execute(
            select(Target).where(
                Target.organization_id == organization_id,
                Target.project_id == project_id,
                Target.base_url == target_url,
            )
        )
        target = result.scalar_one_or_none()
        if target is None:
            target = Target(
                organization_id=organization_id,
                project_id=project_id,
                base_url=target_url,
                allowed_domains=allowed_domains or [],
            )
            self.session.add(target)
            await self.session.flush()
        return target

    async def _create_policy(
        self, organization_id: str, project_id: str, payload: dict[str, Any] | None
    ) -> Policy:
        payload = payload or {}
        settings = get_settings()
        policy = Policy(
            organization_id=organization_id,
            project_id=project_id,
            name=payload.get("name") or "Default MVP Safe Scan Policy",
            max_requests_per_second=min(
                float(
                    payload.get(
                        "max_requests_per_second", settings.max_requests_per_second
                    )
                ),
                settings.max_requests_per_second,
            ),
            allow_sqli_validation=bool(payload.get("allow_sqli_validation", True)),
            allow_auth_validation=bool(payload.get("allow_auth_validation", True)),
            allow_timing_validation=bool(payload.get("allow_timing_validation", False)),
            excluded_paths=list(payload.get("excluded_paths", [])),
            forbidden_paths=list(payload.get("forbidden_paths", [])),
            scope_boundaries=list(payload.get("scope_boundaries", [])),
            max_depth=int(payload.get("max_depth", settings.max_crawl_depth)),
            max_pages=int(payload.get("max_pages", settings.max_crawl_pages)),
        )
        self.session.add(policy)
        await self.session.flush()
        return policy

