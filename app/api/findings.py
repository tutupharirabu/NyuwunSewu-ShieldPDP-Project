import hmac

from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.config import get_settings
from app.core.rbac import Permission
from app.database.session import get_session
from app.models import Endpoint, Evidence, Finding, User
from app.repositories.domain import DomainRepository
from app.schemas.finding import (
    FindingEvidencePeekResponse,
    FindingEvidenceResponse,
    FindingResponse,
)
from app.schemas.webhook import AgentFindingIngest, AgentFindingResponse

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


def _verify_agent_auth(x_agent_secret: str | None) -> bool:
    """Verify the agent's shared secret for finding ingestion."""
    if not x_agent_secret:
        return False
    settings = get_settings()
    agent_secret = getattr(settings, "agent_secret", None)
    if agent_secret and hmac.compare_digest(x_agent_secret, agent_secret):
        return True
    # Fallback: check if it matches the app secret_key (convenient for local dev)
    return hmac.compare_digest(x_agent_secret, settings.secret_key)


@router.post(
    "/findings/ingest",
    response_model=AgentFindingResponse,
    status_code=status.HTTP_201_CREATED,
)
async def ingest_agent_finding(
    payload: AgentFindingIngest,
    x_agent_secret: str | None = Header(None),
    session: AsyncSession = Depends(get_session),
) -> AgentFindingResponse:
    """Accept a finding submitted by an external agent (e.g. Phantom).

    Authentication is via ``X-Agent-Secret`` header matching the configured
    ``AGENT_SECRET`` (or falls back to ``SECRET_KEY`` for local development).
    """
    if not _verify_agent_auth(x_agent_secret):
        raise HTTPException(status_code=401, detail="Invalid agent secret")

    # Resolve target and scan if provided
    target_id = None
    scan_id = None
    organization_id = None
    project_id = None

    if payload.scan_id:
        from app.models import Scan, Target

        scan_result = await session.execute(
            select(Scan).where(Scan.id == payload.scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        if scan:
            scan_id = scan.id
            target_id = scan.target_id
            organization_id = scan.organization_id
            project_id = scan.project_id
        else:
            raise HTTPException(status_code=404, detail=f"Scan {payload.scan_id} not found")

    if not organization_id:
        # Use the default organization for agent-submitted findings
        from app.models import Organization

        org_result = await session.execute(select(Organization).limit(1))
        org = org_result.scalar_one_or_none()
        if not org:
            raise HTTPException(status_code=400, detail="No organization found; run a scan first to bootstrap")
        organization_id = org.id

    severity = payload.severity.lower()
    finding = Finding(
        organization_id=organization_id,
        project_id=project_id or "00000000-0000-0000-0000-000000000000",
        target_id=target_id or "00000000-0000-0000-0000-000000000000",
        scan_id=scan_id,
        endpoint_id=None,
        finding_type=payload.finding_type,
        title=payload.title,
        severity=severity,
        confidence=payload.confidence,
        risk_score=_severity_to_risk_score(severity),
        description=payload.description,
        reasoning=payload.reasoning,
        evidence_summary={
            "source": "agent",
            "agent_name": payload.agent_name or "phantom",
            "exploit_chain": payload.exploit_chain,
            "evidence": payload.evidence,
            "request": {
                "method": payload.request_method,
                "url": payload.request_url,
                "headers": _redact_sensitive(payload.request_headers),
                "body": payload.request_body,
            } if payload.request_url else None,
            "response": {
                "status": payload.response_status,
                "headers": _redact_sensitive(payload.response_headers),
                "body": payload.response_body,
            } if payload.response_status is not None else None,
        },
        compliance=[],
        remediation_guidance=payload.remediation or "Review and remediate the identified vulnerability.",
    )
    session.add(finding)
    await session.commit()
    await session.refresh(finding)

    return AgentFindingResponse(
        finding_id=finding.id,
        status=finding.status,
        message=f"Finding ingested: {payload.title}",
    )


def _severity_to_risk_score(severity: str) -> float:
    mapping = {"info": 1.0, "low": 3.0, "medium": 5.0, "high": 8.0, "critical": 10.0}
    return mapping.get(severity, 5.0)


def _redact_sensitive(headers: dict | None) -> dict | None:
    if not headers:
        return headers
    sensitive = {"authorization", "cookie", "x-api-key", "x-agent-secret"}
    return {k: "[REDACTED]" if k.lower() in sensitive else v for k, v in headers.items()}
