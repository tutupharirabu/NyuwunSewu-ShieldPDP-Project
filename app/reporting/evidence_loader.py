from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Evidence


async def load_evidence_by_finding_id(
    session: AsyncSession,
    *,
    organization_id: str,
    findings: list[Any],
) -> dict[str, Evidence]:
    finding_ids = [str(getattr(finding, "id", "")) for finding in findings]
    finding_ids = [finding_id for finding_id in finding_ids if finding_id]
    if not finding_ids:
        return {}

    result = await session.execute(
        select(Evidence)
        .where(
            Evidence.organization_id == organization_id,
            Evidence.finding_id.in_(finding_ids),
        )
        .order_by(Evidence.captured_at.desc())
    )
    evidence_by_finding_id: dict[str, Evidence] = {}
    for evidence in result.scalars().all():
        if evidence.finding_id:
            evidence_by_finding_id.setdefault(evidence.finding_id, evidence)
    return evidence_by_finding_id
