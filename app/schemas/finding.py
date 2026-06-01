from datetime import datetime
from typing import Any

from pydantic import BaseModel


class FindingResponse(BaseModel):
    id: str
    project_id: str
    target_id: str
    scan_id: str
    endpoint_id: str | None
    endpoint_url: str | None = None
    finding_type: str
    title: str
    severity: str
    status: str
    confidence: float
    risk_score: float
    description: str
    reasoning: list[str]
    evidence_summary: dict[str, Any]
    compliance: list[dict[str, Any]]
    remediation_guidance: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingEvidenceResponse(BaseModel):
    immutable_id: str
    finding_id: str | None
    raw_request: dict[str, Any]
    raw_response: dict[str, Any]
    headers: dict[str, Any]
    reproduction_steps: list[str]
    curl_reproduction: str
    evidence_hash: str
    captured_at: datetime

    model_config = {"from_attributes": True}


class FindingEvidencePeekResponse(BaseModel):
    immutable_id: str
    raw_request_full: dict[str, Any]
    raw_response_full: dict[str, Any]
    captured_at: datetime

    model_config = {"from_attributes": True}
