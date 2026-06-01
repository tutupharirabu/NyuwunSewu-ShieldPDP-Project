from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ProjectSummaryResponse(BaseModel):
    id: str
    name: str
    description: str | None
    is_active: bool
    targets: int
    scans: int
    findings: int
    created_at: datetime


class TargetSummaryResponse(BaseModel):
    id: str
    project_id: str
    base_url: str
    allowed_domains: list[str]
    is_active: bool
    scans: int
    findings: int
    created_at: datetime


class ScanListResponse(BaseModel):
    id: str
    project_id: str
    project_name: str | None = None
    target_id: str
    target_url: str | None = None
    status: str
    stats: dict[str, Any]
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    error: str | None = None


class ScanDetailResponse(ScanListResponse):
    policy_id: str
    stop_requested: bool


class EndpointInventoryResponse(BaseModel):
    id: str
    scan_id: str
    url: str
    method: str
    normalized_path: str
    status_code: int | None
    title: str | None
    content_type: str | None
    query_parameters: list[str]
    forms: list[dict[str, Any]]
    tech_stack: list[str]
    classifications: list[dict[str, Any]]
    risk_score: float
    finding_count: int
    highest_severity: str | None = None
    highest_confidence: float | None = None
    finding_types: list[str]
    finding_titles: list[str]
    created_at: datetime


class RemediationListResponse(BaseModel):
    id: str
    finding_id: str
    title: str
    severity: str
    status: str
    assignee_id: str | None
    notes: str | None
    retest_scan_id: str | None
    updated_at: datetime


class AuditLogResponse(BaseModel):
    id: str
    timestamp: datetime
    user_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    ip_address: str | None
    metadata_json: dict[str, Any]
    entry_hash: str
