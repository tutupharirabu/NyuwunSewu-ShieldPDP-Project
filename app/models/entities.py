import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def new_id() -> str:
    return str(uuid.uuid4())


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(str, Enum):
    OPEN = "Open"
    ASSIGNED = "Assigned"
    IN_PROGRESS = "In Progress"
    RETEST = "Re-Test"
    CLOSED = "Closed"
    ACCEPTED_RISK = "Accepted Risk"
    FALSE_POSITIVE = "False Positive"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False
    )


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="organization")
    projects: Mapped[list["Project"]] = relationship(back_populates="organization")


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="role")


class User(Base, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("organization_id", "email", name="uq_org_email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    role_id: Mapped[str] = mapped_column(
        ForeignKey("roles.id"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization | None] = relationship(back_populates="users")
    role: Mapped[Role] = relationship(back_populates="users")


class Project(Base, TimestampMixin):
    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_org_project_name"),
        Index("ix_project_org_owner", "organization_id", "owner_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="projects")
    owner: Mapped[User | None] = relationship()


class Target(Base, TimestampMixin):
    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "project_id", "base_url", name="uq_target_url"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    allowed_domains: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    project: Mapped[Project] = relationship()


class Policy(Base, TimestampMixin):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    project_id: Mapped[str | None] = mapped_column(
        ForeignKey("projects.id"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    max_requests_per_second: Mapped[float] = mapped_column(
        Float, default=5.0, nullable=False
    )
    allow_sqli_validation: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    allow_auth_validation: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    allow_timing_validation: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    excluded_paths: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    forbidden_paths: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    scope_boundaries: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    max_depth: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    max_pages: Mapped[int] = mapped_column(Integer, default=500, nullable=False)


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scan_org_project_status", "organization_id", "project_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id"), nullable=False)
    started_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), default=ScanStatus.QUEUED.value, nullable=False
    )
    celery_task_id: Mapped[str | None] = mapped_column(String(255))
    stop_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)

    project: Mapped[Project] = relationship()
    target: Mapped[Target] = relationship()
    policy: Mapped[Policy] = relationship()
    started_by: Mapped[User] = relationship()


class Endpoint(Base, TimestampMixin):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("scan_id", "method", "url", name="uq_scan_endpoint"),
        Index("ix_endpoint_org_project", "organization_id", "project_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(12), default="GET", nullable=False)
    normalized_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(512))
    content_type: Mapped[str | None] = mapped_column(String(255))
    query_parameters: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    forms: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    tech_stack: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    classifications: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (
        Index(
            "ix_finding_org_status_severity", "organization_id", "status", "severity"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id"), nullable=False, index=True
    )
    endpoint_id: Mapped[str | None] = mapped_column(
        ForeignKey("endpoints.id"), nullable=True
    )
    finding_type: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(24), default=Severity.LOW.value, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), default=FindingStatus.OPEN.value, nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    reasoning: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    evidence_summary: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    compliance: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    remediation_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    is_false_positive: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )


class Evidence(Base, TimestampMixin):
    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("immutable_id", name="uq_evidence_immutable_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    immutable_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id"), nullable=True
    )
    raw_request: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    raw_response: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    raw_request_full: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    raw_response_full: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    reproduction_steps: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    curl_reproduction: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )


class ComplianceMapping(Base, TimestampMixin):
    __tablename__ = "compliance_mapping"
    __table_args__ = (
        Index("ix_compliance_org_framework", "organization_id", "framework"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False)
    framework: Mapped[str] = mapped_column(String(120), nullable=False)
    article_or_control: Mapped[str] = mapped_column(String(120), nullable=False)
    privacy_risk: Mapped[str] = mapped_column(Text, nullable=False)
    legal_risk: Mapped[str] = mapped_column(Text, nullable=False)
    business_risk: Mapped[str] = mapped_column(Text, nullable=False)


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    generated_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    export_format: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    report_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class RemediationTracking(Base, TimestampMixin):
    __tablename__ = "remediation_tracking"
    __table_args__ = (UniqueConstraint("finding_id", name="uq_remediation_finding"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False)
    assignee_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default=FindingStatus.OPEN.value, nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text)
    retest_scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id"), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_org_action_time", "organization_id", "action", "timestamp"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False, index=True
    )
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    organization_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    ip_address: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)



class WebhookSubscription(Base, TimestampMixin):
    """External webhook endpoints notified on scan lifecycle events."""
    __tablename__ = "webhook_subscriptions"
    __table_args__ = (
        Index("ix_webhook_org_active", "organization_id", "is_active"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    secret: Mapped[str | None] = mapped_column(String(512))  # HMAC signing key
    events: Mapped[list[str]] = mapped_column(
        JSON, default=lambda: ["scan.completed", "scan.failed"], nullable=False
    )
    headers: Mapped[dict[str, str]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_delivery_status: Mapped[int | None] = mapped_column(Integer)
