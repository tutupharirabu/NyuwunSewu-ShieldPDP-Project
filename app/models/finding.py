from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.enums import FindingStatus, Severity, TimestampMixin, new_id, now_utc


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
