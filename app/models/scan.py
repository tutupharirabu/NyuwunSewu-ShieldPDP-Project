from datetime import datetime
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
from app.models.enums import EngagementMode, ScanStatus, TimestampMixin, new_id, now_utc


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
    engagement_mode: Mapped[str] = mapped_column(
        String(16), default=EngagementMode.INTERNAL.value, nullable=False
    )
    roe_document_id: Mapped[str | None] = mapped_column(
        ForeignKey("roe_documents.id"), nullable=True
    )
    roe_basis: Mapped[str | None] = mapped_column(String(32), nullable=True)

    project: Mapped["Project"] = relationship()  # noqa: F821
    target: Mapped["Target"] = relationship()  # noqa: F821
    policy: Mapped["Policy"] = relationship()  # noqa: F821
    started_by: Mapped["User"] = relationship()  # noqa: F821


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
