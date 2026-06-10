from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.enums import FindingStatus, TimestampMixin, new_id, now_utc


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
