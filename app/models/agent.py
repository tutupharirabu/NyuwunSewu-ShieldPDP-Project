from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.enums import TimestampMixin, new_id, now_utc


class AgentSession(Base, TimestampMixin):
    """Tracks agent exploration sessions with real-time logs and approval workflow."""

    __tablename__ = "agent_sessions"
    __table_args__ = (
        Index("ix_agent_session_org_status", "organization_id", "status"),
        Index("ix_agent_session_scan", "scan_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id"), nullable=True, index=True
    )
    agent_name: Mapped[str] = mapped_column(
        String(120), nullable=False, default="phantom"
    )
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), default="idle", nullable=False
    )  # idle, exploring, pending_approval, approved, denied, completed, failed
    current_action: Mapped[str | None] = mapped_column(String(512))
    logs: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    pending_action: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebhookSubscription(Base, TimestampMixin):
    """External webhook endpoints notified on scan lifecycle events."""

    __tablename__ = "webhook_subscriptions"
    __table_args__ = (Index("ix_webhook_org_active", "organization_id", "is_active"),)

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
    headers: Mapped[dict[str, str]] = mapped_column(JSON, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_delivery_status: Mapped[int | None] = mapped_column(Integer)


class BreachNotification(Base, TimestampMixin):
    """Tracks data breach notifications per Pasal 46 UU PDP (3x24h SLA)."""

    __tablename__ = "breach_notifications"
    __table_args__ = (
        Index("ix_breach_org_status", "organization_id", "status"),
        Index("ix_breach_org_deadline", "organization_id", "sla_deadline"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    finding_ids: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="List of Finding IDs that triggered this breach assessment",
    )
    breach_title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    breach_type: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        default="detected",
        nullable=False,
        comment="detected, assessing, notified, overdue, dismissed",
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )
    sla_deadline: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="3x24 hours from detected_at per Pasal 46 UU PDP",
    )
    notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When notification was actually sent",
    )
    notification_channels: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="Channels used: telegram, email, dashboard",
    )
    pii_types_affected: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="Types of personal data affected (nik, npwp, etc.)",
    )
    data_subjects_estimate: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Estimated number of affected data subjects",
    )
    notification_text: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Generated notification text per Pasal 46 requirements",
    )
    actions_taken: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="Remediation actions already taken or planned",
    )
    contact_info: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Contact information for the data controller"
    )
    dismissed_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Reason if breach was dismissed as non-notifiable"
    )
    compliance_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="Evidence of compliance: timestamps, delivery confirmations, etc.",
    )
