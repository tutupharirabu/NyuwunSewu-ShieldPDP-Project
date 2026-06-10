from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.enums import new_id, now_utc


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
