import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, mapped_column


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
