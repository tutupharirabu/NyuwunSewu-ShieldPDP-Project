from sqlalchemy import (
    JSON,
    Boolean,
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
from app.models.enums import TimestampMixin, new_id


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

    organization: Mapped["Organization"] = relationship(back_populates="projects")  # noqa: F821
    owner: Mapped["User | None"] = relationship()  # noqa: F821


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
