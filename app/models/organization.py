from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.enums import TimestampMixin, new_id


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="organization")  # noqa: F821
    projects: Mapped[list["Project"]] = relationship(back_populates="organization")  # noqa: F821


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="role")  # noqa: F821


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

    organization: Mapped[Organization | None] = relationship(back_populates="users")  # noqa: F821
    role: Mapped[Role] = relationship(back_populates="users")  # noqa: F821
