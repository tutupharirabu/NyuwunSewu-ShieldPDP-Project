import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.rbac import RoleName, default_permissions_for
from app.core.security import hash_password, utcnow
from app.models import Organization, Role, Scan, ScanStatus, User


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "default"


async def seed_defaults(session: AsyncSession) -> None:
    settings = get_settings()

    roles_by_name: dict[str, Role] = {}
    for role_name in RoleName:
        role = (
            await session.execute(select(Role).where(Role.name == role_name.value))
        ).scalar_one_or_none()
        if role is None:
            role = Role(name=role_name.value, permissions=default_permissions_for(role_name))
            session.add(role)
        else:
            role.permissions = default_permissions_for(role_name)
        roles_by_name[role_name.value] = role

    await session.flush()

    org = (
        await session.execute(
            select(Organization).where(
                Organization.slug == slugify(settings.bootstrap_organization_name)
            )
        )
    ).scalar_one_or_none()
    if org is None:
        org = Organization(
            name=settings.bootstrap_organization_name,
            slug=slugify(settings.bootstrap_organization_name),
        )
        session.add(org)
        await session.flush()

    admin = (
        await session.execute(
            select(User).where(
                User.email == settings.bootstrap_admin_email,
                User.organization_id == org.id,
            )
        )
    ).scalar_one_or_none()
    if admin is None:
        session.add(
            User(
                organization_id=org.id,
                role_id=roles_by_name[RoleName.SUPER_ADMIN.value].id,
                email=settings.bootstrap_admin_email,
                full_name="NyuwunSewu Administrator",
                hashed_password=hash_password(settings.bootstrap_admin_password),
            )
        )

    await session.commit()


async def mark_interrupted_scans(session: AsyncSession) -> None:
    """Recover local in-process scans that cannot survive an app restart."""
    result = await session.execute(
        select(Scan).where(
            Scan.status.in_(
                [
                    ScanStatus.QUEUED.value,
                    ScanStatus.RUNNING.value,
                    ScanStatus.STOPPING.value,
                ]
            )
        )
    )
    scans = list(result.scalars().all())
    if not scans:
        return

    now = utcnow()
    for scan in scans:
        scan.status = ScanStatus.FAILED.value
        scan.finished_at = now
        scan.error = "Interrupted by application restart before scan completion."
        scan.stop_requested = False
        scan.stats = {
            **(scan.stats or {}),
            "phase": "Interrupted",
            "progress_percentage": 100,
            "message": scan.error,
            "coverage_status": "interrupted",
        }

    await session.commit()
