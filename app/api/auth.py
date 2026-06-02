from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.concurrency import run_in_threadpool

from app.api.deps import current_ip, get_current_user, require_permission
from app.core.config import get_settings
from app.core.rbac import Permission
from app.core.security import (
    create_access_token,
    hash_password,
    utcnow,
    verify_password,
)
from app.database.session import get_session
from app.models import Organization, Role, User
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    UserCreateRequest,
    UserResponse,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    payload = await _login_payload(request)
    stmt = (
        select(User)
        .options(selectinload(User.role), selectinload(User.organization))
        .where(
            User.email == payload.email,
            User.is_active.is_(True),
        )
    )
    if payload.organization_slug:
        org_result = await session.execute(
            select(Organization).where(Organization.slug == payload.organization_slug)
        )
        org = org_result.scalar_one_or_none()
        if org is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )
        stmt = stmt.where(User.organization_id == org.id)

    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    # PBKDF2 is CPU-intensive — run in threadpool to avoid blocking the event loop
    password_valid = await run_in_threadpool(
        verify_password, payload.password, user.hashed_password
    )
    if not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    user.last_login_at = utcnow()
    await AuditService(session).log(
        action="login",
        resource_type="user",
        resource_id=user.id,
        user=user,
        ip_address=current_ip(request),
    )
    await session.commit()

    settings = get_settings()
    token = create_access_token(user.id, user.organization_id, user.role.name)
    return TokenResponse(
        access_token=token, expires_in_minutes=settings.access_token_ttl_minutes
    )


async def _login_payload(request: Request) -> LoginRequest:
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        data = await request.json()
        return LoginRequest.model_validate(data)

    form = await request.form()
    return LoginRequest(
        email=str(form.get("username") or form.get("email") or ""),
        password=str(form.get("password") or ""),
        organization_slug=(
            str(form.get("organization_slug"))
            if form.get("organization_slug")
            else "default-organization"
        ),
    )


@router.post("/logout")
async def logout(
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    await AuditService(session).log(
        action="logout",
        resource_type="user",
        resource_id=user.id,
        user=user,
        ip_address=current_ip(request),
    )
    await session.commit()
    return {"status": "ok"}


@router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse(
        id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        full_name=user.full_name,
        role=user.role.name,
        permissions=user.role.permissions,
    )


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    user: User = Depends(require_permission(Permission.ADMIN)),
    session: AsyncSession = Depends(get_session),
) -> list[UserResponse]:
    result = await session.execute(
        select(User)
        .options(selectinload(User.role))
        .where(User.organization_id == user.organization_id)
        .order_by(User.email)
    )
    rows = list(result.scalars().all())
    return [
        UserResponse(
            id=row.id,
            organization_id=row.organization_id,
            email=row.email,
            full_name=row.full_name,
            role=row.role.name,
            permissions=row.role.permissions,
        )
        for row in rows
    ]


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreateRequest,
    request: Request,
    user: User = Depends(require_permission(Permission.ADMIN)),
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    existing = (
        await session.execute(
            select(User).where(
                User.organization_id == user.organization_id,
                User.email == payload.email,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="User already exists"
        )

    role = (
        await session.execute(select(Role).where(Role.name == payload.role))
    ).scalar_one_or_none()
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown role"
        )

    created = User(
        organization_id=user.organization_id,
        role_id=role.id,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
    )
    session.add(created)
    await session.flush()
    await AuditService(session).log(
        action="user.create",
        resource_type="user",
        resource_id=created.id,
        user=user,
        ip_address=current_ip(request),
        metadata={"created_email": payload.email, "role": role.name},
    )
    await session.commit()
    return UserResponse(
        id=created.id,
        organization_id=created.organization_id,
        email=created.email,
        full_name=created.full_name,
        role=role.name,
        permissions=role.permissions,
    )
