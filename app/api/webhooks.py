"""Webhook subscription management API."""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_ip, require_permission
from app.core.rbac import Permission
from app.database.session import get_session
from app.models import User, WebhookSubscription
from app.repositories.domain import DomainRepository
from app.schemas.webhook import WebhookCreate, WebhookResponse, WebhookUpdate

router = APIRouter(tags=["webhooks"])


@router.get("/webhooks", response_model=list[WebhookResponse])
async def list_webhooks(
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> list[WebhookSubscription]:
    result = await session.execute(
        select(WebhookSubscription)
        .where(WebhookSubscription.organization_id == user.organization_id)
        .order_by(WebhookSubscription.created_at.desc())
    )
    return list(result.scalars().all())


@router.post(
    "/webhooks",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_webhook(
    payload: WebhookCreate,
    user: User = Depends(require_permission(Permission.SCAN_CREATE)),
    session: AsyncSession = Depends(get_session),
) -> WebhookSubscription:
    webhook = WebhookSubscription(
        organization_id=user.organization_id,
        name=payload.name,
        url=payload.url,
        secret=payload.secret,
        events=payload.events,
        headers=payload.headers,
    )
    session.add(webhook)
    await session.commit()
    await session.refresh(webhook)
    return webhook


@router.get("/webhooks/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: str,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> WebhookSubscription:
    repo = DomainRepository(session)
    result = await session.execute(
        select(WebhookSubscription).where(
            WebhookSubscription.id == webhook_id,
            WebhookSubscription.organization_id == user.organization_id,
        )
    )
    webhook = result.scalar_one_or_none()
    if webhook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return webhook


@router.patch("/webhooks/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: str,
    payload: WebhookUpdate,
    user: User = Depends(require_permission(Permission.SCAN_CREATE)),
    session: AsyncSession = Depends(get_session),
) -> WebhookSubscription:
    result = await session.execute(
        select(WebhookSubscription).where(
            WebhookSubscription.id == webhook_id,
            WebhookSubscription.organization_id == user.organization_id,
        )
    )
    webhook = result.scalar_one_or_none()
    if webhook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(webhook, field, value)

    await session.commit()
    await session.refresh(webhook)
    return webhook


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: str,
    user: User = Depends(require_permission(Permission.SCAN_CREATE)),
    session: AsyncSession = Depends(get_session),
) -> None:
    result = await session.execute(
        select(WebhookSubscription).where(
            WebhookSubscription.id == webhook_id,
            WebhookSubscription.organization_id == user.organization_id,
        )
    )
    webhook = result.scalar_one_or_none()
    if webhook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await session.delete(webhook)
    await session.commit()
