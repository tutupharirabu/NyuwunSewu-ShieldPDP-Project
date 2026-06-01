from typing import Generic, TypeVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.base import Base

ModelT = TypeVar("ModelT", bound=Base)


class AsyncRepository(Generic[ModelT]):
    def __init__(self, session: AsyncSession, model: type[ModelT]):
        self.session = session
        self.model = model

    async def get(self, object_id: str) -> ModelT | None:
        return await self.session.get(self.model, object_id)

    async def add(self, instance: ModelT) -> ModelT:
        self.session.add(instance)
        await self.session.flush()
        return instance

    async def list_by_org(self, organization_id: str, limit: int = 100, offset: int = 0) -> list[ModelT]:
        stmt = (
            select(self.model)
            .where(getattr(self.model, "organization_id") == organization_id)
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

