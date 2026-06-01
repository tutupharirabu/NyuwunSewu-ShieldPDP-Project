#!/usr/bin/env python3
"""Initialize the database manually before starting the server."""
import os
import asyncio
import sys

os.chdir("/root/NyuwunSewu-ShieldPDP-Project")
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./nyuwunsewu_prod.db"
os.environ["ALLOW_PRIVATE_TARGETS"] = "true"
os.environ["USE_CELERY"] = "false"
# AGENT_SECRET and other settings will be loaded from .env by Settings

from app.database.base import Base
from app.database.session import engine
from app import models  # noqa: F401
from app.core.bootstrap import seed_defaults
from app.database.session import AsyncSessionLocal

async def init_db():
    print("Creating database tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Tables created successfully!")
    
    print("Seeding default data...")
    async with AsyncSessionLocal() as session:
        await seed_defaults(session)
        await session.commit()
    print("Default data seeded!")
    print("Database ready for server startup.")

if __name__ == "__main__":
    asyncio.run(init_db())
