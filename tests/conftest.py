import asyncio
import os
from pathlib import Path

import pytest

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_nyuwunsewu.db")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-nyuwunsewu")
os.environ.setdefault("AGENT_SECRET", "test-agent-secret-for-nyuwunsewu")
os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL", "admin@nyuwunsewu.local")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe123!")


@pytest.fixture(scope="session", autouse=True)
def initialize_database():
    from app.database.base import Base
    from app.database.session import engine

    async def _init():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_init())
    yield
    asyncio.run(engine.dispose())
    db_file = Path("test_nyuwunsewu.db")
    if db_file.exists():
        db_file.unlink()
