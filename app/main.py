from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.bootstrap import mark_interrupted_scans, seed_defaults
from app.core.config import get_settings
from app.database.base import Base
from app.database.session import get_engine, get_sessionmaker
from app import models  # noqa: F401
from app.middleware.request_context import RequestContextMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    session_factory = get_sessionmaker()
    if get_settings().database_url.startswith("sqlite"):
        async with get_engine().begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
    async with session_factory() as session:
        await seed_defaults(session)
    if not get_settings().use_celery:
        async with session_factory() as session:
            await mark_interrupted_scans(session)
    yield


settings = get_settings()

app = FastAPI(
    title="NyuwunSewu - Compliance-Driven Security Validation & Privacy Risk Management",
    version="0.1.0",
    description=(
        "Enterprise MVP for lightweight API security validation, privacy exposure detection, "
        "compliance mapping, audit logging, and remediation tracking."
    ),
    lifespan=lifespan,
)

app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in settings.cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(api_router)


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "positioning": "Compliance-driven security validation and privacy risk management",
        "docs": "/docs",
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy"}
