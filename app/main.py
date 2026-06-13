from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.api.router import api_router
from app.core.bootstrap import mark_interrupted_scans, seed_defaults
from app.core.config import get_settings
from app.database.base import Base
from app.database.session import get_engine, get_sessionmaker
from app import models  # noqa: F401
from app.middleware.http_cache import HTTPCacheMiddleware
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
# ETag + Cache-Control on JSON GETs so polls/reloads revalidate cheaply (304 when
# unchanged) instead of re-downloading the full body. Added before GZip so it is
# *inner* to it — the ETag is computed over the uncompressed body (a stable weak
# validator regardless of Accept-Encoding).
app.add_middleware(HTTPCacheMiddleware)
# API JSON responses were served uncompressed (Content-Encoding: none), so large
# payloads like /api/findings (~367 KB) and /api/scans crossed the wire raw and
# dominated load time over the Tailscale link. JSON compresses ~90%; only bodies
# over `minimum_size` bytes are touched, so small responses stay untouched.
app.add_middleware(GZipMiddleware, minimum_size=1000)
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
