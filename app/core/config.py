from functools import lru_cache
from typing import Any, Literal

from pydantic import AliasChoices, AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "NyuwunSewu"
    environment: Literal["local", "test", "staging", "production"] = "local"
    debug: bool = False
    secret_key: str = Field("change-me-in-production", min_length=16)
    agent_secret: str | None = Field(
        None,
        # Accept either AGENT_SECRET (docker-compose remap) or the
        # PHANTOM_AGENT_SECRET used directly in .env, so the shared secret
        # resolves the same whether the backend runs bare or in Docker.
        validation_alias=AliasChoices("AGENT_SECRET", "PHANTOM_AGENT_SECRET"),
        description="Shared secret for external agent finding ingestion",
    )
    access_token_ttl_minutes: int = 480

    database_url: str = (
        "postgresql+asyncpg://nyuwunsewu:nyuwunsewu@postgres:5432/nyuwunsewu"
    )
    redis_url: str = "redis://redis:6379/0"
    use_celery: bool = False

    bootstrap_admin_email: str = "admin@nyuwunsewu.local"
    bootstrap_admin_password: str = Field("ChangeMe123!", min_length=10)
    bootstrap_organization_name: str = "Default Organization"

    allow_private_targets: bool = False
    max_crawl_depth: int = 5
    max_crawl_pages: int = 5000
    max_requests_per_second: float = 5.0
    request_timeout_seconds: float = 10.0
    max_response_bytes: int = 1_000_000
    user_agent: str = "NyuwunSewu-MVP/1.0 compliance-validation"

    cors_origins: list[str | AnyHttpUrl] = ["http://localhost:8000"]

    # Telegram integration for agent notifications
    telegram_bot_token: str | None = Field(
        None, description="Telegram bot token for agent notifications"
    )
    telegram_chat_id: str | None = Field(
        None, description="Telegram chat ID for agent notifications"
    )

    # Breach SLA automation (Pasal 46 UU PDP)
    enable_sla_monitor: bool = True
    sla_monitor_interval_seconds: int = 900  # 15 menit
    sla_alert_thresholds: list[int] = [48, 24, 6, 1]  # jam tersisa
    pdp_authority_name: str = "Kementerian Komunikasi dan Digital (Komdigi)"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @field_validator("max_requests_per_second")
    @classmethod
    def clamp_global_rate(cls, value: float) -> float:
        return max(0.2, min(value, 20.0))

    @field_validator("debug", mode="before")
    @classmethod
    def parse_debug_flag(cls, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on", "debug", "dev", "development"}:
                return True
            if normalized in {
                "0",
                "false",
                "no",
                "off",
                "release",
                "prod",
                "production",
            }:
                return False
        return bool(value)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # pydantic-settings reads from env/file
