from typing import Any

from pydantic import BaseModel, Field, field_validator


class PolicyInput(BaseModel):
    name: str | None = None
    max_requests_per_second: float = Field(5.0, ge=0.2, le=20)
    allow_sqli_validation: bool = True
    allow_auth_validation: bool = True
    allow_timing_validation: bool = False
    excluded_paths: list[str] = Field(default_factory=list)
    forbidden_paths: list[str] = Field(default_factory=list)
    scope_boundaries: list[str] = Field(default_factory=list)
    max_depth: int = Field(2, ge=0, le=5)
    max_pages: int = Field(500, ge=1, le=5000)


class CredentialAuthInput(BaseModel):
    login_path: str = Field("/login", max_length=2048)
    username: str = Field(..., min_length=1, max_length=320)
    password: str = Field(..., min_length=1, max_length=2048, repr=False)


class ExploitChainInput(BaseModel):
    enabled: bool = False
    username_candidates: list[str] = Field(
        default_factory=lambda: ["admin", "administrator", "jeruk", "test", "user"],
        max_length=50,
    )
    weak_jwt_secrets: list[str] = Field(
        default_factory=lambda: [
            "secret",
            "jwtsecret",
            "jwt_secret",
            "supersecret",
            "password",
            "admin123",
            "vuln-bank",
            "change-me-in-production",
        ],
        max_length=50,
    )
    admin_paths: list[str] = Field(
        default_factory=lambda: [
            "/admin",
            "/admin/dashboard",
            "/dashboard",
            "/api/admin",
            "/api/admin/analytics",
            "/sup3r_s3cr3t_admin",
            "/manage",
        ],
        max_length=50,
    )
    modern_vuln_bank_probes: bool = True


class ScanStartRequest(BaseModel):
    target_url: str
    project_id: str | None = None
    project_name: str | None = "Default Security Validation Project"
    allowed_domains: list[str] = Field(default_factory=list)
    initial_paths: list[str] = Field(default_factory=list, max_length=20)
    credential_auth: CredentialAuthInput | None = None
    policy: PolicyInput = Field(default_factory=PolicyInput)
    primary_headers: dict[str, str] = Field(default_factory=dict)
    secondary_headers: dict[str, str] = Field(default_factory=dict)
    admin_headers: dict[str, str] = Field(default_factory=dict)
    auditor_headers: dict[str, str] = Field(default_factory=dict)
    custom_role_headers: dict[str, dict[str, str]] = Field(default_factory=dict)
    exploit_chains: ExploitChainInput = Field(default_factory=ExploitChainInput)

    @field_validator("target_url")
    @classmethod
    def target_must_be_http(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("target_url must be http or https")
        return value.rstrip("/")

    @field_validator("initial_paths")
    @classmethod
    def clean_initial_paths(cls, values: list[str]) -> list[str]:
        return [value.strip() for value in values if value.strip()]


class ScanStartResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanStopRequest(BaseModel):
    scan_id: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    target_id: str
    project_id: str
    stats: dict[str, Any]
    error: str | None = None


class RoeUploadResponse(BaseModel):
    roe_document_id: str
    filename: str
    char_count: int
    extraction_warning: bool
