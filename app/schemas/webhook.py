from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class WebhookCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., min_length=1, max_length=2048)
    secret: str | None = Field(None, max_length=512)
    events: list[str] = Field(
        default_factory=lambda: ["scan.completed", "scan.failed"],
        max_length=20,
    )
    headers: dict[str, str] = Field(default_factory=dict)


class WebhookUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    url: str | None = Field(None, min_length=1, max_length=2048)
    secret: str | None = Field(None, max_length=512)
    events: list[str] | None = Field(None, max_length=20)
    headers: dict[str, str] | None = None
    is_active: bool | None = None


class WebhookResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    url: str
    events: list[str]
    is_active: bool
    last_delivery_at: datetime | None = None
    last_delivery_status: int | None = None


class AgentFindingIngest(BaseModel):
    """Finding submitted by an external agent (e.g. Phantom)."""

    scan_id: str | None = Field(
        None,
        description=(
            "Existing scan to attach the finding to. Required: the owning "
            "organization is resolved strictly from this scan (the shared agent "
            "secret carries no tenant identity)."
        ),
    )
    target_url: str | None = Field(
        None,
        description="Informational only; the tenant is resolved from scan_id, not this.",
    )
    finding_type: str = Field(..., max_length=120)
    title: str = Field(..., min_length=1, max_length=255)
    severity: str = Field("medium", pattern="^(info|low|medium|high|critical)$")
    confidence: float = Field(50.0, ge=0.0, le=100.0)
    description: str = Field(..., min_length=1)
    reasoning: list[str] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)
    request_method: str | None = Field(None)
    request_url: str | None = Field(None)
    request_headers: dict | None = Field(None)
    request_body: str | None = Field(None)
    response_status: int | None = Field(None)
    response_headers: dict | None = Field(None)
    response_body: str | None = Field(None)
    remediation: str | None = Field(None)
    agent_name: str | None = Field(
        None, description="Name of the agent that found this"
    )
    exploit_chain: list[str] = Field(
        default_factory=list, description="Steps taken to exploit"
    )


class AgentFindingResponse(BaseModel):
    finding_id: str
    status: str
    message: str
