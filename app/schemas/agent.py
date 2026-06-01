from pydantic import BaseModel, Field


class AgentLogEntry(BaseModel):
    timestamp: str
    level: str = "info"  # info, warning, error, success
    message: str
    action: str | None = None
    details: dict = Field(default_factory=dict)


class AgentSessionCreate(BaseModel):
    scan_id: str | None = None
    target_url: str
    agent_name: str = "phantom"


class AgentSessionResponse(BaseModel):
    id: str
    agent_name: str
    target_url: str
    status: str
    current_action: str | None = None
    logs: list[dict]
    pending_action: dict | None = None
    findings_count: int
    scan_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    created_at: str | None = None


class AgentLogSubmit(BaseModel):
    session_id: str
    level: str = "info"
    message: str
    action: str | None = None
    details: dict = Field(default_factory=dict)


class AgentActionApproval(BaseModel):
    session_id: str
    action: str
    description: str
    risk_level: str = "medium"  # low, medium, high, critical
    request: dict = Field(default_factory=dict)


class AgentActionResponse(BaseModel):
    approved: bool
    action: str
    message: str


class AgentApprovalRequest(BaseModel):
    approved: bool
    notes: str | None = None
