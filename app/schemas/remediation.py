from pydantic import BaseModel


class RemediationUpdateRequest(BaseModel):
    status: str
    assignee_id: str | None = None
    notes: str | None = None


class RemediationResponse(BaseModel):
    id: str
    finding_id: str
    assignee_id: str | None
    status: str
    notes: str | None
    retest_scan_id: str | None

    model_config = {"from_attributes": True}


class RetestRequest(BaseModel):
    finding_id: str
    run_scan: bool = True


class RetestResponse(BaseModel):
    remediation_id: str
    status: str
    scan_id: str | None = None

