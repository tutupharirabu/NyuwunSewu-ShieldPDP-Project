from pydantic import BaseModel, Field


class ReportResponse(BaseModel):
    id: str
    project_id: str
    scan_id: str | None
    title: str
    report_type: str
    export_format: str
    report_hash: str
    content: str | None = None

    model_config = {"from_attributes": True}


class ReportGenerateRequest(BaseModel):
    project_id: str
    scan_id: str | None = None
    report_type: str = Field("Compliance Report", pattern="^(Executive Summary|Technical Report|Compliance Report|Remediation Roadmap)$")
    export_format: str = Field("html", pattern="^(html|pdf)$")

