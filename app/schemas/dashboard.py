from pydantic import BaseModel


class DashboardResponse(BaseModel):
    compliance_score: int
    security_score: int
    unresolved_findings: int
    critical_findings: int
    remediation_progress: int
    severity_breakdown: dict[str, int]

