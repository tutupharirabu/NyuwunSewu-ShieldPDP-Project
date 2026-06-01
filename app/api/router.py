from fastapi import APIRouter

from app.api import auth, compliance, dashboard, enterprise, findings, remediation, reports, scans

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(reports.router)
api_router.include_router(remediation.router)
api_router.include_router(compliance.router)
api_router.include_router(dashboard.router)
api_router.include_router(enterprise.router)
