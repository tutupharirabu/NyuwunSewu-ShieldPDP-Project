from fastapi import APIRouter

from app.api import agent_sessions, auth, compliance, dashboard, enterprise, findings, remediation, reports, scans, telegram, webhooks

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(reports.router)
api_router.include_router(remediation.router)
api_router.include_router(compliance.router)
api_router.include_router(dashboard.router)
api_router.include_router(enterprise.router)
api_router.include_router(webhooks.router)
api_router.include_router(agent_sessions.router)
api_router.include_router(telegram.router)
