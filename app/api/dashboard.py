from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import Permission
from app.database.session import get_session
from app.dashboard.service import DashboardService
from app.models import User
from app.schemas.dashboard import DashboardResponse

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/dashboard", response_model=DashboardResponse)
async def dashboard(
    target_id: str | None = None,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
) -> DashboardResponse:
    data = await DashboardService(session).overview(user.organization_id, target_id)
    return DashboardResponse(**data)


@router.get("/ui/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_ui(
    request: Request,
    target_id: str | None = None,
    user: User = Depends(require_permission(Permission.READ_DASHBOARD)),
    session: AsyncSession = Depends(get_session),
):
    data = await DashboardService(session).overview(user.organization_id, target_id)
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"dashboard": data, "user": user},
    )
