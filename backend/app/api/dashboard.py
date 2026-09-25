from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import User
from app.schemas.dashboard import DashboardStats, DashboardCharts
from app.services.dashboard_service import DashboardService
from app.api.auth import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve high-level SOC dashboard KPI counters."""
    return DashboardService.get_stats(db)

@router.get("/charts", response_model=DashboardCharts)
def get_dashboard_charts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve chart series for visual threat intelligence & traffic breakdowns."""
    return DashboardService.get_charts(db)
