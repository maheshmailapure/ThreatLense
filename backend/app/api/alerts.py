from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from app.database.database import get_db
from app.database.models import User
from app.schemas.alerts import AlertStatusUpdate
from app.services.alert_service import AlertService
from app.api.auth import get_current_user

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("")
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    risk_level: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve filtered, paginated security alerts queue."""
    return AlertService.get_paginated_alerts(
        db=db,
        page=page,
        page_size=page_size,
        risk_level=risk_level,
        status=status,
        search=search
    )

@router.get("/{alert_id}")
def get_alert_detail(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve full incident details for an individual alert."""
    alert_data = AlertService.get_alert_by_id(alert_id, db)
    if not alert_data:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_data

@router.put("/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    status_update: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update alert triage status (NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
    return AlertService.update_status(alert_id, status_update.status, db)
