from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional
from pydantic import BaseModel
from app.database.database import get_db
from app.database.models import User
from app.services.live_monitor_service import LiveMonitorService
from app.api.auth import get_current_user

router = APIRouter(prefix="/api/live-monitor", tags=["Live Host & Network Monitor"])

class AttackTestPayload(BaseModel):
    model_name: str = "Random Forest"
    packet_features: Dict[str, Any]

@router.get("/telemetry")
def get_system_telemetry(
    current_user: User = Depends(get_current_user)
):
    """Retrieve real-time host hardware, memory, and network interface metrics."""
    return LiveMonitorService.get_system_telemetry()

@router.get("/scan")
def scan_host_network(
    max_connections: int = Query(50, ge=5, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Perform a live scan of all active network sockets, local/remote connections,
    and running processes on the host machine, and evaluate them through the AI intrusion detection model.
    """
    try:
        return LiveMonitorService.scan_host_connections(db=db, max_connections=max_connections)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Live scan failed: {str(e)}")

@router.post("/test-attack")
def test_attack_scenario(
    payload: AttackTestPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Simulate or evaluate an inbound/outbound attack vector against the active AI model
    and trigger automated SIEM incident response.
    """
    try:
        return LiveMonitorService.evaluate_test_packet(
            packet_data=payload.packet_features,
            model_name=payload.model_name,
            db=db
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack simulation failed: {str(e)}")
