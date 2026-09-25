from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import User
from app.schemas.simulation import SimulationStartRequest, SimulationStatusResponse
from app.services.simulation_service import simulation_service_instance
from app.api.auth import get_current_user

router = APIRouter(prefix="/api/simulation", tags=["Real-Time Simulation"])

@router.post("/start", response_model=SimulationStatusResponse)
def start_simulation(
    request: SimulationStartRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start simulated real-time packet stream ingestion."""
    return simulation_service_instance.start(
        dataset_id=request.dataset_id,
        model_name=request.model_name,
        speed_ms=request.speed_ms
    )

@router.post("/stop", response_model=SimulationStatusResponse)
def stop_simulation(
    current_user: User = Depends(get_current_user)
):
    """Stop the ongoing simulated traffic stream."""
    return simulation_service_instance.stop()

@router.get("/status", response_model=SimulationStatusResponse)
def get_simulation_status(
    current_user: User = Depends(get_current_user)
):
    """Poll the real-time simulation counters and latest packet detections."""
    return simulation_service_instance.get_status()
