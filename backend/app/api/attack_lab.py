from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import User
from app.services.attack_simulator_service import AttackSimulatorService
from app.api.auth import get_current_user

router = APIRouter(prefix="/api/attack-lab", tags=["Attack Testing Lab"])

class AttackSimulationRequest(BaseModel):
    scenario_id: Optional[str] = "web_sqli"
    model_name: str = "Random Forest"
    custom_payload: Optional[Dict[str, Any]] = None

@router.get("/scenarios")
def list_attack_scenarios(current_user: User = Depends(get_current_user)):
    """Retrieve catalog of available web and server attack simulation vectors."""
    return AttackSimulatorService.get_available_scenarios()

@router.post("/simulate")
async def run_attack_simulation(
    request: AttackSimulationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Launch a real-world web/server attack scenario through the IDS ML engine
    and trigger automated SIEM incident alerts + LLM response decisions.
    """
    try:
        return await AttackSimulatorService.simulate_attack(
            scenario_id=request.scenario_id,
            custom_payload=request.custom_payload or {},
            model_name=request.model_name,
            db=db
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack simulation error: {str(e)}")
