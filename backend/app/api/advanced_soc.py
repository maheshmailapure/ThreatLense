from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import User
from app.api.auth import get_current_user
from app.services.kill_chain_service import KillChainService
from app.services.ueba_service import UEBAService
from app.services.encrypted_traffic_service import EncryptedTrafficService
from app.services.soar_playbook_service import SOARPlaybookService

router = APIRouter(prefix="/api/advanced-soc", tags=["Advanced SOC Operations"])

class PlaybookExecutionRequest(BaseModel):
    playbook_id: str
    parameters: Optional[Dict[str, Any]] = None

@router.get("/kill-chain")
def get_kill_chain_campaigns(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve Cyber Kill Chain correlated attack campaigns and MITRE ATT&CK stages."""
    return {
        "stages": KillChainService.get_stages(),
        "campaigns": KillChainService.correlate_campaigns(db)
    }

@router.get("/ueba")
def get_ueba_analytics(
    current_user: User = Depends(get_current_user)
):
    """Retrieve User and Entity Behavior Analytics (UEBA) entity risk profiles."""
    return {
        "metrics": UEBAService.get_ueba_metrics(),
        "entities": UEBAService.get_entity_profiles()
    }

@router.get("/encrypted-traffic")
def get_encrypted_traffic_analysis(
    current_user: User = Depends(get_current_user)
):
    """Inspect encrypted TLS 1.3/HTTPS flow telemetry, entropy, and C2 timing jitter."""
    return EncryptedTrafficService.inspect_encrypted_flows()

@router.get("/playbooks")
def list_soar_playbooks(
    current_user: User = Depends(get_current_user)
):
    """List available automated incident containment playbooks."""
    return SOARPlaybookService.get_playbooks()

@router.post("/playbooks/execute")
def execute_containment_playbook(
    request: PlaybookExecutionRequest,
    current_user: User = Depends(get_current_user)
):
    """Execute an automated SOAR security playbook against a live threat."""
    try:
        return SOARPlaybookService.execute_playbook(
            playbook_id=request.playbook_id,
            parameters=request.parameters or {}
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
