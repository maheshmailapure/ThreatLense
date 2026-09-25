from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from app.services.atria_service import AtriaService
from app.database.database import get_db
from app.database.models import User, Alert, Detection
from app.api.auth import get_current_user
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/ai-decision", tags=["Atria AI Detection & Incident Center"])

class PromptTrainingRequest(BaseModel):
    system_prompt: str
    rules: Optional[List[Dict[str, Any]]] = None

class IncidentAnalysisRequest(BaseModel):
    alert_id: Optional[int] = None
    detection_id: Optional[int] = None
    incident_data: Optional[Dict[str, Any]] = None

class TelemetryDetectRequest(BaseModel):
    telemetry: Dict[str, Any]

@router.get("/config")
@router.get("/status")
def get_atria_config(current_user: User = Depends(get_current_user)):
    """Retrieve active Atria AI configuration, architecture, and prompt training rules."""
    return AtriaService.get_config()

@router.post("/train-rules")
def update_atria_training(
    request: PromptTrainingRequest,
    current_user: User = Depends(get_current_user)
):
    """Update instruction-tuned cybersecurity prompt and custom detection rules."""
    return AtriaService.update_training_prompt(request.system_prompt, request.rules)

@router.post("/test-atria")
@router.post("/test-ollama")
async def test_atria_gateway(
    current_user: User = Depends(get_current_user)
):
    """Ping Atria AI API Gateway and verify active model readiness."""
    return await AtriaService.test_connection()

@router.post("/detect-telemetry")
async def detect_telemetry_with_atria(
    request: TelemetryDetectRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Run real-time inference on a network packet, socket flow, or process event
    using Atria-Dawn-Preview agentic intelligence.
    """
    return await AtriaService.analyze_threat(request.telemetry)

@router.post("/analyze-incident")
async def analyze_incident_with_atria(
    request: IncidentAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate an AI mitigation decision, root cause analysis, and ready-to-execute
    Windows netsh / Linux iptables firewall rules using Atria AI.
    """
    incident_dict = {}

    if request.alert_id:
        alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        det = alert.detection
        incident_dict = {
            "attack_type": det.attack_type if det else alert.alert_type,
            "prediction": det.prediction if det else "ATTACK",
            "risk_level": alert.risk_level,
            "source_ip": det.input_features.get("source_ip", "192.168.1.105") if det and det.input_features else "192.168.1.105",
            "target_port": det.input_features.get("target_port", 80) if det and det.input_features else 80,
            "anomaly_score": det.anomaly_score if det else 0.85,
            "input_features": det.input_features if det else {}
        }
    elif request.detection_id:
        det = db.query(Detection).filter(Detection.id == request.detection_id).first()
        if not det:
            raise HTTPException(status_code=404, detail="Detection record not found")
        incident_dict = {
            "attack_type": det.attack_type,
            "prediction": det.prediction,
            "risk_level": det.risk_level,
            "source_ip": det.input_features.get("source_ip", "192.168.1.105") if det.input_features else "192.168.1.105",
            "target_port": det.input_features.get("target_port", 80) if det.input_features else 80,
            "anomaly_score": det.anomaly_score,
            "input_features": det.input_features
        }
    elif request.incident_data:
        incident_dict = request.incident_data
    else:
        raise HTTPException(status_code=400, detail="Provide alert_id, detection_id, or incident_data.")

    return await AtriaService.triage_incident(incident_dict)


# Live System Protection & Containment Endpoints
from app.services.containment_service import ContainmentService

class BlockIPRequest(BaseModel):
    ip: str
    rule_name: Optional[str] = None
    alert_id: Optional[int] = None

class BlockPortRequest(BaseModel):
    port: int
    protocol: Optional[str] = "TCP"
    rule_name: Optional[str] = None
    alert_id: Optional[int] = None

class KillProcessRequest(BaseModel):
    pid: int
    process_name: Optional[str] = None
    alert_id: Optional[int] = None

class QuarantineFileRequest(BaseModel):
    filepath: str
    alert_id: Optional[int] = None

class WakeAIRequest(BaseModel):
    incident_data: Optional[Dict[str, Any]] = None
    alert_id: Optional[int] = None

@router.post("/contain/block-ip")
def contain_block_ip(
    request: BlockIPRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Instantly block an attacker IP via Windows Defender Firewall rules."""
    result = ContainmentService.block_ip(ip=request.ip, rule_name=request.rule_name)
    if request.alert_id and result.get("success"):
        alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
        if alert:
            alert.status = "CONTAINED"
            db.commit()
    return result

@router.post("/contain/block-port")
def contain_block_port(
    request: BlockPortRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Neutralize backdoor or reverse shell port via Windows Defender Firewall."""
    result = ContainmentService.block_port(port=request.port, protocol=request.protocol or "TCP", rule_name=request.rule_name)
    if request.alert_id and result.get("success"):
        alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
        if alert:
            alert.status = "CONTAINED"
            db.commit()
    return result

@router.post("/contain/kill-process")
def contain_kill_process(
    request: KillProcessRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Terminate rogue spawned process (cmd.exe, powershell.exe, malware PID)."""
    result = ContainmentService.terminate_process(pid=request.pid, process_name=request.process_name)
    if request.alert_id and result.get("success"):
        alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
        if alert:
            alert.status = "CONTAINED"
            db.commit()
    return result

@router.post("/contain/quarantine-file")
def contain_quarantine_file(
    request: QuarantineFileRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Safely isolate a malicious or high-entropy download into quarantine vault."""
    result = ContainmentService.quarantine_file(filepath=request.filepath)
    if request.alert_id and result.get("success"):
        alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
        if alert:
            alert.status = "CONTAINED"
            db.commit()
    return result

@router.post("/wake-ai")
async def wake_ai_on_demand(
    request: WakeAIRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    On-Demand Trigger: Wakes Atria AI MoE to analyze a specific incident or alert.
    Ensures zero tokens are wasted during routine background monitoring.
    """
    incident = request.incident_data or {}
    if request.alert_id:
        alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
        if alert:
            det = alert.detection
            incident.setdefault("title", alert.alert_type)
            incident.setdefault("severity", alert.risk_level)
            incident.setdefault("process", det.attack_type if det else alert.alert_type)
            incident.setdefault("evidence", alert.description)
            if det and det.input_features:
                incident.setdefault("source_ip", det.input_features.get("source_ip"))
                incident.setdefault("target_port", det.input_features.get("target_port"))
                incident.setdefault("input_features", det.input_features)

    deep_eval = await AtriaService.analyze_threat(incident)
    
    # Optionally update Alert description/remediation
    if request.alert_id:
        alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
        if alert:
            remediation = deep_eval.get("firewall_rule") or deep_eval.get("mitigation_action", "")
            if remediation and remediation != "None":
                alert.description = f"{alert.description}\n[Atria AI Remediation]: {remediation}"
                db.commit()

    return {
        "status": "WOKEN_ANALYSIS_COMPLETE",
        "tokens_used": deep_eval.get("tokens_used", "N/A"),
        "analysis": deep_eval
    }

