import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.agent.agent_engine import ids_agent
from app.utils.logger import logger

router = APIRouter(tags=["Real-Time Agent Telemetry"])

@router.get("/api/agent/telemetry")
def get_agent_telemetry():
    """REST endpoint returning the latest live in-memory telemetry snapshot from the IDS Agent."""
    return ids_agent.get_snapshot()

@router.post("/api/agent/pause")
def pause_agent():
    ids_agent.pause()
    return {"status": "PAUSED", "agent_running": ids_agent.is_running}

@router.post("/api/agent/resume")
def resume_agent():
    ids_agent.resume()
    return {"status": "RESUMED", "agent_running": ids_agent.is_running}

@router.post("/api/agent/clear-incidents")
def clear_agent_incidents():
    ids_agent.clear_incidents()
    return {"status": "CLEARED", "active_incidents_count": 0}

@router.post("/api/agent/calibrate-baseline")
def calibrate_baseline(duration_seconds: int = 30):
    """Trigger real-time 30-second baseline calibration on this machine."""
    from app.agent.host_anomaly_detector import host_anomaly_detector
    host_anomaly_detector.start_calibration(duration_samples=duration_seconds)
    return {"status": "CALIBRATING", "target_seconds": duration_seconds}

@router.post("/api/agent/set-sensitivity")
def set_sensitivity(threshold: float = 0.70):
    """Adjust live anomaly detection threshold (0.50 to 0.95)."""
    from app.agent.host_anomaly_detector import host_anomaly_detector
    host_anomaly_detector.set_sensitivity(threshold)
    return {"status": "UPDATED", "sensitivity_threshold": host_anomaly_detector.sensitivity_threshold}

@router.post("/api/agent/remediate/kill-process")
def terminate_process(pid: int):
    """SOAR Active Remediation: Kill unauthorized or anomalous process."""
    import psutil
    try:
        if psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            name = proc.name()
            proc.kill()
            return {"status": "SUCCESS", "message": f"Terminated process {name} (PID {pid})."}
        return {"status": "NOT_FOUND", "message": f"PID {pid} does not exist or already terminated."}
    except Exception as e:
        return {"status": "ERROR", "message": f"Failed to terminate PID {pid}: {str(e)}"}

@router.post("/api/agent/remediate/block-ip")
def block_remote_ip(ip_address: str):
    """SOAR Active Remediation: Block remote malicious IP via Windows Firewall (netsh)."""
    import subprocess
    import platform
    if platform.system() != "Windows":
        return {"status": "IGNORED", "message": "Firewall IP blocking is designed for Windows endpoints."}
    try:
        rule_name = f"AI-IDS-Block-{ip_address.replace(':', '_')}"
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"status": "SUCCESS", "message": f"Injected Windows Firewall block rule for {ip_address}."}
    except Exception as e:
        return {"status": "ERROR", "message": f"Failed to inject firewall rule for {ip_address}: {str(e)}"}

@router.websocket("/api/ws/agent")
async def websocket_agent_stream(websocket: WebSocket):
    """
    WebSocket endpoint streaming live real-time telemetry from the IDS Agent
    to connected dashboard clients every 2 seconds.
    """
    await websocket.accept()
    try:
        while True:
            snapshot = ids_agent.get_snapshot()
            await websocket.send_text(json.dumps(snapshot))
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        logger.info("Dashboard WebSocket client disconnected.")
    except Exception as err:
        logger.warn(f"WebSocket streaming exception: {err}")
