from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class SimulationStartRequest(BaseModel):
    dataset_id: Optional[int] = None
    model_name: str = "Random Forest"
    speed_ms: int = 500  # Stream interval in ms
    batch_size: int = 1

class SimulationStatusResponse(BaseModel):
    is_running: bool
    processed_records: int
    attack_count: int
    anomaly_count: int
    alerts_count: int
    recent_detections: List[Dict[str, Any]] = []
    current_speed_ms: int
