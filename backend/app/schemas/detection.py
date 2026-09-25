from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class DetectionRunRequest(BaseModel):
    dataset_id: int
    model_name: str = "Random Forest"
    limit: Optional[int] = 1000  # Number of rows to run detection on

class DetectionResponse(BaseModel):
    id: int
    dataset_id: Optional[int]
    timestamp: datetime
    prediction: str
    attack_type: str
    model: str
    anomaly_score: float
    is_anomaly: bool
    risk_level: str
    input_features: Dict[str, Any] = {}
    explanation: Dict[str, Any] = {}

    class Config:
        from_attributes = True

class DetectionBatchResult(BaseModel):
    total_processed: int
    normal_count: int
    attack_count: int
    anomaly_count: int
    alerts_generated: int
    results: List[DetectionResponse]
