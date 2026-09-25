from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class AlertStatusUpdate(BaseModel):
    status: str  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE

class AlertResponse(BaseModel):
    id: int
    detection_id: int
    alert_type: str
    risk_level: str
    status: str
    description: str
    created_at: datetime
    resolved_at: Optional[datetime] = None
    detection: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True
