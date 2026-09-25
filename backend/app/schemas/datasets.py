from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class DatasetSummary(BaseModel):
    id: int
    filename: str
    original_name: str
    total_records: int
    total_features: int
    uploaded_at: datetime
    status: str
    meta_info: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

class DatasetDetail(DatasetSummary):
    sample_records: List[Dict[str, Any]] = []
    columns: List[str] = []
    categorical_columns: List[str] = []
    numerical_columns: List[str] = []
    class_distribution: Dict[str, int] = {}
