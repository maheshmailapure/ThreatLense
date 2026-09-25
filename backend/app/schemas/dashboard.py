from pydantic import BaseModel
from typing import List, Dict, Any

class DashboardStats(BaseModel):
    total_records: int
    normal_records: int
    attack_records: int
    anomalies: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    models_trained_count: int
    system_status: str

class ChartDataPoint(BaseModel):
    name: str
    value: Any

class DashboardCharts(BaseModel):
    normal_vs_attack: List[Dict[str, Any]]
    attack_categories: List[Dict[str, Any]]
    detection_timeline: List[Dict[str, Any]]
    risk_distribution: List[Dict[str, Any]]
    protocol_distribution: List[Dict[str, Any]]
    model_performance_comparison: List[Dict[str, Any]]
