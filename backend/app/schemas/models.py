from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class TrainRequest(BaseModel):
    dataset_id: int
    models_to_train: List[str] = ["Random Forest", "SVM", "K-Means", "Isolation Forest"]
    test_size: float = Field(default=0.3, ge=0.1, le=0.5)
    random_state: int = 42
    feature_selection_k: int = Field(default=20, ge=5, le=41)
    pca_components: int = Field(default=10, ge=2, le=30)
    rf_n_estimators: int = 100
    svm_kernel: str = "rbf"
    kmeans_clusters: int = 5
    anomaly_threshold_percentile: float = 95.0

class ModelResponse(BaseModel):
    id: int
    name: str
    version: str
    training_date: datetime
    dataset_name: str
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None
    training_time: float
    status: str
    hyperparameters: Dict[str, Any] = {}
    metrics_json: Dict[str, Any] = {}

    class Config:
        from_attributes = True

class ModelComparison(BaseModel):
    models: List[ModelResponse]
    feature_names: List[str] = []
    selected_features: List[str] = []
    pca_variance_ratio: List[float] = []
    pca_total_variance: float = 0.0
