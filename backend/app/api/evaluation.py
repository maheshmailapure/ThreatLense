import os
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from app.database.database import get_db
from app.database.models import User, MLModel
from app.api.auth import get_current_user

router = APIRouter(prefix="/api/evaluation", tags=["Model Evaluation"])

MODEL_DIR = os.getenv("MODEL_DIR", "./models")

@router.get("/compare")
def compare_models(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve full comparative analysis across Random Forest, SVM, K-Means, and Isolation Forest."""
    models = db.query(MLModel).all()
    metadata_path = os.path.join(MODEL_DIR, "metadata.json")
    metadata = {}
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception:
            pass

    return {
        "models": [
            {
                "id": m.id,
                "name": m.name,
                "version": m.version,
                "dataset_name": m.dataset_name,
                "accuracy": m.accuracy,
                "precision": m.precision,
                "recall": m.recall,
                "f1_score": m.f1_score,
                "false_positive_rate": m.false_positive_rate,
                "training_time": m.training_time,
                "status": m.status,
                "hyperparameters": m.hyperparameters,
                "metrics_json": m.metrics_json
            }
            for m in models
        ],
        "metadata": metadata
    }

@router.get("/{model_name}")
def get_model_evaluation(
    model_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve specific model evaluation metrics including confusion matrix."""
    model = db.query(MLModel).filter(MLModel.name.ilike(model_name)).first()
    if not model:
        raise HTTPException(status_code=404, detail=f"Model '{model_name}' not found")
    
    return {
        "id": model.id,
        "name": model.name,
        "accuracy": model.accuracy,
        "precision": model.precision,
        "recall": model.recall,
        "f1_score": model.f1_score,
        "false_positive_rate": model.false_positive_rate,
        "training_time": model.training_time,
        "metrics_json": model.metrics_json,
        "hyperparameters": model.hyperparameters
    }
