import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from app.database.database import get_db
from app.database.models import User, MLModel, Dataset
from app.schemas.models import TrainRequest, ModelResponse, ModelComparison
from app.ml.training import TrainingPipeline
from app.api.auth import get_current_user
from app.utils.logger import logger

router = APIRouter(prefix="/api/models", tags=["ML Models"])

@router.post("/train", response_model=Dict[str, Any])
def train_models(
    request: TrainRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Train selected AI/ML intrusion and anomaly detection models."""
    dataset = db.query(Dataset).filter(Dataset.id == request.dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Selected training dataset not found")

    pipeline = TrainingPipeline(
        test_size=request.test_size,
        random_state=request.random_state,
        feature_selection_k=request.feature_selection_k,
        pca_components=request.pca_components,
        rf_n_estimators=request.rf_n_estimators,
        svm_kernel=request.svm_kernel,
        kmeans_clusters=request.kmeans_clusters,
        anomaly_threshold_percentile=request.anomaly_threshold_percentile
    )

    try:
        results = pipeline.execute(
            dataset_path=dataset.file_path,
            dataset_name=dataset.filename,
            models_to_train=request.models_to_train
        )
    except Exception as e:
        logger.error(f"Training failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Model training failed: {str(e)}")

    # Update or insert MLModel records in DB
    for model_name, model_info in results.get("models", {}).items():
        metrics = model_info.get("metrics", {})
        
        # Check if model record exists
        existing_model = db.query(MLModel).filter(MLModel.name == model_name).first()
        if not existing_model:
            existing_model = MLModel(name=model_name)
            db.add(existing_model)

        existing_model.version = "1.0.0"
        existing_model.training_date = datetime.datetime.utcnow()
        existing_model.dataset_name = dataset.filename
        existing_model.accuracy = metrics.get("accuracy")
        existing_model.precision = metrics.get("precision")
        existing_model.recall = metrics.get("recall")
        existing_model.f1_score = metrics.get("f1_score")
        existing_model.false_positive_rate = metrics.get("false_positive_rate")
        existing_model.training_time = model_info.get("training_time", 0.0)
        existing_model.status = "TRAINED"
        existing_model.hyperparameters = metrics.get("hyperparameters", {})
        existing_model.metrics_json = metrics

    db.commit()
    return results

@router.get("", response_model=List[ModelResponse])
def get_all_models(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all trained machine learning models."""
    return db.query(MLModel).order_by(MLModel.id.asc()).all()

@router.get("/{model_id}", response_model=ModelResponse)
def get_model(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve details for a specific model."""
    model = db.query(MLModel).filter(MLModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    return model
