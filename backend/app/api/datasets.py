from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from app.database.database import get_db
from app.database.models import User
from app.schemas.datasets import DatasetSummary, DatasetDetail
from app.services.dataset_service import DatasetService
from app.api.auth import get_current_user

router = APIRouter(prefix="/api/datasets", tags=["Datasets"])

@router.post("/upload", response_model=DatasetSummary)
def upload_dataset(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Upload an NSL-KDD dataset (.txt or .csv) or general network traffic dataset."""
    if not file.filename.endswith(('.csv', '.txt', '.data')):
        raise HTTPException(status_code=400, detail="Only .csv, .txt, or .data files are supported")
    return DatasetService.save_upload(file, db)

@router.get("", response_model=List[DatasetSummary])
def list_datasets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all uploaded datasets."""
    return DatasetService.get_all(db)

@router.get("/{dataset_id}", response_model=DatasetSummary)
def get_dataset(
    dataset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve details for a specific dataset."""
    dataset = DatasetService.get_by_id(dataset_id, db)
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    return dataset

@router.get("/{dataset_id}/preview", response_model=Dict[str, Any])
def preview_dataset(
    dataset_id: int,
    limit: int = 15,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Inspect sample records and column distributions of a dataset."""
    return DatasetService.get_preview(dataset_id, db, limit=limit)

@router.delete("/{dataset_id}")
def delete_dataset(
    dataset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a dataset and its stored file."""
    success = DatasetService.delete(dataset_id, db)
    if not success:
        raise HTTPException(status_code=404, detail="Dataset not found")
    return {"message": "Dataset deleted successfully"}
