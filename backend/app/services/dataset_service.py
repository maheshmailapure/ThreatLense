import os
import shutil
import pandas as pd
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from fastapi import UploadFile, HTTPException
from app.database.models import Dataset
from app.ml.preprocessing import load_nsl_kdd_dataset
from app.utils.logger import log_event, logger

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

class DatasetService:
    @staticmethod
    def save_upload(file: UploadFile, db: Session) -> Dataset:
        """Handle file upload, validate format, compute dataset statistics, and save DB record."""
        # Sanitize filename
        safe_filename = os.path.basename(file.filename or "dataset.csv")
        file_path = os.path.join(UPLOAD_DIR, safe_filename)

        # Write file to disk
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        try:
            df = load_nsl_kdd_dataset(file_path)
        except Exception as e:
            if os.path.exists(file_path):
                os.remove(file_path)
            raise HTTPException(status_code=400, detail=f"Invalid dataset file: {str(e)}")

        total_records = len(df)
        total_features = df.shape[1]

        # Calculate metadata
        cols = list(df.columns)
        cat_cols = list(df.select_dtypes(include=['object', 'category']).columns)
        num_cols = [c for c in cols if c not in cat_cols]
        
        # Calculate class distribution if label exists
        class_dist = {}
        if "label" in df.columns:
            class_dist = df["label"].astype(str).value_counts().head(10).to_dict()

        meta_info = {
            "columns": cols,
            "categorical_columns": cat_cols,
            "numerical_columns": num_cols,
            "missing_values": int(df.isna().sum().sum()),
            "duplicates": int(df.duplicated().sum()),
            "class_distribution": class_dist,
            "memory_usage_mb": round(df.memory_usage(deep=True).sum() / (1024 * 1024), 2)
        }

        dataset_record = Dataset(
            filename=safe_filename,
            original_name=file.filename or safe_filename,
            file_path=file_path,
            total_records=total_records,
            total_features=total_features,
            status="READY",
            meta_info=meta_info
        )
        db.add(dataset_record)
        db.commit()
        db.refresh(dataset_record)

        log_event("DATASET_UPLOAD", {
            "dataset_id": dataset_record.id,
            "filename": safe_filename,
            "records": total_records
        })
        return dataset_record

    @staticmethod
    def get_all(db: Session) -> List[Dataset]:
        """List all datasets ordered by upload date descending."""
        return db.query(Dataset).order_by(Dataset.uploaded_at.desc()).all()

    @staticmethod
    def get_by_id(dataset_id: int, db: Session) -> Optional[Dataset]:
        """Fetch a specific dataset by ID."""
        return db.query(Dataset).filter(Dataset.id == dataset_id).first()

    @staticmethod
    def get_preview(dataset_id: int, db: Session, limit: int = 15) -> Dict[str, Any]:
        """Return sample rows and column structure for preview."""
        dataset = DatasetService.get_by_id(dataset_id, db)
        if not dataset:
            raise HTTPException(status_code=404, detail="Dataset not found")

        df = load_nsl_kdd_dataset(dataset.file_path)
        preview_rows = df.head(limit).fillna("").to_dict(orient="records")
        return {
            "id": dataset.id,
            "filename": dataset.filename,
            "total_records": dataset.total_records,
            "total_features": dataset.total_features,
            "columns": list(df.columns),
            "sample_records": preview_rows,
            "meta_info": dataset.meta_info
        }

    @staticmethod
    def delete(dataset_id: int, db: Session) -> bool:
        """Delete a dataset and its physical file."""
        dataset = DatasetService.get_by_id(dataset_id, db)
        if not dataset:
            return False

        if os.path.exists(dataset.file_path):
            try:
                os.remove(dataset.file_path)
            except Exception as e:
                logger.warning(f"Could not remove dataset file {dataset.file_path}: {e}")

        db.delete(dataset)
        db.commit()
        return True
