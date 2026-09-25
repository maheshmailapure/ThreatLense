from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from app.database.database import get_db
from app.database.models import User
from app.schemas.detection import DetectionRunRequest, DetectionBatchResult, DetectionResponse
from app.services.detection_service import DetectionService
from app.api.auth import get_current_user

router = APIRouter(prefix="/api/detection", tags=["Detection"])

@router.post("/run", response_model=Dict[str, Any])
def run_detection(
    request: DetectionRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run detection and anomaly analysis against an uploaded dataset using a trained model."""
    try:
        return DetectionService.run_detection(
            dataset_id=request.dataset_id,
            model_name=request.model_name,
            limit=request.limit,
            db=db
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection run failed: {str(e)}")

@router.get("/results")
def get_detection_results(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    prediction: Optional[str] = None,
    attack_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    model: Optional[str] = None,
    is_anomaly: Optional[bool] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get paginated, filtered, and searchable detection records."""
    return DetectionService.get_paginated_results(
        db=db,
        page=page,
        page_size=page_size,
        prediction=prediction,
        attack_type=attack_type,
        risk_level=risk_level,
        model=model,
        is_anomaly=is_anomaly,
        search=search
    )

@router.get("/results/{detection_id}", response_model=DetectionResponse)
def get_detection_by_id(
    detection_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve full packet features and detection explanation for a single record."""
    det = DetectionService.get_by_id(detection_id, db)
    if not det:
        raise HTTPException(status_code=404, detail="Detection record not found")
    return det

@router.get("/export")
def export_detection_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export detection results as downloadable CSV."""
    csv_content = DetectionService.export_csv(db)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ids_detection_results.csv"}
    )
