import io
import csv
import pandas as pd
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_
from fastapi import HTTPException
from app.database.models import Detection, Dataset, Alert
from app.ml.preprocessing import load_nsl_kdd_dataset
from app.ml.prediction import PredictionEngine
from app.services.alert_service import AlertService
from app.utils.logger import log_event, logger
from datetime import datetime, timezone

prediction_engine = PredictionEngine()

def serialize_dt(dt) -> Optional[str]:
    if dt is None:
        return None
    if hasattr(dt, 'isoformat'):
        return dt.isoformat()
    return str(dt)

class DetectionService:
    @staticmethod
    def run_detection(
        dataset_id: int,
        model_name: str,
        limit: Optional[int],
        db: Session
    ) -> Dict[str, Any]:
        """Execute detection pipeline on dataset rows and record detections and alerts in database."""
        dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
        if not dataset:
            raise HTTPException(status_code=404, detail="Dataset not found")

        df = load_nsl_kdd_dataset(dataset.file_path)
        if limit and limit > 0:
            df = df.head(limit)

        logger.info(f"Running detection on {len(df)} records using model: {model_name}")
        log_event("DETECTION_START", {"dataset_id": dataset_id, "model": model_name, "records": len(df)})

        results = prediction_engine.predict_dataframe(df, model_name=model_name)

        now = datetime.now(timezone.utc)
        detection_records = []
        normal_count = 0
        attack_count = 0
        anomaly_count = 0

        for item in results:
            det = Detection(
                dataset_id=dataset_id,
                prediction=item["prediction"],
                attack_type=item["attack_type"],
                model=item["model"],
                anomaly_score=item["anomaly_score"],
                is_anomaly=item["is_anomaly"],
                risk_level=item["risk_level"],
                input_features=item["input_features"],
                explanation=item["explanation"],
                timestamp=now
            )
            detection_records.append(det)

            if item["prediction"] == "ATTACK":
                attack_count += 1
            else:
                normal_count += 1

            if item["is_anomaly"]:
                anomaly_count += 1

        # Bulk save detections
        db.add_all(detection_records)
        db.commit()

        # Batch save corresponding alerts
        alert_records = []
        for det in detection_records:
            if det.prediction == "ATTACK" or det.is_anomaly or det.risk_level in ["HIGH", "CRITICAL"]:
                if det.attack_type != "Normal":
                    alert_type = f"{det.attack_type} Intrusion Detected"
                elif det.is_anomaly:
                    alert_type = "Zero-Day Behavioral Anomaly"
                else:
                    alert_type = "Suspicious Traffic Flag"

                desc = det.explanation.get("summary", f"Automated detection triggered by {det.model}.") if isinstance(det.explanation, dict) else f"Detection by {det.model}"

                alert = Alert(
                    detection_id=det.id,
                    alert_type=alert_type,
                    risk_level=det.risk_level,
                    status="NEW",
                    description=desc,
                    created_at=now
                )
                alert_records.append(alert)

        if alert_records:
            db.add_all(alert_records)
            db.commit()

        log_event("DETECTION_COMPLETE", {
            "dataset_id": dataset_id,
            "total_processed": len(results),
            "attacks": attack_count,
            "anomalies": anomaly_count,
            "alerts": len(alert_records)
        })

        return {
            "total_processed": len(results),
            "normal_count": normal_count,
            "attack_count": attack_count,
            "anomaly_count": anomaly_count,
            "alerts_generated": len(alert_records),
            "results": [
                {
                    "id": det.id,
                    "prediction": det.prediction,
                    "attack_type": det.attack_type,
                    "anomaly_score": det.anomaly_score,
                    "is_anomaly": det.is_anomaly,
                    "risk_level": det.risk_level
                }
                for det in detection_records[:50]
            ]
        }

    @staticmethod
    def get_paginated_results(
        db: Session,
        page: int = 1,
        page_size: int = 20,
        prediction: Optional[str] = None,
        attack_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        model: Optional[str] = None,
        is_anomaly: Optional[bool] = None,
        search: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fetch paginated detections with optional dynamic security filters."""
        query = db.query(Detection)

        if prediction:
            query = query.filter(Detection.prediction == prediction.upper())
        if attack_type:
            query = query.filter(Detection.attack_type.ilike(f"%{attack_type}%"))
        if risk_level:
            query = query.filter(Detection.risk_level == risk_level.upper())
        if model:
            query = query.filter(Detection.model.ilike(f"%{model}%"))
        if is_anomaly is not None:
            query = query.filter(Detection.is_anomaly == is_anomaly)
        if search:
            query = query.filter(
                or_(
                    Detection.attack_type.ilike(f"%{search}%"),
                    Detection.model.ilike(f"%{search}%"),
                    Detection.prediction.ilike(f"%{search}%")
                )
            )

        total = query.count()
        total_pages = (total + page_size - 1) // page_size or 1
        items = query.order_by(Detection.id.desc()).offset((page - 1) * page_size).limit(page_size).all()

        return {
            "items": [
                {
                    "id": item.id,
                    "dataset_id": item.dataset_id,
                    "prediction": item.prediction,
                    "attack_type": item.attack_type,
                    "model": item.model,
                    "anomaly_score": item.anomaly_score,
                    "is_anomaly": item.is_anomaly,
                    "risk_level": item.risk_level,
                    "input_features": item.input_features,
                    "explanation": item.explanation,
                    "timestamp": serialize_dt(item.timestamp)
                }
                for item in items
            ],
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages
        }

    @staticmethod
    def get_detection_by_id(detection_id: int, db: Session) -> Dict[str, Any]:
        """Retrieve single detection record with associated SIEM alert details."""
        det = db.query(Detection).filter(Detection.id == detection_id).first()
        if not det:
            raise HTTPException(status_code=404, detail="Detection record not found")

        alert = db.query(Alert).filter(Alert.detection_id == detection_id).first()

        return {
            "id": det.id,
            "dataset_id": det.dataset_id,
            "prediction": det.prediction,
            "attack_type": det.attack_type,
            "model": det.model,
            "anomaly_score": det.anomaly_score,
            "is_anomaly": det.is_anomaly,
            "risk_level": det.risk_level,
            "input_features": det.input_features,
            "explanation": det.explanation,
            "timestamp": serialize_dt(det.timestamp),
            "alert": {
                "id": alert.id,
                "alert_type": alert.alert_type,
                "status": alert.status,
                "risk_level": alert.risk_level,
                "description": alert.description,
                "created_at": serialize_dt(alert.created_at)
            } if alert else None
        }

    @staticmethod
    def export_detections_csv(db: Session, limit: int = 1000) -> str:
        """Export recent intrusion detection records as standard RFC 4180 CSV."""
        records = db.query(Detection).order_by(Detection.id.desc()).limit(limit).all()
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["ID", "Timestamp", "Prediction", "Attack_Type", "Risk_Level", "Anomaly_Score", "Model"])
        for r in records:
            writer.writerow([
                r.id,
                serialize_dt(r.timestamp) or "",
                r.prediction,
                r.attack_type,
                r.risk_level,
                r.anomaly_score,
                r.model
            ])

        return output.getvalue()
