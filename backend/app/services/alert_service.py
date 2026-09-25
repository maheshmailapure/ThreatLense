import time
import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session, joinedload
from fastapi import HTTPException
from app.database.models import Alert, Detection
from app.agent.agent_engine import ids_agent
from app.utils.logger import log_event, logger

_ALERTS_CACHE = {"data": None, "ts": 0.0}

class AlertService:
    @staticmethod
    def create_alert_from_detection(detection: Detection, db: Session) -> Alert:
        """Construct and persist a security alert corresponding to a high-risk or anomalous detection."""
        _ALERTS_CACHE["data"] = None  # Invalidate cache on new alert

        # Determine alert type title
        if detection.attack_type != "Normal":
            alert_type = f"{detection.attack_type} Intrusion Detected"
        elif detection.is_anomaly:
            alert_type = "Zero-Day Behavioral Anomaly"
        else:
            alert_type = "Suspicious Traffic Flag"

        description = detection.explanation.get("summary", f"Automated detection triggered by {detection.model}.")

        alert = Alert(
            detection_id=detection.id,
            alert_type=alert_type,
            risk_level=detection.risk_level,
            status="NEW",
            description=description,
            created_at=datetime.datetime.utcnow()
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        log_event("ALERT_CREATED", {
            "alert_id": alert.id,
            "detection_id": detection.id,
            "risk_level": alert.risk_level,
            "type": alert_type
        })
        return alert

    @staticmethod
    def get_paginated_alerts(
        db: Session,
        page: int = 1,
        page_size: int = 20,
        risk_level: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fetch filtered and paginated security alerts with linked detection metadata."""
        now = time.time()
        is_default_query = (page == 1 and not risk_level and not status and not search)
        if is_default_query and _ALERTS_CACHE["data"] and (now - _ALERTS_CACHE["ts"] < 2.5):
            return _ALERTS_CACHE["data"]

        formatted_items = []

        # 1. Real-time in-memory active incidents from IDS Agent (Zero DB Latency)
        try:
            snapshot = ids_agent.get_snapshot()
            active_incidents = snapshot.get("active_incidents", [])
            for inc in active_incidents:
                formatted_items.append({
                    "id": inc.get("incident_id", "INC-LIVE"),
                    "detection_id": 0,
                    "alert_type": inc.get("title", "Live Endpoint Security Alert"),
                    "risk_level": inc.get("severity", "HIGH"),
                    "status": "NEW",
                    "description": inc.get("evidence", "Real-time behavioral correlation flag."),
                    "created_at": inc.get("timestamp", datetime.datetime.utcnow().isoformat()),
                    "resolved_at": None,
                    "attack_type": inc.get("attack_category", "Suspicious Activity"),
                    "model": "Endpoint Real-Time IDS Agent",
                    "anomaly_score": inc.get("confidence", 90.0) / 100.0
                })
        except Exception:
            pass

        # 2. Try fetching historical DB alerts with fast timeout
        if not is_default_query or len(formatted_items) == 0:
            try:
                query = db.query(Alert).join(Detection, Alert.detection_id == Detection.id)
                if risk_level:
                    query = query.filter(Alert.risk_level == risk_level.upper())
                if status:
                    query = query.filter(Alert.status == status.upper())
                if search:
                    search_pattern = f"%{search}%"
                    query = query.filter(
                        (Alert.alert_type.ilike(search_pattern)) |
                        (Alert.description.ilike(search_pattern)) |
                        (Detection.attack_type.ilike(search_pattern)) |
                        (Detection.model.ilike(search_pattern))
                    )
                alerts = query.options(joinedload(Alert.detection)).order_by(Alert.created_at.desc()).limit(page_size).all()
                for a in alerts:
                    formatted_items.append({
                        "id": a.id,
                        "detection_id": a.detection_id,
                        "alert_type": a.alert_type,
                        "risk_level": a.risk_level,
                        "status": a.status,
                        "description": a.description,
                        "created_at": a.created_at,
                        "resolved_at": a.resolved_at,
                        "attack_type": a.detection.attack_type if a.detection else "Unknown",
                        "model": a.detection.model if a.detection else "N/A",
                        "anomaly_score": a.detection.anomaly_score if a.detection else 0.0
                    })
            except Exception as err:
                logger.info(f"Fast fallback on DB alerts query: {err}")

        total_combined = len(formatted_items)
        res = {
            "total": total_combined,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, (total_combined + page_size - 1) // page_size),
            "items": formatted_items[:page_size]
        }

        if is_default_query:
            _ALERTS_CACHE["data"] = res
            _ALERTS_CACHE["ts"] = now

        return res

    @staticmethod
    def get_alert_by_id(alert_id: int, db: Session) -> Optional[Dict[str, Any]]:
        """Fetch full alert detail with associated detection record and feature attributes."""
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None

        detection = alert.detection
        return {
            "id": alert.id,
            "detection_id": alert.detection_id,
            "alert_type": alert.alert_type,
            "risk_level": alert.risk_level,
            "status": alert.status,
            "description": alert.description,
            "created_at": alert.created_at,
            "resolved_at": alert.resolved_at,
            "detection": {
                "id": detection.id,
                "timestamp": detection.timestamp,
                "prediction": detection.prediction,
                "attack_type": detection.attack_type,
                "model": detection.model,
                "anomaly_score": detection.anomaly_score,
                "is_anomaly": detection.is_anomaly,
                "risk_level": detection.risk_level,
                "input_features": detection.input_features,
                "explanation": detection.explanation
            } if detection else None
        }

    @staticmethod
    def update_status(alert_id: int, new_status: str, db: Session) -> Dict[str, Any]:
        """Update status of alert (NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
        valid_statuses = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
        status_upper = new_status.upper()
        if status_upper not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        alert.status = status_upper
        if status_upper in ["RESOLVED", "FALSE_POSITIVE"]:
            alert.resolved_at = datetime.datetime.utcnow()
        else:
            alert.resolved_at = None

        db.commit()
        db.refresh(alert)

        log_event("ALERT_STATUS_UPDATE", {"alert_id": alert_id, "new_status": status_upper})
        return {"id": alert.id, "status": alert.status, "resolved_at": alert.resolved_at}
