import time
import threading
import pandas as pd
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.database.database import SessionLocal
from app.database.models import Dataset, Detection
from app.ml.preprocessing import load_nsl_kdd_dataset
from app.ml.prediction import PredictionEngine
from app.services.alert_service import AlertService
from app.utils.logger import log_event, logger

class SimulationService:
    def __init__(self):
        self.is_running = False
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.processed_records = 0
        self.attack_count = 0
        self.anomaly_count = 0
        self.alerts_count = 0
        self.recent_detections: List[Dict[str, Any]] = []
        self.current_speed_ms = 500
        self.model_name = "Random Forest"
        self.prediction_engine = PredictionEngine()

    def start(
        self,
        dataset_id: Optional[int],
        model_name: str = "Random Forest",
        speed_ms: int = 500
    ) -> Dict[str, Any]:
        """Start the simulated real-time IDS stream in a background worker thread."""
        if self.is_running:
            return self.get_status()

        self.is_running = True
        self.stop_event.clear()
        self.current_speed_ms = max(100, speed_ms)
        self.model_name = model_name

        self.thread = threading.Thread(
            target=self._run_stream,
            args=(dataset_id, model_name),
            daemon=True
        )
        self.thread.start()

        log_event("SIMULATION_START", {"model": model_name, "speed_ms": self.current_speed_ms})
        return self.get_status()

    def stop(self) -> Dict[str, Any]:
        """Signal the background worker to stop the simulation stream."""
        if self.is_running:
            self.stop_event.set()
            self.is_running = False
            log_event("SIMULATION_STOP", {"processed": self.processed_records})
        return self.get_status()

    def get_status(self) -> Dict[str, Any]:
        """Retrieve live streaming counters and recent packet detections."""
        return {
            "is_running": self.is_running,
            "processed_records": self.processed_records,
            "attack_count": self.attack_count,
            "anomaly_count": self.anomaly_count,
            "alerts_count": self.alerts_count,
            "recent_detections": self.recent_detections[-15:],
            "current_speed_ms": self.current_speed_ms
        }

    def _run_stream(self, dataset_id: Optional[int], model_name: str):
        """Worker loop that streams packet records sequentially."""
        db: Session = SessionLocal()
        try:
            # Find dataset file or fallback
            df = None
            if dataset_id:
                dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
                if dataset:
                    df = load_nsl_kdd_dataset(dataset.file_path)

            if df is None or len(df) == 0:
                first_dataset = db.query(Dataset).first()
                if first_dataset:
                    df = load_nsl_kdd_dataset(first_dataset.file_path)

            if df is None or len(df) == 0:
                logger.warning("No dataset available for simulation stream.")
                self.is_running = False
                return

            total_rows = len(df)
            idx = 0

            while not self.stop_event.is_set():
                row_df = df.iloc[[idx % total_rows]]
                idx += 1

                try:
                    results = self.prediction_engine.predict_dataframe(row_df, model_name=model_name)
                    if results:
                        res = results[0]
                        # Persist detection record
                        det = Detection(
                            dataset_id=dataset_id,
                            prediction=res["prediction"],
                            attack_type=res["attack_type"],
                            model=res["model"],
                            anomaly_score=res["anomaly_score"],
                            is_anomaly=res["is_anomaly"],
                            risk_level=res["risk_level"],
                            input_features=res["input_features"],
                            explanation=res["explanation"]
                        )
                        db.add(det)
                        db.commit()
                        db.refresh(det)

                        self.processed_records += 1
                        if res["prediction"] == "ATTACK":
                            self.attack_count += 1
                        if res["is_anomaly"]:
                            self.anomaly_count += 1

                        if res["prediction"] == "ATTACK" or res["is_anomaly"] or res["risk_level"] in ["HIGH", "CRITICAL"]:
                            AlertService.create_alert_from_detection(det, db)
                            self.alerts_count += 1

                        feed_item = {
                            "id": det.id,
                            "timestamp": det.timestamp.strftime("%H:%M:%S"),
                            "prediction": det.prediction,
                            "attack_type": det.attack_type,
                            "anomaly_score": det.anomaly_score,
                            "is_anomaly": det.is_anomaly,
                            "risk_level": det.risk_level,
                            "model": det.model
                        }
                        self.recent_detections.append(feed_item)
                        if len(self.recent_detections) > 50:
                            self.recent_detections.pop(0)

                except Exception as e:
                    logger.error(f"Error during simulation step: {e}")

                # Sleep interval
                sleep_seconds = self.current_speed_ms / 1000.0
                time.sleep(sleep_seconds)

        finally:
            self.is_running = False
            db.close()

simulation_service_instance = SimulationService()
