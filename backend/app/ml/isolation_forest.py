import os
import time
import joblib
import numpy as np
from typing import Dict, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest
from app.ml.evaluation import calculate_binary_metrics

MODEL_DIR = os.getenv("MODEL_DIR", "./models")
os.makedirs(MODEL_DIR, exist_ok=True)

class IsolationForestAnomalyDetector:
    def __init__(self, n_estimators: int = 100, contamination: float = 0.1, random_state: int = 42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.is_trained: bool = False

    def train(
        self,
        X_train: np.ndarray,
        y_train: Optional[np.ndarray] = None,
        X_test: Optional[np.ndarray] = None,
        y_test: Optional[np.ndarray] = None
    ) -> Tuple[Dict[str, Any], float]:
        """Train Isolation Forest anomaly detector and evaluate against ground truth test set."""
        start_time = time.time()
        
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.model.fit(X_train)
        training_time = time.time() - start_time

        metrics: Dict[str, Any] = {
            "evaluation_type": "Unsupervised Tree Isolation",
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "hyperparameters": {
                "n_estimators": self.n_estimators,
                "contamination": self.contamination,
                "random_state": self.random_state
            }
        }

        if X_test is not None and y_test is not None:
            # predict returns -1 for anomaly, 1 for inlier
            raw_preds = self.model.predict(X_test)
            y_pred_anomaly = (raw_preds == -1).astype(int)
            eval_metrics = calculate_binary_metrics(y_test, y_pred_anomaly)

            metrics["accuracy"] = eval_metrics["accuracy"]
            metrics["precision"] = eval_metrics["precision"]
            metrics["recall"] = eval_metrics["recall"]
            metrics["f1_score"] = eval_metrics["f1_score"]
            metrics["false_positive_rate"] = eval_metrics["false_positive_rate"]
            metrics["confusion_matrix"] = eval_metrics["confusion_matrix"]
            metrics["note"] = "Isolation Forest anomaly classification evaluated against test partition."

        self.is_trained = True
        return metrics, training_time

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Return binary anomaly predictions (1 for anomaly, 0 for inlier) and normalized anomaly scores [0, 1]."""
        if not self.is_trained or self.model is None:
            raise ValueError("Isolation Forest is not trained. Train or load model first.")
        
        raw_preds = self.model.predict(X)
        is_anomaly = (raw_preds == -1).astype(int)
        
        # score_samples returns negative anomaly score (lower means more anomalous)
        scores = self.model.score_samples(X)
        # Normalize roughly into [0.0, 1.0] where 1.0 is highest anomaly
        min_score = np.min(scores) if len(scores) > 0 else -1.0
        max_score = np.max(scores) if len(scores) > 0 else 0.0
        range_val = max(max_score - min_score, 1e-6)
        normalized_scores = np.clip(1.0 - ((scores - min_score) / range_val), 0.0, 1.0)

        return is_anomaly, normalized_scores

    def save(self, filepath: Optional[str] = None):
        """Save Isolation Forest to disk."""
        path = filepath or os.path.join(MODEL_DIR, "isolation_forest.joblib")
        joblib.dump({
            "model": self.model,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "is_trained": self.is_trained
        }, path)

    def load(self, filepath: Optional[str] = None):
        """Load Isolation Forest from disk."""
        path = filepath or os.path.join(MODEL_DIR, "isolation_forest.joblib")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Isolation Forest model not found at {path}")
        saved_data = joblib.load(path)
        self.model = saved_data["model"]
        self.n_estimators = saved_data["n_estimators"]
        self.contamination = saved_data["contamination"]
        self.random_state = saved_data["random_state"]
        self.is_trained = saved_data["is_trained"]
