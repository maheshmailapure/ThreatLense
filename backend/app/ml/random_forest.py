import os
import time
import joblib
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from sklearn.ensemble import RandomForestClassifier
from app.ml.evaluation import calculate_binary_metrics

MODEL_DIR = os.getenv("MODEL_DIR", "./models")
os.makedirs(MODEL_DIR, exist_ok=True)

class RandomForestModel:
    def __init__(self, n_estimators: int = 100, random_state: int = 42):
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model: Optional[RandomForestClassifier] = None
        self.feature_importances: Dict[str, float] = {}
        self.is_trained: bool = False

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> Tuple[Dict[str, Any], float]:
        """Train Random Forest model and evaluate on test partition."""
        start_time = time.time()
        
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.model.fit(X_train, y_train)
        training_time = time.time() - start_time

        # Calculate feature importances
        if feature_names and len(feature_names) == X_train.shape[1]:
            importances = self.model.feature_importances_
            sorted_indices = np.argsort(importances)[::-1]
            self.feature_importances = {
                feature_names[i]: round(float(importances[i]), 4)
                for i in sorted_indices
            }

        # Predict on test set
        y_pred = self.model.predict(X_test)
        metrics = calculate_binary_metrics(y_test, y_pred)
        metrics["feature_importances"] = self.feature_importances
        metrics["hyperparameters"] = {
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "criterion": "gini"
        }

        self.is_trained = True
        return metrics, training_time

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Return predictions and attack class probability."""
        if not self.is_trained or self.model is None:
            raise ValueError("Random Forest model is not trained. Train or load model first.")
        
        preds = self.model.predict(X)
        probs = self.model.predict_proba(X)[:, 1] if hasattr(self.model, "predict_proba") else np.zeros(len(preds))
        return preds, probs

    def save(self, filepath: Optional[str] = None):
        """Save model to disk using joblib."""
        path = filepath or os.path.join(MODEL_DIR, "random_forest.joblib")
        joblib.dump({
            "model": self.model,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "feature_importances": self.feature_importances,
            "is_trained": self.is_trained
        }, path)

    def load(self, filepath: Optional[str] = None):
        """Load model from disk."""
        path = filepath or os.path.join(MODEL_DIR, "random_forest.joblib")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Random Forest model not found at {path}")
        saved_data = joblib.load(path)
        self.model = saved_data["model"]
        self.n_estimators = saved_data["n_estimators"]
        self.random_state = saved_data["random_state"]
        self.feature_importances = saved_data.get("feature_importances", {})
        self.is_trained = saved_data["is_trained"]
