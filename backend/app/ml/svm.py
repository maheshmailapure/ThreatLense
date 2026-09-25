import os
import time
import joblib
import numpy as np
from typing import Dict, Any, Optional, Tuple
from sklearn.svm import SVC
from app.ml.evaluation import calculate_binary_metrics

MODEL_DIR = os.getenv("MODEL_DIR", "./models")
os.makedirs(MODEL_DIR, exist_ok=True)

class SVMModel:
    def __init__(self, kernel: str = "rbf", C: float = 1.0, random_state: int = 42):
        self.kernel = kernel
        self.C = C
        self.random_state = random_state
        self.model: Optional[SVC] = None
        self.is_trained: bool = False

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray
    ) -> Tuple[Dict[str, Any], float]:
        """Train SVM model with max_iter limit for responsive training, then evaluate on test partition."""
        start_time = time.time()
        
        # We set probability=True and max_iter=3000 to maintain fast execution during interactive academic training
        self.model = SVC(
            kernel=self.kernel,
            C=self.C,
            probability=True,
            random_state=self.random_state,
            max_iter=3000
        )
        self.model.fit(X_train, y_train)
        training_time = time.time() - start_time

        # Predict on test set
        y_pred = self.model.predict(X_test)
        metrics = calculate_binary_metrics(y_test, y_pred)
        metrics["hyperparameters"] = {
            "kernel": self.kernel,
            "C": self.C,
            "random_state": self.random_state
        }

        self.is_trained = True
        return metrics, training_time

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Return predictions and attack class probability."""
        if not self.is_trained or self.model is None:
            raise ValueError("SVM model is not trained. Train or load model first.")
        
        preds = self.model.predict(X)
        probs = self.model.predict_proba(X)[:, 1] if hasattr(self.model, "predict_proba") else np.zeros(len(preds))
        return preds, probs

    def save(self, filepath: Optional[str] = None):
        """Save SVM model to disk using joblib."""
        path = filepath or os.path.join(MODEL_DIR, "svm.joblib")
        joblib.dump({
            "model": self.model,
            "kernel": self.kernel,
            "C": self.C,
            "random_state": self.random_state,
            "is_trained": self.is_trained
        }, path)

    def load(self, filepath: Optional[str] = None):
        """Load SVM model from disk."""
        path = filepath or os.path.join(MODEL_DIR, "svm.joblib")
        if not os.path.exists(path):
            raise FileNotFoundError(f"SVM model not found at {path}")
        saved_data = joblib.load(path)
        self.model = saved_data["model"]
        self.kernel = saved_data["kernel"]
        self.C = saved_data["C"]
        self.random_state = saved_data["random_state"]
        self.is_trained = saved_data["is_trained"]
