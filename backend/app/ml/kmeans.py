import os
import time
import joblib
import numpy as np
from typing import Dict, Any, Optional, Tuple
from sklearn.cluster import KMeans
from app.ml.evaluation import calculate_binary_metrics

MODEL_DIR = os.getenv("MODEL_DIR", "./models")
os.makedirs(MODEL_DIR, exist_ok=True)

class KMeansAnomalyDetector:
    def __init__(self, n_clusters: int = 5, threshold_percentile: float = 95.0, random_state: int = 42):
        self.n_clusters = n_clusters
        self.threshold_percentile = threshold_percentile
        self.random_state = random_state
        self.model: Optional[KMeans] = None
        self.distance_threshold: float = 0.0
        self.max_training_distance: float = 1.0
        self.is_trained: bool = False

    def train(
        self,
        X_train: np.ndarray,
        y_train: Optional[np.ndarray] = None,
        X_test: Optional[np.ndarray] = None,
        y_test: Optional[np.ndarray] = None
    ) -> Tuple[Dict[str, Any], float]:
        """Train unsupervised K-Means clustering and compute anomaly threshold from centroid distances."""
        start_time = time.time()
        
        self.model = KMeans(
            n_clusters=self.n_clusters,
            random_state=self.random_state,
            n_init=10
        )
        self.model.fit(X_train)
        training_time = time.time() - start_time

        # Calculate distances of all training points to their closest centroid
        train_distances = self._compute_centroid_distances(X_train)
        self.distance_threshold = float(np.percentile(train_distances, self.threshold_percentile))
        self.max_training_distance = float(np.max(train_distances)) if np.max(train_distances) > 0 else 1.0

        metrics: Dict[str, Any] = {
            "evaluation_type": "Unsupervised Anomaly Clustering",
            "inertia": round(float(self.model.inertia_), 2),
            "n_clusters": self.n_clusters,
            "threshold_percentile": self.threshold_percentile,
            "distance_threshold": round(self.distance_threshold, 4),
            "mean_centroid_distance": round(float(np.mean(train_distances)), 4),
            "hyperparameters": {
                "n_clusters": self.n_clusters,
                "threshold_percentile": self.threshold_percentile,
                "random_state": self.random_state
            }
        }

        # If ground truth labels exist on test partition, evaluate unsupervised anomaly detection vs ground truth
        if X_test is not None and y_test is not None:
            test_distances = self._compute_centroid_distances(X_test)
            # Binary flag: distance > threshold => flagged as anomaly (predicted attack)
            y_pred_anomaly = (test_distances > self.distance_threshold).astype(int)
            eval_metrics = calculate_binary_metrics(y_test, y_pred_anomaly)
            
            metrics["accuracy"] = eval_metrics["accuracy"]
            metrics["precision"] = eval_metrics["precision"]
            metrics["recall"] = eval_metrics["recall"]
            metrics["f1_score"] = eval_metrics["f1_score"]
            metrics["false_positive_rate"] = eval_metrics["false_positive_rate"]
            metrics["confusion_matrix"] = eval_metrics["confusion_matrix"]
            metrics["note"] = (
                "Unsupervised anomaly detection evaluated by thresholding centroid distance "
                "against labeled test partition."
            )

        self.is_trained = True
        return metrics, training_time

    def _compute_centroid_distances(self, X: np.ndarray) -> np.ndarray:
        """Compute Euclidean distance of each point to its assigned cluster centroid."""
        if self.model is None:
            raise ValueError("KMeans model is not fitted.")
        # Cluster centers shape: (n_clusters, n_features)
        centers = self.model.cluster_centers_
        labels = self.model.predict(X)
        # Vectorized Euclidean distance from point to assigned centroid
        distances = np.linalg.norm(X - centers[labels], axis=1)
        return distances

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Return binary anomaly predictions (1 for anomaly, 0 for normal)
        and normalized anomaly score in [0.0, 1.0].
        """
        if not self.is_trained or self.model is None:
            raise ValueError("KMeans model is not trained. Train or load model first.")
        
        distances = self._compute_centroid_distances(X)
        is_anomaly = (distances > self.distance_threshold).astype(int)
        
        # Scale anomaly score: 0.0 = on centroid, 1.0 = highly distant outlier
        max_dist = max(self.max_training_distance, np.max(distances) if len(distances) > 0 else 1.0)
        anomaly_scores = np.clip(distances / max_dist, 0.0, 1.0)
        
        return is_anomaly, anomaly_scores

    def save(self, filepath: Optional[str] = None):
        """Save KMeans model to disk using joblib."""
        path = filepath or os.path.join(MODEL_DIR, "kmeans.joblib")
        joblib.dump({
            "model": self.model,
            "n_clusters": self.n_clusters,
            "threshold_percentile": self.threshold_percentile,
            "distance_threshold": self.distance_threshold,
            "max_training_distance": self.max_training_distance,
            "random_state": self.random_state,
            "is_trained": self.is_trained
        }, path)

    def load(self, filepath: Optional[str] = None):
        """Load KMeans model from disk."""
        path = filepath or os.path.join(MODEL_DIR, "kmeans.joblib")
        if not os.path.exists(path):
            raise FileNotFoundError(f"KMeans model not found at {path}")
        saved_data = joblib.load(path)
        self.model = saved_data["model"]
        self.n_clusters = saved_data["n_clusters"]
        self.threshold_percentile = saved_data["threshold_percentile"]
        self.distance_threshold = saved_data["distance_threshold"]
        self.max_training_distance = saved_data.get("max_training_distance", 1.0)
        self.random_state = saved_data["random_state"]
        self.is_trained = saved_data["is_trained"]
