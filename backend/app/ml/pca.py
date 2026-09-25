import os
import joblib
import numpy as np
from typing import Tuple, Optional, List, Dict, Any
from sklearn.decomposition import PCA

MODEL_DIR = os.getenv("MODEL_DIR", "./models")
os.makedirs(MODEL_DIR, exist_ok=True)

class PCATransformer:
    def __init__(self, n_components: int = 10):
        self.n_components = n_components
        self.pca: Optional[PCA] = None
        self.explained_variance_ratio_: List[float] = []
        self.total_explained_variance_: float = 0.0
        self.is_fitted: bool = False

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit PCA on training data and return reduced dimensionality components."""
        # Ensure n_components <= min(n_samples, n_features)
        actual_components = min(self.n_components, X.shape[1], X.shape[0])
        self.pca = PCA(n_components=actual_components, random_state=42)
        
        X_pca = self.pca.fit_transform(X)
        self.explained_variance_ratio_ = [float(v) for v in self.pca.explained_variance_ratio_]
        self.total_explained_variance_ = float(np.sum(self.explained_variance_ratio_))
        self.is_fitted = True
        return X_pca

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Project new data onto fitted principal components."""
        if not self.is_fitted or self.pca is None:
            raise ValueError("PCATransformer is not fitted. Fit or load a PCA model first.")
        return self.pca.transform(X)

    def save(self, filepath: Optional[str] = None):
        """Save the fitted PCA transformer."""
        path = filepath or os.path.join(MODEL_DIR, "pca.joblib")
        joblib.dump({
            "n_components": self.n_components,
            "pca": self.pca,
            "explained_variance_ratio_": self.explained_variance_ratio_,
            "total_explained_variance_": self.total_explained_variance_,
            "is_fitted": self.is_fitted
        }, path)

    def load(self, filepath: Optional[str] = None):
        """Load a saved PCA transformer."""
        path = filepath or os.path.join(MODEL_DIR, "pca.joblib")
        if not os.path.exists(path):
            raise FileNotFoundError(f"PCA file not found at {path}")
        saved_data = joblib.load(path)
        self.n_components = saved_data["n_components"]
        self.pca = saved_data["pca"]
        self.explained_variance_ratio_ = saved_data["explained_variance_ratio_"]
        self.total_explained_variance_ = saved_data["total_explained_variance_"]
        self.is_fitted = saved_data["is_fitted"]
