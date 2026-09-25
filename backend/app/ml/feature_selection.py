import os
import joblib
import numpy as np
from typing import List, Tuple, Optional, Dict, Any
from sklearn.feature_selection import SelectKBest, f_classif

MODEL_DIR = os.getenv("MODEL_DIR", "./models")
os.makedirs(MODEL_DIR, exist_ok=True)

class FeatureSelector:
    def __init__(self, k: int = 20):
        self.k = k
        self.selector: Optional[SelectKBest] = None
        self.selected_indices: List[int] = []
        self.selected_features: List[str] = []
        self.feature_scores: Dict[str, float] = {}
        self.is_fitted: bool = False

    def fit_transform(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> Tuple[np.ndarray, List[str]]:
        """Fit SelectKBest on training data and return reduced features."""
        # Ensure k does not exceed number of available features
        actual_k = min(self.k, X.shape[1])
        self.selector = SelectKBest(score_func=f_classif, k=actual_k)
        
        X_selected = self.selector.fit_transform(X, y)
        self.selected_indices = list(self.selector.get_support(indices=True))
        
        # Map selected indices to feature names if available
        if feature_names and len(feature_names) == X.shape[1]:
            self.selected_features = [feature_names[i] for i in self.selected_indices]
            # Store scores
            scores = self.selector.scores_
            for i, name in enumerate(feature_names):
                score_val = float(scores[i]) if scores is not None and not np.isnan(scores[i]) else 0.0
                self.feature_scores[name] = score_val
        else:
            self.selected_features = [f"feature_{i}" for i in self.selected_indices]

        self.is_fitted = True
        return X_selected, self.selected_features

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transform input features using the fitted selector."""
        if not self.is_fitted or self.selector is None:
            raise ValueError("FeatureSelector is not fitted. Fit or load a selector first.")
        return self.selector.transform(X)

    def save(self, filepath: Optional[str] = None):
        """Save the fitted feature selector."""
        path = filepath or os.path.join(MODEL_DIR, "feature_selector.joblib")
        joblib.dump({
            "k": self.k,
            "selector": self.selector,
            "selected_indices": self.selected_indices,
            "selected_features": self.selected_features,
            "feature_scores": self.feature_scores,
            "is_fitted": self.is_fitted
        }, path)

    def load(self, filepath: Optional[str] = None):
        """Load a saved feature selector."""
        path = filepath or os.path.join(MODEL_DIR, "feature_selector.joblib")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Feature selector file not found at {path}")
        saved_data = joblib.load(path)
        self.k = saved_data["k"]
        self.selector = saved_data["selector"]
        self.selected_indices = saved_data["selected_indices"]
        self.selected_features = saved_data["selected_features"]
        self.feature_scores = saved_data.get("feature_scores", {})
        self.is_fitted = saved_data["is_fitted"]
