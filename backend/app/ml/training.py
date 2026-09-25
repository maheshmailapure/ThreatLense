import os
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from sklearn.model_selection import train_test_split
from app.ml.preprocessing import PreprocessingPipeline, load_nsl_kdd_dataset, prepare_dataset_for_training
from app.ml.feature_selection import FeatureSelector
from app.ml.pca import PCATransformer
from app.ml.random_forest import RandomForestModel
from app.ml.svm import SVMModel
from app.ml.kmeans import KMeansAnomalyDetector
from app.ml.isolation_forest import IsolationForestAnomalyDetector
from app.utils.logger import log_event, logger

MODEL_DIR = os.getenv("MODEL_DIR", "./models")
os.makedirs(MODEL_DIR, exist_ok=True)

class TrainingPipeline:
    def __init__(
        self,
        test_size: float = 0.3,
        random_state: int = 42,
        feature_selection_k: int = 20,
        pca_components: int = 10,
        rf_n_estimators: int = 100,
        svm_kernel: str = "rbf",
        kmeans_clusters: int = 5,
        anomaly_threshold_percentile: float = 95.0
    ):
        self.test_size = test_size
        self.random_state = random_state
        self.feature_selection_k = feature_selection_k
        self.pca_components = pca_components
        self.rf_n_estimators = rf_n_estimators
        self.svm_kernel = svm_kernel
        self.kmeans_clusters = kmeans_clusters
        self.anomaly_threshold_percentile = anomaly_threshold_percentile

        self.preprocessor = PreprocessingPipeline()
        self.feature_selector = FeatureSelector(k=self.feature_selection_k)
        self.pca = PCATransformer(n_components=self.pca_components)

    def execute(
        self,
        dataset_path: str,
        dataset_name: str,
        models_to_train: List[str]
    ) -> Dict[str, Any]:
        """Execute the end-to-end training and evaluation pipeline."""
        logger.info(f"Starting ML Training Pipeline on dataset: {dataset_name}")
        log_event("TRAINING_START", {"dataset": dataset_name, "models": models_to_train})

        # 1. Load Dataset
        df = load_nsl_kdd_dataset(dataset_path)
        total_samples = len(df)
        X_raw, y_binary, y_category = prepare_dataset_for_training(df)

        # 2. Stratified 70:30 Train/Test Split
        # Fallback to non-stratified if any class has fewer than 2 instances
        stratify_col = y_binary if (y_binary.value_counts().min() > 1) else None
        X_train_raw, X_test_raw, y_train, y_test, y_cat_train, y_cat_test = train_test_split(
            X_raw, y_binary, y_category,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=stratify_col
        )

        logger.info(f"Split completed: Train={len(X_train_raw)}, Test={len(X_test_raw)}")

        # 3. Fit Preprocessing ONLY on training data to prevent leakage
        X_train_proc, feature_names = self.preprocessor.fit_transform(X_train_raw)
        X_test_proc = self.preprocessor.transform(X_test_raw)
        self.preprocessor.save()

        # 4. Feature Selection
        X_train_sel, selected_features = self.feature_selector.fit_transform(
            X_train_proc, y_train.values, feature_names
        )
        X_test_sel = self.feature_selector.transform(X_test_proc)
        self.feature_selector.save()

        # 5. PCA Dimensionality Reduction
        X_train_pca = self.pca.fit_transform(X_train_sel)
        X_test_pca = self.pca.transform(X_test_sel)
        self.pca.save()

        results: Dict[str, Any] = {
            "dataset_name": dataset_name,
            "total_records": total_samples,
            "train_records": len(X_train_raw),
            "test_records": len(X_test_raw),
            "original_features_count": len(feature_names),
            "selected_features_count": len(selected_features),
            "pca_components_count": len(self.pca.explained_variance_ratio_),
            "pca_total_variance": round(self.pca.total_explained_variance_ * 100, 2),
            "pca_explained_variance_ratio": [round(v * 100, 2) for v in self.pca.explained_variance_ratio_],
            "selected_features": selected_features,
            "models": {}
        }

        # 6. Train Selected Models
        # Random Forest
        if "Random Forest" in models_to_train:
            logger.info("Training Random Forest...")
            rf = RandomForestModel(
                n_estimators=self.rf_n_estimators,
                random_state=self.random_state
            )
            rf_metrics, rf_time = rf.train(
                X_train_sel, y_train.values,
                X_test_sel, y_test.values,
                feature_names=selected_features
            )
            rf.save()
            results["models"]["Random Forest"] = {
                "metrics": rf_metrics,
                "training_time": round(rf_time, 3),
                "status": "TRAINED"
            }

        # SVM
        if "SVM" in models_to_train:
            logger.info("Training Support Vector Machine (SVM)...")
            svm = SVMModel(
                kernel=self.svm_kernel,
                random_state=self.random_state
            )
            # SVM is trained on PCA features for computational efficiency and numerical stability
            svm_metrics, svm_time = svm.train(
                X_train_pca, y_train.values,
                X_test_pca, y_test.values
            )
            svm.save()
            results["models"]["SVM"] = {
                "metrics": svm_metrics,
                "training_time": round(svm_time, 3),
                "status": "TRAINED"
            }

        # K-Means (Unsupervised Anomaly Detection)
        if "K-Means" in models_to_train:
            logger.info("Training K-Means Anomaly Detector...")
            kmeans = KMeansAnomalyDetector(
                n_clusters=self.kmeans_clusters,
                threshold_percentile=self.anomaly_threshold_percentile,
                random_state=self.random_state
            )
            km_metrics, km_time = kmeans.train(
                X_train_pca, y_train.values,
                X_test_pca, y_test.values
            )
            kmeans.save()
            results["models"]["K-Means"] = {
                "metrics": km_metrics,
                "training_time": round(km_time, 3),
                "status": "TRAINED"
            }

        # Isolation Forest (Unsupervised Outlier Isolation)
        if "Isolation Forest" in models_to_train:
            logger.info("Training Isolation Forest Anomaly Detector...")
            iso = IsolationForestAnomalyDetector(
                n_estimators=100,
                contamination=0.1,
                random_state=self.random_state
            )
            iso_metrics, iso_time = iso.train(
                X_train_pca, y_train.values,
                X_test_pca, y_test.values
            )
            iso.save()
            results["models"]["Isolation Forest"] = {
                "metrics": iso_metrics,
                "training_time": round(iso_time, 3),
                "status": "TRAINED"
            }

        # Save metadata.json
        metadata_path = os.path.join(MODEL_DIR, "metadata.json")
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        log_event("TRAINING_COMPLETE", {"dataset": dataset_name, "models_trained": list(results["models"].keys())})
        return results
