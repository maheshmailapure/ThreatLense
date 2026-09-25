import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple
from app.ml.preprocessing import PreprocessingPipeline
from app.ml.feature_selection import FeatureSelector
from app.ml.pca import PCATransformer
from app.ml.random_forest import RandomForestModel
from app.ml.svm import SVMModel
from app.ml.kmeans import KMeansAnomalyDetector
from app.ml.isolation_forest import IsolationForestAnomalyDetector
from app.utils.helpers import evaluate_risk, map_attack_category

MODEL_DIR = os.getenv("MODEL_DIR", "./models")

class PredictionEngine:
    def __init__(self):
        self.preprocessor = PreprocessingPipeline()
        self.feature_selector = FeatureSelector()
        self.pca = PCATransformer()
        self.rf = RandomForestModel()
        self.svm = SVMModel()
        self.kmeans = KMeansAnomalyDetector()
        self.iso_forest = IsolationForestAnomalyDetector()
        self.is_loaded = False

    def load_artifacts(self) -> bool:
        """Load all saved preprocessing transformers and ML models from disk."""
        try:
            self.preprocessor.load()
            self.feature_selector.load()
            self.pca.load()

            # Attempt loading individual models
            if os.path.exists(os.path.join(MODEL_DIR, "random_forest.joblib")):
                self.rf.load()
            if os.path.exists(os.path.join(MODEL_DIR, "svm.joblib")):
                self.svm.load()
            if os.path.exists(os.path.join(MODEL_DIR, "kmeans.joblib")):
                self.kmeans.load()
            if os.path.exists(os.path.join(MODEL_DIR, "isolation_forest.joblib")):
                self.iso_forest.load()

            self.is_loaded = True
            return True
        except Exception as e:
            self.is_loaded = False
            return False

    def predict_dataframe(
        self,
        df: pd.DataFrame,
        model_name: str = "Random Forest"
    ) -> List[Dict[str, Any]]:
        """Run batch inference on a pandas DataFrame of raw or NSL-KDD network records."""
        if not self.is_loaded:
            if not self.load_artifacts():
                raise RuntimeError("Trained models not found. Please train models first.")

        # 1. Transform raw dataframe through saved preprocessor
        X_proc = self.preprocessor.transform(df)
        X_sel = self.feature_selector.transform(X_proc)
        X_pca = self.pca.transform(X_sel)

        # 2. Always compute anomaly score via K-Means or Isolation Forest
        anomaly_flags = np.zeros(len(df), dtype=int)
        anomaly_scores = np.zeros(len(df), dtype=float)
        if self.kmeans.is_trained:
            km_flags, km_scores = self.kmeans.predict(X_pca)
            anomaly_flags = km_flags
            anomaly_scores = km_scores
        elif self.iso_forest.is_trained:
            iso_flags, iso_scores = self.iso_forest.predict(X_pca)
            anomaly_flags = iso_flags
            anomaly_scores = iso_scores

        # 3. Model Classification
        if model_name == "Random Forest" and self.rf.is_trained:
            preds, probs = self.rf.predict(X_sel)
        elif model_name == "SVM" and self.svm.is_trained:
            preds, probs = self.svm.predict(X_pca)
        elif model_name == "K-Means" and self.kmeans.is_trained:
            preds = anomaly_flags
            probs = anomaly_scores
        elif model_name == "Isolation Forest" and self.iso_forest.is_trained:
            preds = anomaly_flags
            probs = anomaly_scores
        else:
            # Fallback to RF or whatever is trained
            if self.rf.is_trained:
                preds, probs = self.rf.predict(X_sel)
                model_name = "Random Forest"
            else:
                preds = anomaly_flags
                probs = anomaly_scores

        results = []
        for i in range(len(df)):
            row = df.iloc[i].to_dict()
            is_attack = bool(preds[i] == 1)
            pred_label = "ATTACK" if is_attack else "NORMAL"
            score = float(anomaly_scores[i])
            is_anom = bool(anomaly_flags[i] == 1)
            conf = float(probs[i]) if is_attack else float(1.0 - probs[i])

            # Determine attack category from raw label if present, else infer based on flow characteristics
            raw_label = str(row.get("label", row.get("class", "normal"))).strip().lower()
            if raw_label != "normal" and raw_label != "unknown" and raw_label != "":
                attack_type = map_attack_category(raw_label)
            else:
                if is_attack:
                    # Heuristic inference from network features
                    srv_count = float(row.get("srv_count", 0))
                    src_bytes = float(row.get("src_bytes", 0))
                    dst_bytes = float(row.get("dst_bytes", 0))
                    failed_logins = float(row.get("num_failed_logins", 0))
                    root_shell = float(row.get("root_shell", 0))

                    if root_shell > 0:
                        attack_type = "U2R"
                    elif failed_logins > 0 or (src_bytes > 5000 and dst_bytes == 0):
                        attack_type = "R2L"
                    elif srv_count > 100:
                        attack_type = "DoS"
                    else:
                        attack_type = "Probe"
                else:
                    attack_type = "Normal"

            risk_level, risk_desc = evaluate_risk(
                prediction=pred_label,
                attack_type=attack_type,
                anomaly_score=score,
                confidence=conf
            )

            # Generate Explainability metadata
            explanation = {
                "summary": risk_desc,
                "model_prediction": pred_label,
                "confidence_percentage": round(conf * 100, 2),
                "anomaly_score": round(score, 4),
                "anomaly_flagged": is_anom,
                "factors": []
            }

            if is_attack:
                explanation["factors"].append(f"Model ({model_name}) identified attack pattern with {conf*100:.1f}% confidence.")
            if is_anom:
                explanation["factors"].append(f"Unsupervised anomaly detector identified unusual behavioral deviation (score: {score:.3f}).")
            if not is_attack and not is_anom:
                explanation["factors"].append("All packet flow metrics conform to normal baseline behavior.")

            # Top feature weights if RF
            if self.rf.is_trained and len(self.rf.feature_importances) > 0:
                top_3 = list(self.rf.feature_importances.items())[:3]
                explanation["top_influential_features"] = [
                    {"feature": k, "importance": round(v * 100, 2), "packet_value": row.get(k, "N/A")}
                    for k, v in top_3
                ]

            results.append({
                "prediction": pred_label,
                "attack_type": attack_type,
                "model": model_name,
                "anomaly_score": round(score, 4),
                "is_anomaly": is_anom,
                "risk_level": risk_level,
                "input_features": {k: str(v) for k, v in list(row.items())[:15]}, # Key features
                "explanation": explanation
            })

        return results
