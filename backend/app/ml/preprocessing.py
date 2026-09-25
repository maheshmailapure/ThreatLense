import os
import joblib
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, List, Optional
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from app.utils.helpers import NSL_KDD_COLUMNS, CATEGORICAL_COLUMNS, NUMERICAL_COLUMNS, map_attack_category

MODEL_DIR = os.getenv("MODEL_DIR", "./models")
os.makedirs(MODEL_DIR, exist_ok=True)

class PreprocessingPipeline:
    def __init__(self):
        self.preprocessor: Optional[ColumnTransformer] = None
        self.feature_names: List[str] = []
        self.is_fitted: bool = False

    def build_transformer(self) -> ColumnTransformer:
        """Construct the scikit-learn ColumnTransformer for categorical and numerical features."""
        numeric_transformer = Pipeline(steps=[
            ('scaler', StandardScaler())
        ])
        
        categorical_transformer = Pipeline(steps=[
            ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
        ])

        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, NUMERICAL_COLUMNS),
                ('cat', categorical_transformer, CATEGORICAL_COLUMNS)
            ],
            remainder='drop'
        )
        return preprocessor

    def fit_transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
        """Fit preprocessing pipeline on training features and return transformed numpy array with feature names."""
        # Ensure all required columns exist
        clean_df = self._clean_data(df)
        self.preprocessor = self.build_transformer()
        
        transformed_data = self.preprocessor.fit_transform(clean_df)
        
        # Extract resulting feature names
        cat_encoder = self.preprocessor.named_transformers_['cat'].named_steps['onehot']
        cat_feature_names = list(cat_encoder.get_feature_names_out(CATEGORICAL_COLUMNS))
        self.feature_names = NUMERICAL_COLUMNS + cat_feature_names
        self.is_fitted = True
        return transformed_data, self.feature_names

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform input features using the fitted preprocessor."""
        if not self.is_fitted or self.preprocessor is None:
            raise ValueError("Preprocessing pipeline is not fitted. Fit or load a trained pipeline first.")
        clean_df = self._clean_data(df)
        return self.preprocessor.transform(clean_df)

    def _clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean dataframe by handling missing, duplicate, and infinite values."""
        df_copy = df.copy()

        # Handle missing numerical columns by adding 0
        for col in NUMERICAL_COLUMNS:
            if col not in df_copy.columns:
                df_copy[col] = 0.0
            else:
                df_copy[col] = pd.to_numeric(df_copy[col], errors='coerce').fillna(0.0)
                # Replace inf and -inf
                df_copy[col] = df_copy[col].replace([np.inf, -np.inf], 0.0)

        # Handle categorical columns
        for col in CATEGORICAL_COLUMNS:
            if col not in df_copy.columns:
                df_copy[col] = "unknown"
            else:
                df_copy[col] = df_copy[col].astype(str).fillna("unknown")

        return df_copy

    def save(self, filepath: Optional[str] = None):
        """Save the preprocessor and feature names."""
        path = filepath or os.path.join(MODEL_DIR, "preprocessor.joblib")
        joblib.dump({
            "preprocessor": self.preprocessor,
            "feature_names": self.feature_names,
            "is_fitted": self.is_fitted
        }, path)

    def load(self, filepath: Optional[str] = None):
        """Load the saved preprocessor."""
        path = filepath or os.path.join(MODEL_DIR, "preprocessor.joblib")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Preprocessor file not found at {path}")
        saved_data = joblib.load(path)
        self.preprocessor = saved_data["preprocessor"]
        self.feature_names = saved_data["feature_names"]
        self.is_fitted = saved_data["is_fitted"]


def load_nsl_kdd_dataset(file_path: str) -> pd.DataFrame:
    """
    Robust loader for NSL-KDD dataset (.txt or .csv) and general network flow CSVs.
    Detects whether headers are present and maps standard 41/42/43 NSL-KDD column formats.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    # Inspect the first few lines to check delimiter and header
    try:
        sample_df = pd.read_csv(file_path, nrows=5, sep=None, engine='python')
    except Exception:
        sample_df = pd.read_csv(file_path, nrows=5)

    # Check if first row contains column names matching NSL-KDD or if it is headerless
    first_col = str(sample_df.columns[0]).strip().lower()
    has_header = first_col in ["duration", "protocol_type", "src_bytes"] or any(c in sample_df.columns for c in ["label", "class", "attack"])

    if has_header:
        df = pd.read_csv(file_path)
    else:
        # Standard NSL-KDD headerless format with 41-43 columns
        num_cols = sample_df.shape[1]
        if num_cols >= 41:
            col_names = list(NSL_KDD_COLUMNS)
            if num_cols >= 42:
                col_names.append("label")
            if num_cols >= 43:
                col_names.append("difficulty_level")
            # If there are additional columns, name them extra_i
            if num_cols > len(col_names):
                for i in range(len(col_names), num_cols):
                    col_names.append(f"extra_{i}")
            df = pd.read_csv(file_path, header=None, names=col_names[:num_cols])
        else:
            df = pd.read_csv(file_path)

    # Standardize label column name if present
    for target_name in ["label", "class", "attack", "attack_type", "status"]:
        if target_name in df.columns and target_name != "label":
            df["label"] = df[target_name]
            break

    return df


def prepare_dataset_for_training(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """
    Separates X and y from the dataset.
    Returns:
    - X: feature dataframe
    - y_binary: binary series (0 for Normal, 1 for Attack)
    - y_category: multi-class series (Normal, DoS, Probe, R2L, U2R)
    """
    df_clean = df.copy()
    if "label" not in df_clean.columns:
        # If no explicit label, default all to normal
        df_clean["label"] = "normal"

    y_category = df_clean["label"].apply(map_attack_category)
    y_binary = (y_category != "Normal").astype(int)

    # Drop label columns and difficulty level from X if present
    drop_cols = ["label", "difficulty_level", "class", "attack", "attack_type", "status"]
    feature_cols = [c for c in df_clean.columns if c not in drop_cols]
    X = df_clean[feature_cols]

    return X, y_binary, y_category
