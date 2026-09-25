import os
import shutil
from sqlalchemy.orm import Session
from app.database.database import engine, Base, SessionLocal
from app.database.models import User, Dataset
from app.utils.security import get_password_hash
from app.services.dataset_service import DatasetService
from app.ml.training import TrainingPipeline
from app.database.models import MLModel
import datetime

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

def seed_database():
    """Create database tables, default user accounts, seed dataset, and train initial models."""
    print("Creating database schema...")
    Base.metadata.create_all(bind=engine)

    db: Session = SessionLocal()
    try:
        # 1. Seed Admin & Analyst Users
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            print("Creating default admin account ('admin' / 'Admin@1234')...")
            admin_user = User(
                username="admin",
                password_hash=get_password_hash("Admin@1234"),
                role="admin"
            )
            db.add(admin_user)

        analyst_user = db.query(User).filter(User.username == "analyst").first()
        if not analyst_user:
            print("Creating default analyst account ('analyst' / 'Analyst@1234')...")
            analyst_user = User(
                username="analyst",
                password_hash=get_password_hash("Analyst@1234"),
                role="analyst"
            )
            db.add(analyst_user)

        db.commit()

        # 2. Seed Initial Dataset if available
        sample_source = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sample.csv")
        existing_dataset = db.query(Dataset).first()

        if not existing_dataset and os.path.exists(sample_source):
            print("Importing initial synthetic NSL-KDD dataset...")
            dest_path = os.path.join(UPLOAD_DIR, "NSL_KDD_Sample.csv")
            shutil.copy(sample_source, dest_path)

            from app.ml.preprocessing import load_nsl_kdd_dataset
            df = load_nsl_kdd_dataset(dest_path)

            cols = list(df.columns)
            cat_cols = list(df.select_dtypes(include=['object', 'category']).columns)
            num_cols = [c for c in cols if c not in cat_cols]
            class_dist = df["label"].astype(str).value_counts().head(10).to_dict() if "label" in df.columns else {}

            meta_info = {
                "columns": cols,
                "categorical_columns": cat_cols,
                "numerical_columns": num_cols,
                "missing_values": int(df.isna().sum().sum()),
                "duplicates": int(df.duplicated().sum()),
                "class_distribution": class_dist,
                "memory_usage_mb": round(df.memory_usage(deep=True).sum() / (1024 * 1024), 2)
            }

            dataset_record = Dataset(
                filename="NSL_KDD_Sample.csv",
                original_name="sample.csv",
                file_path=dest_path,
                total_records=len(df),
                total_features=df.shape[1],
                status="READY",
                meta_info=meta_info
            )
            db.add(dataset_record)
            db.commit()
            db.refresh(dataset_record)
            existing_dataset = dataset_record
            print(f"Dataset '{dataset_record.filename}' seeded successfully with {dataset_record.total_records} records.")

        # 3. Pre-train ML Models for instantaneous demonstration
        if existing_dataset and db.query(MLModel).count() == 0:
            print("Training initial AI-IDS models (Random Forest, SVM, K-Means, Isolation Forest)...")
            pipeline = TrainingPipeline(
                test_size=0.3,
                random_state=42,
                feature_selection_k=20,
                pca_components=10,
                rf_n_estimators=100,
                svm_kernel="rbf",
                kmeans_clusters=5
            )
            results = pipeline.execute(
                dataset_path=existing_dataset.file_path,
                dataset_name=existing_dataset.filename,
                models_to_train=["Random Forest", "SVM", "K-Means", "Isolation Forest"]
            )

            for model_name, model_info in results.get("models", {}).items():
                metrics = model_info.get("metrics", {})
                m_record = MLModel(
                    name=model_name,
                    version="1.0.0",
                    training_date=datetime.datetime.utcnow(),
                    dataset_name=existing_dataset.filename,
                    accuracy=metrics.get("accuracy"),
                    precision=metrics.get("precision"),
                    recall=metrics.get("recall"),
                    f1_score=metrics.get("f1_score"),
                    false_positive_rate=metrics.get("false_positive_rate"),
                    training_time=model_info.get("training_time", 0.0),
                    status="TRAINED",
                    hyperparameters=metrics.get("hyperparameters", {}),
                    metrics_json=metrics
                )
                db.add(m_record)
            db.commit()
            print("Initial ML models trained and registered successfully.")

        print("Database seed complete! System ready.")

    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
