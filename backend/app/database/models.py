import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="analyst")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Dataset(Base):
    __tablename__ = "datasets"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    original_name = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    total_records = Column(Integer, default=0)
    total_features = Column(Integer, default=0)
    uploaded_at = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String(50), default="READY")
    meta_info = Column(JSON, default=dict)

    detections = relationship("Detection", back_populates="dataset", cascade="all, delete-orphan")

class MLModel(Base):
    __tablename__ = "models"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)  # e.g., "Random Forest", "SVM", "K-Means", "Isolation Forest"
    version = Column(String(20), default="1.0.0")
    training_date = Column(DateTime, default=datetime.datetime.utcnow)
    dataset_name = Column(String(255), default="NSL-KDD")
    accuracy = Column(Float, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    false_positive_rate = Column(Float, nullable=True)
    training_time = Column(Float, default=0.0)  # In seconds
    status = Column(String(50), default="TRAINED")  # TRAINED, TRAINING, FAILED
    model_path = Column(String(512), nullable=True)
    hyperparameters = Column(JSON, default=dict)
    metrics_json = Column(JSON, default=dict)  # Detailed metrics including confusion matrix

class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(Integer, ForeignKey("datasets.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    prediction = Column(String(50), nullable=False)  # NORMAL, ATTACK
    attack_type = Column(String(50), default="Normal")  # Normal, DoS, Probe, R2L, U2R, or specific label
    model = Column(String(100), nullable=False)  # Random Forest, SVM, K-Means, etc.
    anomaly_score = Column(Float, default=0.0)
    is_anomaly = Column(Boolean, default=False)
    risk_level = Column(String(20), default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    input_features = Column(JSON, default=dict)  # Sample packet/flow attributes
    explanation = Column(JSON, default=dict)  # Key detection reasons / feature weights

    dataset = relationship("Dataset", back_populates="detections")
    alerts = relationship("Alert", back_populates="detection", cascade="all, delete-orphan")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(Integer, ForeignKey("detections.id", ondelete="CASCADE"), nullable=False)
    alert_type = Column(String(50), nullable=False)  # e.g., "DoS Flood Detected", "Suspicious Probe Scan", "Zero-Day Anomaly"
    risk_level = Column(String(20), default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(50), default="NEW")  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True)

    detection = relationship("Detection", back_populates="alerts")
