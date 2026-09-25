import numpy as np
from typing import Dict, Any, List, Optional
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, classification_report

def calculate_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    """
    Calculate exact academic metrics for binary classification with zero-division safety:
    - Accuracy = (TP + TN) / (TP + TN + FP + FN)
    - Precision = TP / (TP + FP)
    - Recall = TP / (TP + FN)
    - F1 Score = 2 * Precision * Recall / (Precision + Recall)
    - False Positive Rate (FPR) = FP / (FP + TN)
    - Confusion Matrix = [[TN, FP], [FN, TP]]
    """
    y_true_arr = np.array(y_true, dtype=int)
    y_pred_arr = np.array(y_pred, dtype=int)

    cm = confusion_matrix(y_true_arr, y_pred_arr, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    total = float(tp + tn + fp + fn)
    accuracy = float((tp + tn) / total) if total > 0 else 0.0
    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "false_positive_rate": round(fpr * 100, 2),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
            "matrix": [
                [int(tn), int(fp)],
                [int(fn), int(tp)]
            ],
            "labels": ["Normal", "Attack"]
        }
    }


def calculate_multiclass_metrics(y_true: List[str], y_pred: List[str], class_labels: Optional[List[str]] = None) -> Dict[str, Any]:
    """Calculate multi-class evaluation breakdown for DoS, Probe, R2L, U2R, Normal."""
    if class_labels is None:
        class_labels = sorted(list(set(y_true) | set(y_pred)))

    cm = confusion_matrix(y_true, y_pred, labels=class_labels)
    
    report = classification_report(y_true, y_pred, labels=class_labels, output_dict=True, zero_division=0)
    
    return {
        "classes": class_labels,
        "confusion_matrix": cm.tolist(),
        "report": report
    }
