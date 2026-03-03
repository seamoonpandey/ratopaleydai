"""
train_ranker — trains XGBoost model for payload ranking
uses collected execution results to predict payload success probability
"""

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
)

# add payload-gen-module to path for feature extraction
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "modules" / "payload-gen-module"))

from feature_extractor import extract_features, get_feature_names

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("train_ranker")

# paths
TRAINING_DATA_FILE = Path(__file__).resolve().parent.parent.parent / "dataset" / "ranker_training" / "ranker_training_samples.jsonl"
MODEL_OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "model" / "ranker"
MODEL_OUTPUT_PATH = MODEL_OUTPUT_DIR / "xgboost_ranker.json"
METRICS_OUTPUT_PATH = MODEL_OUTPUT_DIR / "ranker_metrics.json"


def load_training_data() -> tuple[list[dict], list[int]]:
    """
    Load training samples from JSONL file.
    
    Returns:
        (samples, labels) where samples are payload dicts and labels are 0/1 success
    """
    if not TRAINING_DATA_FILE.exists():
        raise FileNotFoundError(f"Training data not found at {TRAINING_DATA_FILE}")
    
    samples = []
    labels = []
    
    with open(TRAINING_DATA_FILE, "r") as f:
        for line in f:
            sample = json.loads(line)
            samples.append(sample)
            labels.append(1 if sample.get("success", False) else 0)
    
    logger.info(f"Loaded {len(samples)} training samples")
    
    # compute class distribution
    pos_count = sum(labels)
    neg_count = len(labels) - pos_count
    logger.info(f"Class distribution: {pos_count} success ({pos_count/len(labels)*100:.1f}%), {neg_count} failure")
    
    return samples, labels


def extract_features_from_samples(samples: list[dict]) -> np.ndarray:
    """
    Extract feature vectors from training samples.
    
    Returns:
        numpy array of shape (n_samples, n_features)
    """
    feature_names = get_feature_names()
    feature_vectors = []
    
    for sample in samples:
        # reconstruct payload dict for feature extraction
        payload_dict = {
            "payload": sample.get("payload_text", ""),
            "technique": sample.get("technique", "original"),
            "severity": sample.get("severity", "medium"),
            "target_param": sample.get("target_param", ""),
        }
        
        features = extract_features(
            payload=payload_dict,
            context=sample.get("context", "generic"),
            waf=sample.get("waf"),
            allowed_chars=sample.get("allowed_chars"),
        )
        
        # ensure features are in correct order
        feature_vector = [features.get(name, 0.0) for name in feature_names]
        feature_vectors.append(feature_vector)
    
    X = np.array(feature_vectors, dtype=np.float32)
    logger.info(f"Extracted features: shape={X.shape}")
    
    return X


def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    feature_names: list[str],
) -> xgb.Booster:
    """
    Train XGBoost classifier for payload ranking.
    
    Returns:
        trained XGBoost Booster model
    """
    # compute scale_pos_weight for imbalanced classes
    pos_count = np.sum(y_train)
    neg_count = len(y_train) - pos_count
    scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1.0
    
    logger.info(f"Training with scale_pos_weight={scale_pos_weight:.2f}")
    
    # create DMatrix
    dtrain = xgb.DMatrix(X_train, label=y_train, feature_names=feature_names)
    dval = xgb.DMatrix(X_val, label=y_val, feature_names=feature_names)
    
    # XGBoost parameters optimized for ranking
    params = {
        "objective": "binary:logistic",  # binary classification with probability output
        "eval_metric": ["logloss", "auc"],
        "max_depth": 6,
        "learning_rate": 0.1,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 3,
        "gamma": 0.1,
        "scale_pos_weight": scale_pos_weight,
        "tree_method": "hist",
        "seed": 42,
    }
    
    # train with early stopping
    evals = [(dtrain, "train"), (dval, "val")]
    model = xgb.train(
        params,
        dtrain,
        num_boost_round=500,
        evals=evals,
        early_stopping_rounds=50,
        verbose_eval=50,
    )
    
    logger.info(f"Training complete: best iteration={model.best_iteration}, best score={model.best_score:.4f}")
    
    return model


def evaluate_model(
    model: xgb.Booster,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: list[str],
) -> dict[str, Any]:
    """
    Evaluate trained model on test set.
    
    Returns:
        metrics dict with accuracy, precision, recall, f1, auc
    """
    dtest = xgb.DMatrix(X_test, feature_names=feature_names)
    y_pred_proba = model.predict(dtest)
    y_pred = (y_pred_proba >= 0.5).astype(int)
    
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "auc": float(roc_auc_score(y_test, y_pred_proba)),
    }
    
    logger.info(f"Test metrics: {json.dumps(metrics, indent=2)}")
    
    # print classification report
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["failure", "success"], zero_division=0))
    
    return metrics


def get_feature_importance(model: xgb.Booster, feature_names: list[str]) -> dict[str, float]:
    """
    Get feature importance from trained model.
    """
    importance_dict = model.get_score(importance_type="gain")
    
    # map to feature names and sort
    importance = {}
    for feat_name in feature_names:
        importance[feat_name] = importance_dict.get(feat_name, 0.0)
    
    # sort by importance
    sorted_importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
    
    logger.info("\nTop 10 most important features:")
    for i, (feat, score) in enumerate(list(sorted_importance.items())[:10], 1):
        logger.info(f"  {i}. {feat}: {score:.2f}")
    
    return sorted_importance


def main():
    """
    Main training pipeline.
    """
    logger.info("Starting XGBoost ranker training pipeline")
    
    # load training data
    samples, labels = load_training_data()
    
    if len(samples) < 100:
        logger.warning(
            f"Only {len(samples)} training samples available. "
            "Recommend collecting at least 1000 samples for robust training."
        )
    
    # extract features
    X = extract_features_from_samples(samples)
    y = np.array(labels, dtype=np.int32)
    
    # split into train/val/test (70/15/15)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )
    
    logger.info(
        f"Data split: train={len(X_train)}, val={len(X_val)}, test={len(X_test)}"
    )
    
    # train model
    feature_names = get_feature_names()
    model = train_model(X_train, y_train, X_val, y_val, feature_names)
    
    # evaluate on test set
    metrics = evaluate_model(model, X_test, y_test, feature_names)
    
    # get feature importance
    importance = get_feature_importance(model, feature_names)
    
    # save model
    MODEL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_model(str(MODEL_OUTPUT_PATH))
    logger.info(f"Model saved to {MODEL_OUTPUT_PATH}")
    
    # save metrics
    output_data = {
        "metrics": metrics,
        "feature_importance": importance,
        "training_samples": len(samples),
        "data_split": {
            "train": len(X_train),
            "val": len(X_val),
            "test": len(X_test),
        },
        "best_iteration": int(model.best_iteration),
        "best_score": float(model.best_score),
    }
    
    with open(METRICS_OUTPUT_PATH, "w") as f:
        json.dump(output_data, f, indent=2)
    logger.info(f"Metrics saved to {METRICS_OUTPUT_PATH}")
    
    logger.info("Training pipeline complete!")


if __name__ == "__main__":
    main()
