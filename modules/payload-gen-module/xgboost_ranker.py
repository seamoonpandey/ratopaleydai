"""
xgboost_ranker — ML-powered payload ranking using XGBoost
learns from historical execution success to predict execution probability
falls back to heuristic ranker if model not available
"""

import logging
import os
from pathlib import Path
from typing import Any

import numpy as np

from feature_extractor import extract_features, get_feature_names
from ranker import rank_payloads as heuristic_rank_payloads

logger = logging.getLogger(__name__)

# model path
MODEL_DIR = Path(__file__).parent.parent.parent / "model" / "ranker"
MODEL_PATH = MODEL_DIR / "xgboost_ranker.json"

# global model instance
_model = None
_feature_names = None


def load_model() -> bool:
    """
    Load XGBoost model from disk.
    Returns True if successful, False if model not found.
    """
    global _model, _feature_names
    
    if not MODEL_PATH.exists():
        logger.warning(f"XGBoost ranker model not found at {MODEL_PATH}")
        return False
    
    try:
        import xgboost as xgb
        
        _model = xgb.Booster()
        _model.load_model(str(MODEL_PATH))
        _feature_names = get_feature_names()
        
        logger.info(f"Loaded XGBoost ranker model from {MODEL_PATH}")
        return True
    except ImportError:
        logger.warning("xgboost not installed, falling back to heuristic ranker")
        return False
    except Exception as e:
        logger.error(f"Failed to load XGBoost ranker model: {e}")
        return False


def rank_payloads(
    payloads: list[dict],
    context: str,
    waf: str | None = None,
    allowed_chars: list[str] | None = None,
    limit: int | None = None,
) -> list[dict]:
    """
    Rank payloads using XGBoost model or fallback to heuristic ranker.
    
    Args:
        payloads: list of payload dicts with 'payload', 'technique', 'severity'
        context: target context label (e.g., 'script_injection')
        waf: optional WAF type detected
        allowed_chars: optional list of allowed special characters
        limit: optional limit on number of payloads to return
    
    Returns:
        sorted list of payloads with 'score' field attached
    """
    global _model, _feature_names
    
    # try to load model if not already loaded
    if _model is None:
        load_model()
    
    # fallback to heuristic if model unavailable
    if _model is None:
        logger.info("Using heuristic ranker (XGBoost model not available)")
        return heuristic_rank_payloads(payloads, context, allowed_chars, limit)
    
    # use XGBoost model
    try:
        scored = _rank_with_xgboost(payloads, context, waf, allowed_chars)
        
        # sort by score descending
        scored.sort(key=lambda x: x["score"], reverse=True)
        
        if limit:
            scored = scored[:limit]
        
        logger.info(
            f"XGBoost ranked {len(payloads)} payloads for context={context}, "
            f"top score={scored[0]['score'] if scored else 0}"
        )
        return scored
    
    except Exception as e:
        logger.error(f"XGBoost ranking failed, falling back to heuristic: {e}")
        return heuristic_rank_payloads(payloads, context, allowed_chars, limit)


def _rank_with_xgboost(
    payloads: list[dict],
    context: str,
    waf: str | None,
    allowed_chars: list[str] | None,
) -> list[dict]:
    """
    Rank payloads using loaded XGBoost model.
    """
    import xgboost as xgb
    
    global _model, _feature_names
    
    if not payloads:
        return []
    
    # extract features for all payloads
    feature_vectors = []
    for payload in payloads:
        features = extract_features(payload, context, waf, allowed_chars)
        # ensure features are in correct order
        feature_vector = [features.get(name, 0.0) for name in _feature_names]
        feature_vectors.append(feature_vector)
    
    # convert to DMatrix for XGBoost
    X = np.array(feature_vectors, dtype=np.float32)
    dmatrix = xgb.DMatrix(X, feature_names=_feature_names)
    
    # predict execution probability
    scores = _model.predict(dmatrix)
    
    # attach scores to payloads
    scored = []
    for payload, score in zip(payloads, scores):
        scored.append({**payload, "score": float(score)})
    
    return scored


def get_feature_importance() -> dict[str, float] | None:
    """
    Get feature importance from loaded model.
    Returns None if model not loaded.
    """
    global _model, _feature_names
    
    if _model is None or _feature_names is None:
        return None
    
    try:
        importance_dict = _model.get_score(importance_type="gain")
        # map feature indices to names
        result = {}
        for feat_name in _feature_names:
            result[feat_name] = importance_dict.get(feat_name, 0.0)
        return result
    except Exception as e:
        logger.error(f"Failed to get feature importance: {e}")
        return None


# try to load model at module import time
load_model()
