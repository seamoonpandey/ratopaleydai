#!/usr/bin/env python3
"""
utils.py — adapted to use the real training model (XSSClassifier) and labels.

This file:
- imports XSSClassifier from model/xss_classifier.py (adds model/ to sys.path)
- provides load_checkpoint(), predict_batch(), softmax_np(), save_json()
- defaults point to model/checkpoints/best.pt and model/tokenizer
"""

from pathlib import Path
import sys
import json
from typing import List, Tuple
import numpy as np
import torch
import torch.nn as nn

# Add the project's model/ directory to python path so we can import xss_classifier
# tools/inference/utils.py  -> parents[2] = project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = str(PROJECT_ROOT / "model")
if MODEL_DIR not in sys.path:
    sys.path.insert(0, MODEL_DIR)

# Import the actual model used in training
try:
    from xss_classifier import XSSClassifier
except Exception as e:
    raise ImportError(f"Could not import XSSClassifier from {MODEL_DIR}: {e}")

# Default paths
DEFAULT_CHECKPOINT = "model/checkpoints/best.pt"
DEFAULT_TOKENIZER = "model/tokenizer"   # directory with tokenizer files (or HF name)
DEFAULT_MAX_LENGTH = 128

# Labels (copied from ai/training/config.py)
CONTEXT_LABELS = [
    "script_injection",
    "event_handler",
    "js_uri",
    "tag_injection",
    "template_injection",
    "dom_sink",
    "attribute_escape",
    "generic",
]
SEVERITY_LABELS = ["low", "medium", "high"]

def save_json(obj, path: str):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)

def softmax_np(logits: np.ndarray):
    e = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
    return e / e.sum(axis=-1, keepdims=True)

def load_checkpoint(checkpoint_path: str, map_location="cpu", device: torch.device = torch.device("cpu")) -> nn.Module:
    """
    Load the saved checkpoint and return a ready model (on device).
    Supports checkpoints with 'model_state_dict' key or raw state_dict.
    """
    ck = torch.load(checkpoint_path, map_location=map_location)
    # Extract state_dict
    state_dict = None
    if isinstance(ck, dict):
        state_dict = ck.get("model_state_dict", ck.get("state_dict", None))
        # If still None, maybe the dict *is* the state dict
        if state_dict is None and any(k.startswith("backbone.") or k.startswith("context_head") or k.startswith("severity_head") for k in ck.keys()):
            state_dict = ck
    else:
        # ck is likely a state_dict
        state_dict = ck

    if state_dict is None:
        raise RuntimeError(f"Could not find a state_dict inside checkpoint: {checkpoint_path}")

    # strip module. prefix if present (DDP)
    new_sd = {}
    for k, v in state_dict.items():
        nk = k.replace("module.", "") if k.startswith("module.") else k
        new_sd[nk] = v

    # Instantiate XSSClassifier with the correct head sizes
    model = XSSClassifier(num_contexts=len(CONTEXT_LABELS), num_severities=len(SEVERITY_LABELS))
    # load state dict (non-strict to allow slight mismatch if any)
    model.load_state_dict(new_sd, strict=False)
    model.to(device)
    model.eval()
    return model

def predict_batch(model: nn.Module, tokenizer, texts: List[str], max_length: int, device: torch.device):
    """
    Tokenize and run the model on a list of texts. Returns numpy logits for both heads.
    tokenizer: a transformers AutoTokenizer or equivalent with __call__.
    """
    enc = tokenizer(texts, padding=True, truncation=True, max_length=max_length, return_tensors="pt")
    input_ids = enc["input_ids"].to(device)
    attention_mask = enc["attention_mask"].to(device)
    model.to(device)
    model.eval()
    with torch.no_grad():
        ctx_logits, sev_logits = model(input_ids, attention_mask)
        ctx_logits = ctx_logits.cpu().numpy()
        sev_logits = sev_logits.cpu().numpy()
    return ctx_logits, sev_logits

# --- Backwards-compatible shims for older export scripts ---------------------
# Many older scripts expect a class named MultiHeadModel; alias it to XSSClassifier
# and expect a load_checkpoint() call that either returns a new model (path-only)
# or loads a checkpoint into a provided model (legacy signature).
from pathlib import Path as _Path

MultiHeadModel = XSSClassifier

def _extract_state_dict(ck):
    if isinstance(ck, dict):
        sd = ck.get("model_state_dict", ck.get("state_dict", None))
        if sd is None and any(k.startswith("backbone.") or k.startswith("context_head") or k.startswith("severity_head") for k in ck.keys()):
            sd = ck
        return sd
    else:
        return ck

def load_checkpoint(checkpoint_or_model, *args, map_location="cpu", device: torch.device = torch.device("cpu"), **kwargs):
    """
    Backwards-compatible loader.

    Usage patterns supported:
    - load_checkpoint(checkpoint_path: str, map_location=..., device=...) -> returns a new model
    - load_checkpoint(model: nn.Module, ckpt_path: str, map_location=..., device=...) -> loads state into provided model and returns it
    """
    # If first arg is a path -> return a new model (modern usage)
    if isinstance(checkpoint_or_model, (str, _Path)):
        ck = torch.load(str(checkpoint_or_model), map_location=map_location)
        state_dict = _extract_state_dict(ck)
        if state_dict is None:
            raise RuntimeError(f"Could not find a state_dict inside checkpoint: {checkpoint_or_model}")
        new_sd = { (k.replace("module.", "") if k.startswith("module.") else k): v for k, v in state_dict.items() }
        model = XSSClassifier(num_contexts=len(CONTEXT_LABELS), num_severities=len(SEVERITY_LABELS))
        model.load_state_dict(new_sd, strict=False)
        model.to(device)
        model.eval()
        return model

    # If first arg is a model instance -> legacy usage: load into provided model
    elif isinstance(checkpoint_or_model, nn.Module):
        model = checkpoint_or_model
        # ckpt path should be the second positional arg or provided as keyword
        ckpt_path = args[0] if args else kwargs.get("ckpt_path") or kwargs.get("checkpoint_path") or kwargs.get("path")
        if not ckpt_path:
            raise RuntimeError("When calling load_checkpoint(model, ckpt_path) you must provide ckpt_path")
        ck = torch.load(str(ckpt_path), map_location=map_location)
        state_dict = _extract_state_dict(ck)
        if state_dict is None:
            raise RuntimeError(f"Could not find a state_dict inside checkpoint: {ckpt_path}")
        new_sd = { (k.replace("module.", "") if k.startswith("module.") else k): v for k, v in state_dict.items() }
        model.load_state_dict(new_sd, strict=False)
        model.to(device)
        model.eval()
        return model

    else:
        raise TypeError("Unsupported arguments for load_checkpoint(), expected path or nn.Module followed by ckpt path.")
# ---------------------------------------------------------------------------
