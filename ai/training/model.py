# ai/training/model.py
"""
RedSentinel AI — Model Builder
Imports XSSClassifier from model/xss_classifier.py and prepares for training.
"""

import sys
from pathlib import Path

import torch

from config import (
    DEVICE, CONTEXT_CLASSES, SEVERITY_CLASSES, DROPOUT, MODEL_DIR
)

# Add model/ directory to Python path so we can import xss_classifier
sys.path.insert(0, str(MODEL_DIR))
from xss_classifier import XSSClassifier


def build_model() -> XSSClassifier:
    """Build the XSSClassifier and move to device."""

    print("\n🧠 Building model...")
    model = XSSClassifier(
        num_contexts=CONTEXT_CLASSES,
        num_severities=SEVERITY_CLASSES,
        dropout=DROPOUT,
    )

    model = model.to(DEVICE)
    model.count_params()
    print(f"  Device: {DEVICE}")

    # Print freeze status
    frozen = sum(1 for p in model.parameters() if not p.requires_grad)
    total = sum(1 for p in model.parameters())
    print(f"  Frozen layers: {frozen}/{total} parameter groups")

    return model


def load_model_from_checkpoint(checkpoint_path: Path) -> XSSClassifier:
    """Load a trained model from checkpoint."""
    model = XSSClassifier(
        num_contexts=CONTEXT_CLASSES,
        num_severities=SEVERITY_CLASSES,
        dropout=DROPOUT,
    )

    checkpoint = torch.load(checkpoint_path, map_location=DEVICE, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    model = model.to(DEVICE)
    model.eval()

    print(f"✓ Model loaded from {checkpoint_path}")
    return model


# ─── Quick test ──────────────────────────────────────────
if __name__ == "__main__":
    model = build_model()

    # Dummy forward pass
    dummy_ids = torch.randint(0, 30522, (4, 128)).to(DEVICE)   # DistilBERT vocab size
    dummy_mask = torch.ones(4, 128, dtype=torch.long).to(DEVICE)

    ctx_logits, sev_logits = model(dummy_ids, dummy_mask)
    print(f"\n🔍 Test forward pass:")
    print(f"  Context logits:  {ctx_logits.shape}")    # (4, 8)
    print(f"  Severity logits: {sev_logits.shape}")    # (4, 3)
    print("  ✅ Model works!")