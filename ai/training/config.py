# ai/training/config.py
"""
RedSentinel AI — Training Configuration
Corrected to match actual project structure.
"""

import torch
from pathlib import Path

# ─── Paths (matching actual tree structure) ──────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent   # red-sentinel/
DATASET_DIR = PROJECT_ROOT / "dataset" / "splits"
MODEL_DIR = PROJECT_ROOT / "model"
CUSTOM_TOKENIZER_PATH = MODEL_DIR / "tokenizer" / "tokenizer.json"
CHECKPOINT_DIR = MODEL_DIR / "checkpoints"

# Create dirs
CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
(CHECKPOINT_DIR / "logs").mkdir(parents=True, exist_ok=True)

# ─── Dataset Splits (CSV files) ─────────────────────────
TRAIN_FILE = DATASET_DIR / "train.csv"
VAL_FILE = DATASET_DIR / "val.csv"
TEST_FILE = DATASET_DIR / "test.csv"

# ─── Tokenizer ──────────────────────────────────────────
# Using DistilBERT's tokenizer (matches pretrained backbone)
DISTILBERT_MODEL_NAME = "distilbert-base-uncased"
MAX_LENGTH = 128

# ─── Classification Labels (from your actual data) ──────
CONTEXT_LABELS = [
    "script_injection",    # 0
    "event_handler",       # 1
    "js_uri",              # 2
    "tag_injection",       # 3
    "template_injection",  # 4
    "dom_sink",            # 5
    "attribute_escape",    # 6
    "generic",             # 7
]

SEVERITY_LABELS = [
    "low",                 # 0
    "medium",              # 1
    "high",                # 2
]

CONTEXT_CLASSES = len(CONTEXT_LABELS)    # 8
SEVERITY_CLASSES = len(SEVERITY_LABELS)  # 3

# ─── Model Architecture ─────────────────────────────────
DROPOUT = 0.3
FREEZE_LAYERS = 2    # Freeze embeddings + first 2 transformer layers

# ─── Training Hyperparameters ────────────────────────────
EPOCHS = 15
BATCH_SIZE = 32
LEARNING_RATE = 2e-5
WEIGHT_DECAY = 0.01
WARMUP_RATIO = 0.1
MAX_GRAD_NORM = 1.0

# ─── Loss Weights ───────────────────────────────────────
CONTEXT_LOSS_WEIGHT = 0.7
SEVERITY_LOSS_WEIGHT = 0.3
LABEL_SMOOTHING = 0.1

# ─── Early Stopping ─────────────────────────────────────
PATIENCE = 5

# ─── Device ──────────────────────────────────────────────
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# ─── Logging ─────────────────────────────────────────────
LOG_EVERY_N_STEPS = 50
SAVE_EVERY_N_EPOCHS = 1


# ─── Print config on import ──────────────────────────────
def print_config():
    print("\n⚙️  Configuration:")
    print(f"  Project root:  {PROJECT_ROOT}")
    print(f"  Train file:    {TRAIN_FILE} (exists: {TRAIN_FILE.exists()})")
    print(f"  Val file:      {VAL_FILE} (exists: {VAL_FILE.exists()})")
    print(f"  Test file:     {TEST_FILE} (exists: {TEST_FILE.exists()})")
    print(f"  Checkpoint dir: {CHECKPOINT_DIR}")
    print(f"  Backbone:      {DISTILBERT_MODEL_NAME}")
    print(f"  Device:        {DEVICE}")
    print(f"  Context labels: {CONTEXT_LABELS}")
    print(f"  Severity labels: {SEVERITY_LABELS}")


if __name__ == "__main__":
    print_config()