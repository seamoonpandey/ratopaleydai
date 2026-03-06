# ai/training/evaluate.py
"""
RedSentinel AI — Model Evaluation
Tests best.pt on the held-out test set.
Produces confusion matrix, per-class F1, and confidence analysis.

Usage:
    python evaluate.py
    python evaluate.py --checkpoint /path/to/best.pt
"""

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict

import torch
import numpy as np
from torch.cuda.amp import autocast
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from config import (
    DEVICE, CHECKPOINT_DIR,
    CONTEXT_LABELS, SEVERITY_LABELS,
    CONTEXT_CLASSES, SEVERITY_CLASSES,
    MODEL_DIR, BATCH_SIZE,
)
from dataset import get_dataloaders
from model import build_model


def print_confusion_matrix(cm, labels, title="Confusion Matrix"):
    """Pretty-print a confusion matrix."""
    print(f"\n  {title}")
    
    # Header
    max_label = max(len(l) for l in labels)
    header = " " * (max_label + 4)
    for l in labels:
        header += f"{l[:6]:>7}"
    print(f"  {header}")
    print(f"  {' ' * (max_label + 3)}{'─' * (7 * len(labels) + 1)}")
    
    # Rows
    for i, label in enumerate(labels):
        row = f"  {label:>{max_label}} │"
        for j in range(len(labels)):
            val = cm[i][j]
            if i == j:
                row += f"  \033[92m{val:>4}\033[0m "  # Green for diagonal
            elif val > 0:
                row += f"  \033[91m{val:>4}\033[0m "  # Red for errors
            else:
                row += f"  {val:>4} "
            
        # Row accuracy
        row_total = sum(cm[i])
        row_acc = cm[i][i] / row_total * 100 if row_total > 0 else 0
        row += f" │ {row_acc:.1f}%"
        print(row)
    
    print(f"  {' ' * (max_label + 3)}{'─' * (7 * len(labels) + 1)}")


def evaluate_model(model, test_loader, logger_print=print):
    """Run full evaluation on test set."""
    
    model.eval()
    
    all_ctx_preds = []
    all_ctx_labels = []
    all_sev_preds = []
    all_sev_labels = []
    all_ctx_confs = []
    all_sev_confs = []
    
    total_samples = 0
    
    logger_print("\n  🔍 Running inference on test set...")
    
    with torch.no_grad():
        for batch_idx, batch in enumerate(test_loader):
            input_ids = batch["input_ids"].to(DEVICE)
            attention_mask = batch["attention_mask"].to(DEVICE)
            ctx_labels = batch["context_label"].to(DEVICE)
            sev_labels = batch["severity_label"].to(DEVICE)
            
            with autocast(enabled=(DEVICE == "cuda")):
                ctx_logits, sev_logits = model(input_ids, attention_mask)
            
            # Predictions
            ctx_probs = torch.softmax(ctx_logits, dim=-1)
            sev_probs = torch.softmax(sev_logits, dim=-1)
            
            ctx_preds = ctx_logits.argmax(dim=-1)
            sev_preds = sev_logits.argmax(dim=-1)
            
            ctx_confs = ctx_probs.max(dim=-1).values
            sev_confs = sev_probs.max(dim=-1).values
            
            # Collect
            all_ctx_preds.extend(ctx_preds.cpu().numpy())
            all_ctx_labels.extend(ctx_labels.cpu().numpy())
            all_sev_preds.extend(sev_preds.cpu().numpy())
            all_sev_labels.extend(sev_labels.cpu().numpy())
            all_ctx_confs.extend(ctx_confs.cpu().numpy())
            all_sev_confs.extend(sev_confs.cpu().numpy())
            
            total_samples += input_ids.size(0)
    
    # Convert to numpy
    ctx_preds = np.array(all_ctx_preds)
    ctx_labels = np.array(all_ctx_labels)
    sev_preds = np.array(all_sev_preds)
    sev_labels = np.array(all_sev_labels)
    ctx_confs = np.array(all_ctx_confs)
    sev_confs = np.array(all_sev_confs)
    
    logger_print(f"  ✓ Evaluated {total_samples} samples")
    
    # ═══════════════════════════════════════════════════════
    #              OVERALL ACCURACY
    # ═══════════════════════════════════════════════════════
    
    ctx_acc = (ctx_preds == ctx_labels).mean() * 100
    sev_acc = (sev_preds == sev_labels).mean() * 100
    
    ctx_errors = (ctx_preds != ctx_labels).sum()
    sev_errors = (sev_preds != sev_labels).sum()
    
    logger_print("\n" + "=" * 60)
    logger_print("  📊 TEST SET RESULTS")
    logger_print("=" * 60)
    
    logger_print(f"\n  Overall Accuracy:")
    logger_print(f"  ┌──────────────────┬───────────┬──────────┐")
    logger_print(f"  │ Task             │ Accuracy  │ Errors   │")
    logger_print(f"  ├──────────────────┼───────────┼──────────┤")
    logger_print(f"  │ Context (8-cls)  │  {ctx_acc:>5.1f}%   │  {ctx_errors:>4}    │")
    logger_print(f"  │ Severity (3-cls) │  {sev_acc:>5.1f}%   │  {sev_errors:>4}    │")
    logger_print(f"  └──────────────────┴───────────┴──────────┘")
    
    # ═══════════════════════════════════════════════════════
    #            CONTEXT CLASSIFICATION REPORT
    # ═══════════════════════════════════════════════════════
    
    logger_print("\n  📋 Context Classification Report:")
    logger_print("  " + "─" * 56)
    
    ctx_report = classification_report(
        ctx_labels, ctx_preds,
        target_names=CONTEXT_LABELS,
        digits=4,
        zero_division=0,
    )
    for line in ctx_report.split("\n"):
        logger_print(f"  {line}")
    
    # ═══════════════════════════════════════════════════════
    #            SEVERITY CLASSIFICATION REPORT
    # ═══════════════════════════════════════════════════════
    
    logger_print("\n  📋 Severity Classification Report:")
    logger_print("  " + "─" * 56)
    
    sev_report = classification_report(
        sev_labels, sev_preds,
        target_names=SEVERITY_LABELS,
        digits=4,
        zero_division=0,
    )
    for line in sev_report.split("\n"):
        logger_print(f"  {line}")
    
    # ═══════════════════════════════════════════════════════
    #              CONFUSION MATRICES
    # ═══════════════════════════════════════════════════════
    
    ctx_cm = confusion_matrix(ctx_labels, ctx_preds)
    sev_cm = confusion_matrix(sev_labels, sev_preds)
    
    print_confusion_matrix(ctx_cm, CONTEXT_LABELS, "Context Confusion Matrix")
    print_confusion_matrix(sev_cm, SEVERITY_LABELS, "Severity Confusion Matrix")
    
    # ═══════════════════════════════════════════════════════
    #             CONFIDENCE ANALYSIS
    # ═══════════════════════════════════════════════════════
    
    logger_print("\n  🎯 Confidence Analysis:")
    logger_print(f"  ┌──────────────────┬──────────┬──────────┬──────────┐")
    logger_print(f"  │ Task             │   Mean   │   Min    │  Median  │")
    logger_print(f"  ├──────────────────┼──────────┼──────────┼──────────┤")
    logger_print(f"  │ Context          │  {ctx_confs.mean():.4f}  │  {ctx_confs.min():.4f}  │  {np.median(ctx_confs):.4f}  │")
    logger_print(f"  │ Severity         │  {sev_confs.mean():.4f}  │  {sev_confs.min():.4f}  │  {np.median(sev_confs):.4f}  │")
    logger_print(f"  └──────────────────┴──────────┴──────────┴──────────┘")
    
    # Confidence buckets
    logger_print("\n  Confidence Distribution (Context):")
    for threshold in [0.99, 0.95, 0.90, 0.80, 0.50]:
        count = (ctx_confs >= threshold).sum()
        pct = count / len(ctx_confs) * 100
        bar = "█" * int(pct / 2)
        logger_print(f"  ≥{threshold:.2f}: {count:>5}/{len(ctx_confs)} ({pct:>5.1f}%) {bar}")
    
    # ═══════════════════════════════════════════════════════
    #             ERROR ANALYSIS
    # ═══════════════════════════════════════════════════════
    
    logger_print("\n  ❌ Misclassification Breakdown (Context):")
    ctx_errors_detail = defaultdict(int)
    for i in range(len(ctx_preds)):
        if ctx_preds[i] != ctx_labels[i]:
            true_label = CONTEXT_LABELS[ctx_labels[i]]
            pred_label = CONTEXT_LABELS[ctx_preds[i]]
            ctx_errors_detail[f"{true_label} → {pred_label}"] += 1
    
    if ctx_errors_detail:
        sorted_errors = sorted(ctx_errors_detail.items(), key=lambda x: -x[1])
        for error_type, count in sorted_errors[:10]:
            logger_print(f"    {error_type}: {count}")
    else:
        logger_print("    None! Perfect classification.")
    
    logger_print("\n  ❌ Misclassification Breakdown (Severity):")
    sev_errors_detail = defaultdict(int)
    for i in range(len(sev_preds)):
        if sev_preds[i] != sev_labels[i]:
            true_label = SEVERITY_LABELS[sev_labels[i]]
            pred_label = SEVERITY_LABELS[sev_preds[i]]
            sev_errors_detail[f"{true_label} → {pred_label}"] += 1
    
    if sev_errors_detail:
        sorted_errors = sorted(sev_errors_detail.items(), key=lambda x: -x[1])
        for error_type, count in sorted_errors[:10]:
            logger_print(f"    {error_type}: {count}")
    else:
        logger_print("    None! Perfect classification.")
    
    # ═══════════════════════════════════════════════════════
    #              WEIGHTED F1 SCORES
    # ═══════════════════════════════════════════════════════
    
    ctx_f1_weighted = f1_score(ctx_labels, ctx_preds, average="weighted", zero_division=0)
    ctx_f1_macro = f1_score(ctx_labels, ctx_preds, average="macro", zero_division=0)
    sev_f1_weighted = f1_score(sev_labels, sev_preds, average="weighted", zero_division=0)
    sev_f1_macro = f1_score(sev_labels, sev_preds, average="macro", zero_division=0)
    
    logger_print("\n  🏆 Final Scores:")
    logger_print(f"  ┌──────────────────┬──────────────┬──────────────┐")
    logger_print(f"  │ Metric           │   Context    │   Severity   │")
    logger_print(f"  ├──────────────────┼──────────────┼──────────────┤")
    logger_print(f"  │ Accuracy         │   {ctx_acc:>6.2f}%    │   {sev_acc:>6.2f}%    │")
    logger_print(f"  │ F1 (weighted)    │   {ctx_f1_weighted:>6.4f}     │   {sev_f1_weighted:>6.4f}     │")
    logger_print(f"  │ F1 (macro)       │   {ctx_f1_macro:>6.4f}     │   {sev_f1_macro:>6.4f}     │")
    logger_print(f"  └──────────────────┴──────────────┴──────────────┘")
    
    # ═══════════════════════════════════════════════════════
    #              SAVE RESULTS
    # ═══════════════════════════════════════════════════════
    
    results = {
        "test_samples": total_samples,
        "context_accuracy": round(ctx_acc, 4),
        "severity_accuracy": round(sev_acc, 4),
        "context_f1_weighted": round(ctx_f1_weighted, 4),
        "context_f1_macro": round(ctx_f1_macro, 4),
        "severity_f1_weighted": round(sev_f1_weighted, 4),
        "severity_f1_macro": round(sev_f1_macro, 4),
        "context_errors": int(ctx_errors),
        "severity_errors": int(sev_errors),
        "avg_context_confidence": round(float(ctx_confs.mean()), 4),
        "avg_severity_confidence": round(float(sev_confs.mean()), 4),
        "context_confusion_matrix": ctx_cm.tolist(),
        "severity_confusion_matrix": sev_cm.tolist(),
        "context_error_breakdown": dict(ctx_errors_detail),
        "severity_error_breakdown": dict(sev_errors_detail),
    }
    
    results_path = CHECKPOINT_DIR / "test_results.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    
    logger_print(f"\n  💾 Results saved → {results_path}")
    
    return results


# ═════════════════════════════════════════════════════════════
#                         MAIN
# ═════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="RedSentinel AI — Evaluate")
    parser.add_argument(
        "--checkpoint",
        type=str,
        default=str(CHECKPOINT_DIR / "best.pt"),
        help="Path to model checkpoint",
    )
    parser.add_argument("--batch_size", type=int, default=BATCH_SIZE)
    args = parser.parse_args()
    
    checkpoint_path = Path(args.checkpoint)
    
    print("\n" + "=" * 60)
    print("  [logo.png] RedSentinel AI — Model Evaluation")
    print("=" * 60)
    print(f"  Checkpoint: {checkpoint_path}")
    print(f"  Device:     {DEVICE}")
    
    # Check checkpoint exists
    if not checkpoint_path.exists():
        print(f"\n  ❌ Checkpoint not found: {checkpoint_path}")
        print(f"  Available checkpoints:")
        for f in sorted(CHECKPOINT_DIR.glob("*.pt")):
            print(f"    → {f}")
        sys.exit(1)
    
    # Load data
    _, _, test_loader = get_dataloaders(args.batch_size)
    
    # Build model
    model = build_model()
    
    # Load weights
    print(f"\n  📦 Loading checkpoint: {checkpoint_path.name}")
    checkpoint = torch.load(checkpoint_path, map_location=DEVICE, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    print(f"  ✓ Loaded (trained epoch: {checkpoint.get('epoch', '?') + 1})")
    print(f"  ✓ Val loss at save: {checkpoint.get('val_loss', '?'):.4f}")
    
    # Run evaluation
    results = evaluate_model(model, test_loader)
    
    print("\n" + "=" * 60)
    print("  ✅ Evaluation Complete!")
    print("=" * 60)
    print("")


if __name__ == "__main__":
    main()