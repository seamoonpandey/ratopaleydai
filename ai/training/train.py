# ai/training/train.py
"""
RedSentinel AI — Training Loop
Dual-head XSS classifier training with validation, checkpointing, early stopping.

Usage:
    python train.py
    python train.py --epochs 20 --lr 3e-5 --batch_size 64
    python train.py --resume
"""

import argparse
import json
import time
import math
import logging
from pathlib import Path
from datetime import datetime

import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.optim.lr_scheduler import LambdaLR
from torch.cuda.amp import GradScaler, autocast

from config import (
    DEVICE, EPOCHS, BATCH_SIZE, LEARNING_RATE, WEIGHT_DECAY,
    WARMUP_RATIO, MAX_GRAD_NORM, PATIENCE,
    CONTEXT_LOSS_WEIGHT, SEVERITY_LOSS_WEIGHT, LABEL_SMOOTHING,
    CONTEXT_CLASSES, SEVERITY_CLASSES,
    CONTEXT_LABELS, SEVERITY_LABELS,
    CHECKPOINT_DIR, LOG_EVERY_N_STEPS, SAVE_EVERY_N_EPOCHS,
)
from dataset import get_dataloaders
from model import build_model


# ═════════════════════════════════════════════════════════════
#                        UTILITIES
# ═════════════════════════════════════════════════════════════

def setup_logging() -> logging.Logger:
    """Configure dual logging: file + stdout."""
    log_dir = CHECKPOINT_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"train_{timestamp}.log"

    logger = logging.getLogger("redsentinel")
    logger.setLevel(logging.INFO)

    # Clear any existing handlers (prevents duplicate logs on re-runs)
    logger.handlers.clear()

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter("%(asctime)s | %(message)s", datefmt="%H:%M:%S"))

    # Stdout handler
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(fh)
    logger.addHandler(sh)

    logger.info(f"📝 Logging to {log_file}")
    return logger


def get_scheduler(optimizer, num_warmup_steps: int, num_training_steps: int) -> LambdaLR:
    """Linear warmup → cosine decay."""

    def lr_lambda(current_step: int) -> float:
        if current_step < num_warmup_steps:
            return float(current_step) / float(max(1, num_warmup_steps))
        progress = float(current_step - num_warmup_steps) / float(
            max(1, num_training_steps - num_warmup_steps)
        )
        return max(0.0, 0.5 * (1.0 + math.cos(math.pi * progress)))

    return LambdaLR(optimizer, lr_lambda)


class MetricsTracker:
    """Track all training metrics across epochs."""

    def __init__(self):
        self.history = {
            "train_loss": [],
            "val_loss": [],
            "train_context_acc": [],
            "train_severity_acc": [],
            "val_context_acc": [],
            "val_severity_acc": [],
            "learning_rate": [],
            "epoch_time": [],
        }

    def record(self, metrics: dict):
        for key, value in metrics.items():
            if key in self.history:
                self.history[key].append(value)

    def save(self, path: Path):
        with open(path, "w") as f:
            json.dump(self.history, f, indent=2)

    def best_val_loss(self) -> float:
        if not self.history["val_loss"]:
            return float("inf")
        return min(self.history["val_loss"])


# ═════════════════════════════════════════════════════════════
#                     CHECKPOINTING
# ═════════════════════════════════════════════════════════════

def save_checkpoint(model, optimizer, scheduler, scaler, epoch, val_loss, path):
    """Save full training state."""
    torch.save({
        "epoch": epoch,
        "model_state_dict": model.state_dict(),
        "optimizer_state_dict": optimizer.state_dict(),
        "scheduler_state_dict": scheduler.state_dict(),
        "scaler_state_dict": scaler.state_dict(),
        "val_loss": val_loss,
    }, path)


def load_checkpoint(path, model, optimizer, scheduler, scaler):
    """Restore training state. Returns (epoch, val_loss)."""
    ckpt = torch.load(path, map_location=DEVICE, weights_only=False)
    model.load_state_dict(ckpt["model_state_dict"])
    optimizer.load_state_dict(ckpt["optimizer_state_dict"])
    scheduler.load_state_dict(ckpt["scheduler_state_dict"])
    scaler.load_state_dict(ckpt["scaler_state_dict"])
    return ckpt["epoch"], ckpt["val_loss"]


# ═════════════════════════════════════════════════════════════
#                    TRAIN ONE EPOCH
# ═════════════════════════════════════════════════════════════

def train_one_epoch(
    model, loader, optimizer, scheduler, scaler,
    context_criterion, severity_criterion,
    epoch, logger
) -> dict:
    """Train for one full epoch."""

    model.train()

    total_loss = 0.0
    ctx_correct = 0
    sev_correct = 0
    total_samples = 0
    num_batches = len(loader)

    epoch_start = time.time()

    for step, batch in enumerate(loader):
        # Move to device
        input_ids = batch["input_ids"].to(DEVICE)
        attention_mask = batch["attention_mask"].to(DEVICE)
        ctx_labels = batch["context_label"].to(DEVICE)
        sev_labels = batch["severity_label"].to(DEVICE)

        optimizer.zero_grad()

        # Forward (model returns tuple: ctx_logits, sev_logits)
        with autocast(enabled=(DEVICE == "cuda")):
            ctx_logits, sev_logits = model(input_ids, attention_mask)

            # Dual weighted loss
            ctx_loss = context_criterion(ctx_logits, ctx_labels)
            sev_loss = severity_criterion(sev_logits, sev_labels)
            loss = (CONTEXT_LOSS_WEIGHT * ctx_loss) + (SEVERITY_LOSS_WEIGHT * sev_loss)

        # Backward
        if DEVICE == "cuda":
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            nn.utils.clip_grad_norm_(model.parameters(), MAX_GRAD_NORM)
            scaler.step(optimizer)
            scaler.update()
        else:
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), MAX_GRAD_NORM)
            optimizer.step()

        scheduler.step()

        # Track metrics
        bs = input_ids.size(0)
        total_loss += loss.item() * bs
        total_samples += bs
        ctx_correct += (ctx_logits.argmax(dim=-1) == ctx_labels).sum().item()
        sev_correct += (sev_logits.argmax(dim=-1) == sev_labels).sum().item()

        # Log every N steps
        if (step + 1) % LOG_EVERY_N_STEPS == 0:
            avg_loss = total_loss / total_samples
            ca = ctx_correct / total_samples * 100
            sa = sev_correct / total_samples * 100
            lr = scheduler.get_last_lr()[0]

            logger.info(
                f"  Step [{step+1:>4}/{num_batches}] — "
                f"Loss: {avg_loss:.4f} | "
                f"Ctx: {ca:.1f}% | "
                f"Sev: {sa:.1f}% | "
                f"LR: {lr:.2e}"
            )

    epoch_time = time.time() - epoch_start

    return {
        "train_loss": total_loss / total_samples,
        "train_context_acc": ctx_correct / total_samples * 100,
        "train_severity_acc": sev_correct / total_samples * 100,
        "epoch_time": epoch_time,
        "learning_rate": scheduler.get_last_lr()[0],
    }


# ═════════════════════════════════════════════════════════════
#                      VALIDATION
# ═════════════════════════════════════════════════════════════

@torch.no_grad()
def validate(model, loader, context_criterion, severity_criterion, logger) -> dict:
    """Run validation with per-class breakdown."""

    model.eval()

    total_loss = 0.0
    ctx_correct = 0
    sev_correct = 0
    total_samples = 0

    # Per-class tracking
    class_correct = [0] * CONTEXT_CLASSES
    class_total = [0] * CONTEXT_CLASSES

    for batch in loader:
        input_ids = batch["input_ids"].to(DEVICE)
        attention_mask = batch["attention_mask"].to(DEVICE)
        ctx_labels = batch["context_label"].to(DEVICE)
        sev_labels = batch["severity_label"].to(DEVICE)

        with autocast(enabled=(DEVICE == "cuda")):
            ctx_logits, sev_logits = model(input_ids, attention_mask)

            ctx_loss = context_criterion(ctx_logits, ctx_labels)
            sev_loss = severity_criterion(sev_logits, sev_labels)
            loss = (CONTEXT_LOSS_WEIGHT * ctx_loss) + (SEVERITY_LOSS_WEIGHT * sev_loss)

        bs = input_ids.size(0)
        total_loss += loss.item() * bs
        total_samples += bs

        ctx_preds = ctx_logits.argmax(dim=-1)
        sev_preds = sev_logits.argmax(dim=-1)
        ctx_correct += (ctx_preds == ctx_labels).sum().item()
        sev_correct += (sev_preds == sev_labels).sum().item()

        # Per-class
        for i in range(bs):
            label = ctx_labels[i].item()
            pred = ctx_preds[i].item()
            class_total[label] += 1
            if pred == label:
                class_correct[label] += 1

    avg_loss = total_loss / total_samples
    ctx_acc = ctx_correct / total_samples * 100
    sev_acc = sev_correct / total_samples * 100

    # Per-class breakdown
    logger.info("")
    logger.info("  ┌────────────────────────┬──────────┬────────────┐")
    logger.info("  │ Context Class           │ Samples  │ Accuracy   │")
    logger.info("  ├────────────────────────┼──────────┼────────────┤")
    for i, label in enumerate(CONTEXT_LABELS):
        if class_total[i] > 0:
            acc = class_correct[i] / class_total[i] * 100
            logger.info(f"  │ {label:<22} │ {class_total[i]:>6}   │ {acc:>8.1f}%  │")
        else:
            logger.info(f"  │ {label:<22} │ {0:>6}   │      N/A   │")
    logger.info("  └────────────────────────┴──────────┴────────────┘")

    return {
        "val_loss": avg_loss,
        "val_context_acc": ctx_acc,
        "val_severity_acc": sev_acc,
    }


# ═════════════════════════════════════════════════════════════
#                         MAIN
# ═════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="RedSentinel AI — Train XSS Classifier")
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--batch_size", type=int, default=BATCH_SIZE)
    parser.add_argument("--lr", type=float, default=LEARNING_RATE)
    parser.add_argument("--patience", type=int, default=PATIENCE)
    parser.add_argument("--resume", action="store_true", help="Resume from latest.pt")
    args = parser.parse_args()

    # ── Setup ──
    logger = setup_logging()

    logger.info("")
    logger.info("=" * 60)
    logger.info("  🔴 RedSentinel AI — Training Pipeline")
    logger.info("=" * 60)
    logger.info(f"  Device:       {DEVICE}")
    logger.info(f"  Epochs:       {args.epochs}")
    logger.info(f"  Batch size:   {args.batch_size}")
    logger.info(f"  LR:           {args.lr}")
    logger.info(f"  Patience:     {args.patience}")
    logger.info(f"  Label smooth: {LABEL_SMOOTHING}")
    logger.info(f"  Loss weights: ctx={CONTEXT_LOSS_WEIGHT}, sev={SEVERITY_LOSS_WEIGHT}")

    # ── Data ──
    train_loader, val_loader, _ = get_dataloaders(args.batch_size)

    # ── Model ──
    model = build_model()

    # ── Optimizer ──
    # Only optimize trainable params (some layers are frozen)
    trainable_params = [p for p in model.parameters() if p.requires_grad]
    optimizer = AdamW(
        trainable_params,
        lr=args.lr,
        weight_decay=WEIGHT_DECAY,
        betas=(0.9, 0.999),
        eps=1e-8,
    )

    # ── Scheduler ──
    total_steps = len(train_loader) * args.epochs
    warmup_steps = int(total_steps * WARMUP_RATIO)
    scheduler = get_scheduler(optimizer, warmup_steps, total_steps)
    logger.info(f"\n  📊 Steps: {total_steps} total, {warmup_steps} warmup")

    # ── Loss ──
    ctx_criterion = nn.CrossEntropyLoss(label_smoothing=LABEL_SMOOTHING)
    sev_criterion = nn.CrossEntropyLoss(label_smoothing=LABEL_SMOOTHING)

    # ── AMP Scaler ──
    scaler = GradScaler()

    # ── Metrics ──
    metrics = MetricsTracker()

    # ── Resume ──
    start_epoch = 0
    best_val_loss = float("inf")

    if args.resume:
        latest = CHECKPOINT_DIR / "latest.pt"
        if latest.exists():
            start_epoch, best_val_loss = load_checkpoint(latest, model, optimizer, scheduler, scaler)
            start_epoch += 1
            logger.info(f"\n  ⏩ Resumed from epoch {start_epoch}, best val loss: {best_val_loss:.4f}")
        else:
            logger.info("\n  ⚠ No checkpoint found — starting fresh")

    # ── Early Stopping ──
    patience_counter = 0

    # ══════════════════════════════════════════════════════
    #                  TRAINING LOOP
    # ══════════════════════════════════════════════════════

    logger.info("\n" + "=" * 60)
    logger.info("  🚀 Starting Training")
    logger.info("=" * 60)

    total_start = time.time()

    for epoch in range(start_epoch, args.epochs):
        logger.info(f"\n{'─' * 60}")
        logger.info(f"  📌 Epoch {epoch + 1}/{args.epochs}")
        logger.info(f"{'─' * 60}")

        # ── Train ──
        logger.info("\n  📈 Training...")
        train_metrics = train_one_epoch(
            model, train_loader, optimizer, scheduler, scaler,
            ctx_criterion, sev_criterion, epoch, logger
        )
        logger.info(
            f"\n  Train → Loss: {train_metrics['train_loss']:.4f} | "
            f"Ctx: {train_metrics['train_context_acc']:.1f}% | "
            f"Sev: {train_metrics['train_severity_acc']:.1f}% | "
            f"Time: {train_metrics['epoch_time']:.1f}s"
        )

        # ── Validate ──
        logger.info("\n  📊 Validating...")
        val_metrics = validate(model, val_loader, ctx_criterion, sev_criterion, logger)
        logger.info(
            f"\n  Val   → Loss: {val_metrics['val_loss']:.4f} | "
            f"Ctx: {val_metrics['val_context_acc']:.1f}% | "
            f"Sev: {val_metrics['val_severity_acc']:.1f}%"
        )

        # ── Record ──
        all_metrics = {**train_metrics, **val_metrics}
        metrics.record(all_metrics)
        metrics.save(CHECKPOINT_DIR / "metrics.json")

        # ── Save latest ──
        save_checkpoint(
            model, optimizer, scheduler, scaler,
            epoch, val_metrics["val_loss"],
            CHECKPOINT_DIR / "latest.pt"
        )

        # ── Save periodic ──
        if (epoch + 1) % SAVE_EVERY_N_EPOCHS == 0:
            save_checkpoint(
                model, optimizer, scheduler, scaler,
                epoch, val_metrics["val_loss"],
                CHECKPOINT_DIR / f"epoch_{epoch + 1}.pt"
            )

        # ── Best model? ──
        if val_metrics["val_loss"] < best_val_loss:
            improvement = best_val_loss - val_metrics["val_loss"]
            best_val_loss = val_metrics["val_loss"]
            patience_counter = 0

            save_checkpoint(
                model, optimizer, scheduler, scaler,
                epoch, val_metrics["val_loss"],
                CHECKPOINT_DIR / "best.pt"
            )
            logger.info(f"\n  ✅ New best! Val loss improved by {improvement:.4f}")
            logger.info(f"     Saved → {CHECKPOINT_DIR / 'best.pt'}")
        else:
            patience_counter += 1
            logger.info(f"\n  ⏳ No improvement. Patience: {patience_counter}/{args.patience}")

        # ── Early stop? ──
        if patience_counter >= args.patience:
            logger.info(f"\n  🛑 Early stopping at epoch {epoch + 1}")
            break

    # ══════════════════════════════════════════════════════
    #                    DONE
    # ══════════════════════════════════════════════════════

    total_time = time.time() - total_start

    logger.info("\n" + "=" * 60)
    logger.info("  🏁 Training Complete!")
    logger.info("=" * 60)
    logger.info(f"  Total time:       {total_time / 60:.1f} minutes")
    logger.info(f"  Best val loss:    {best_val_loss:.4f}")

    if metrics.history["val_context_acc"]:
        logger.info(f"  Best context acc: {max(metrics.history['val_context_acc']):.1f}%")
    if metrics.history["val_severity_acc"]:
        logger.info(f"  Best severity acc: {max(metrics.history['val_severity_acc']):.1f}%")

    logger.info(f"  Checkpoints:      {CHECKPOINT_DIR}")
    logger.info(f"  Metrics:          {CHECKPOINT_DIR / 'metrics.json'}")

    # ── Summary table ──
    logger.info("\n  Epoch Summary:")
    logger.info("  ┌───────┬────────────┬────────────┬──────────┬──────────┐")
    logger.info("  │ Epoch │ Train Loss │  Val Loss  │ Ctx Acc  │ Sev Acc  │")
    logger.info("  ├───────┼────────────┼────────────┼──────────┼──────────┤")

    for i in range(len(metrics.history["train_loss"])):
        tl = metrics.history["train_loss"][i]
        vl = metrics.history["val_loss"][i]
        ca = metrics.history["val_context_acc"][i]
        sa = metrics.history["val_severity_acc"][i]
        best = " ◀" if vl == best_val_loss else ""
        logger.info(
            f"  │  {i+1:>3}  │  {tl:.4f}   │  {vl:.4f}   │ {ca:>5.1f}%  │ {sa:>5.1f}%  │{best}"
        )

    logger.info("  └───────┴────────────┴────────────┴──────────┴──────────┘")
    logger.info("")


if __name__ == "__main__":
    main()