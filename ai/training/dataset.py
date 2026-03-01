# ai/training/dataset.py
"""
RedSentinel AI — Dataset & DataLoader
Loads CSV splits, tokenizes with DistilBERT tokenizer, returns PyTorch datasets.
"""

import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import DistilBertTokenizerFast
from pathlib import Path
from typing import Tuple

from config import (
    TRAIN_FILE, VAL_FILE, TEST_FILE,
    DISTILBERT_MODEL_NAME, MAX_LENGTH,
    CONTEXT_LABELS, SEVERITY_LABELS,
    BATCH_SIZE
)


class XSSDataset(Dataset):
    """PyTorch Dataset for XSS payload classification from CSV."""

    def __init__(self, csv_path: Path, tokenizer: DistilBertTokenizerFast):
        self.tokenizer = tokenizer

        # Build label mappings
        self.context_to_id = {label: i for i, label in enumerate(CONTEXT_LABELS)}
        self.severity_to_id = {label: i for i, label in enumerate(SEVERITY_LABELS)}

        # Load CSV
        df = pd.read_csv(csv_path)
        print(f"  📄 Raw rows in {csv_path.name}: {len(df)}")

        # Clean + validate
        self.samples = []
        skipped = 0

        for _, row in df.iterrows():
            payload = str(row.get("payload", "")).strip()
            context = str(row.get("context", "")).strip().lower()
            severity = str(row.get("severity", "")).strip().lower()

            # Skip if label not in our known set
            if context not in self.context_to_id:
                skipped += 1
                continue
            if severity not in self.severity_to_id:
                skipped += 1
                continue
            if not payload or payload == "nan":
                skipped += 1
                continue

            self.samples.append({
                "payload": payload,
                "context_id": self.context_to_id[context],
                "severity_id": self.severity_to_id[severity],
            })

        if skipped > 0:
            print(f"  ⚠  Skipped {skipped} rows with unknown/missing labels")
        print(f"  ✓  Loaded {len(self.samples)} valid samples from {csv_path.name}")

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict:
        sample = self.samples[idx]

        # Tokenize using DistilBERT tokenizer
        encoding = self.tokenizer(
            sample["payload"],
            max_length=MAX_LENGTH,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),           # (max_length,)
            "attention_mask": encoding["attention_mask"].squeeze(0),  # (max_length,)
            "context_label": torch.tensor(sample["context_id"], dtype=torch.long),
            "severity_label": torch.tensor(sample["severity_id"], dtype=torch.long),
        }


def get_dataloaders(batch_size: int = BATCH_SIZE) -> Tuple[DataLoader, DataLoader, DataLoader]:
    """Create train, val, test DataLoaders."""

    print("\n📦 Loading datasets...")

    # Load DistilBERT tokenizer (matches pretrained backbone)
    tokenizer = DistilBertTokenizerFast.from_pretrained(DISTILBERT_MODEL_NAME)
    print(f"  ✓ Tokenizer: {DISTILBERT_MODEL_NAME} (vocab: {tokenizer.vocab_size})")

    # Build datasets
    train_ds = XSSDataset(TRAIN_FILE, tokenizer)
    val_ds = XSSDataset(VAL_FILE, tokenizer)
    test_ds = XSSDataset(TEST_FILE, tokenizer)

    # Build dataloaders
    train_loader = DataLoader(
        train_ds,
        batch_size=batch_size,
        shuffle=True,
        num_workers=2,
        pin_memory=True,
        drop_last=True,
    )

    val_loader = DataLoader(
        val_ds,
        batch_size=batch_size,
        shuffle=False,
        num_workers=2,
        pin_memory=True,
    )

    test_loader = DataLoader(
        test_ds,
        batch_size=batch_size,
        shuffle=False,
        num_workers=2,
        pin_memory=True,
    )

    print(f"\n  📊 DataLoader Summary:")
    print(f"  Train: {len(train_ds):>6} samples → {len(train_loader)} batches")
    print(f"  Val:   {len(val_ds):>6} samples → {len(val_loader)} batches")
    print(f"  Test:  {len(test_ds):>6} samples → {len(test_loader)} batches")

    return train_loader, val_loader, test_loader


# ─── Quick test ──────────────────────────────────────────
if __name__ == "__main__":
    train_loader, val_loader, test_loader = get_dataloaders()

    # Grab one batch
    batch = next(iter(train_loader))
    print(f"\n🔍 Sample batch:")
    print(f"  input_ids shape:      {batch['input_ids'].shape}")       # (32, 128)
    print(f"  attention_mask shape: {batch['attention_mask'].shape}")   # (32, 128)
    print(f"  context_label shape:  {batch['context_label'].shape}")   # (32,)
    print(f"  severity_label shape: {batch['severity_label'].shape}")  # (32,)

    # Decode first sample back to text
    tokenizer = DistilBertTokenizerFast.from_pretrained(DISTILBERT_MODEL_NAME)
    decoded = tokenizer.decode(batch["input_ids"][0], skip_special_tokens=True)
    ctx_label = CONTEXT_LABELS[batch["context_label"][0].item()]
    sev_label = SEVERITY_LABELS[batch["severity_label"][0].item()]

    print(f"\n  First sample:")
    print(f"  Payload:  {decoded[:80]}...")
    print(f"  Context:  {ctx_label}")
    print(f"  Severity: {sev_label}")
    print(f"\n  ✅ Dataset works!")