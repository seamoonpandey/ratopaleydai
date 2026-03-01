#!/usr/bin/env python3
"""
inspect.py
Compare model predictions with labels in a test CSV and write misclassified rows.
Input CSV must have columns: payload, context_label, severity_label
"""
import argparse
import pandas as pd
import torch
from transformers import AutoTokenizer
from utils import MultiHeadModel, load_checkpoint, DEFAULT_CHECKPOINT, DEFAULT_TOKENIZER, CONTEXT_LABELS, SEVERITY_LABELS, predict_batch, softmax_np

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--test_csv", required=True)
    p.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT)
    p.add_argument("--tokenizer", default=DEFAULT_TOKENIZER)
    p.add_argument("--out", default="outputs/misclassified.csv")
    p.add_argument("--max_length", type=int, default=128)
    p.add_argument("--device", default="cpu")
    args = p.parse_args()

    df = pd.read_csv(args.test_csv)
    if "payload" not in df.columns:
        raise SystemExit("test csv needs 'payload' column")
    if "context_label" not in df.columns or "severity_label" not in df.columns:
        raise SystemExit("test csv needs 'context_label' and 'severity_label' columns")

    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer)
    model = MultiHeadModel(args.tokenizer, num_context=len(CONTEXT_LABELS), num_severity=len(SEVERITY_LABELS))
    model = load_checkpoint(model, args.checkpoint, map_location=args.device)

    texts = df["payload"].astype(str).tolist()
    rows = []
    batch_size = 32
    device = torch.device(args.device)
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        ctx_logits, sev_logits = predict_batch(model, tokenizer, batch, args.max_length, device)
        ctx_probs = softmax_np(ctx_logits)
        sev_probs = softmax_np(sev_logits)
        for j, text in enumerate(batch):
            ctx_pred = CONTEXT_LABELS[int(ctx_probs[j].argmax())]
            sev_pred = SEVERITY_LABELS[int(sev_probs[j].argmax())]
            ctx_conf = float(ctx_probs[j].max())
            sev_conf = float(sev_probs[j].max())
            orig_idx = i + j
            true_ctx = str(df.loc[orig_idx, "context_label"])
            true_sev = str(df.loc[orig_idx, "severity_label"])
            if ctx_pred != true_ctx or sev_pred != true_sev:
                rows.append({
                    "payload": text,
                    "true_context": true_ctx,
                    "pred_context": ctx_pred,
                    "context_conf": ctx_conf,
                    "true_severity": true_sev,
                    "pred_severity": sev_pred,
                    "severity_conf": sev_conf
                })
    out = pd.DataFrame(rows)
    out.to_csv(args.out, index=False)
    print(f"Wrote {len(out)} misclassified rows to {args.out}")

if __name__ == "__main__":
    main()
