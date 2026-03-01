#!/usr/bin/env python3
"""
infer.py
CLI for single or batch inference using the trained XSSClassifier (via utils.load_checkpoint).
"""
import argparse
import json
import pandas as pd
import numpy as np
import torch
from transformers import AutoTokenizer

# Import helpers from utils.py
from utils import load_checkpoint, DEFAULT_CHECKPOINT, DEFAULT_TOKENIZER, DEFAULT_MAX_LENGTH, CONTEXT_LABELS, SEVERITY_LABELS, predict_batch, softmax_np

def apply_temps(logits: np.ndarray, temp: float):
    return logits / float(temp)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT)
    p.add_argument("--tokenizer", default=DEFAULT_TOKENIZER)
    p.add_argument("--payload", help="Single payload string")
    p.add_argument("--input", help="CSV file with column 'payload' (and optional labels)")
    p.add_argument("--output", help="CSV output path (for batch)")
    p.add_argument("--max_length", type=int, default=DEFAULT_MAX_LENGTH)
    p.add_argument("--device", default="cpu")
    p.add_argument("--temps", help="Optional temps.json file with {'context':T1,'severity':T2}")
    args = p.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer)
    if tokenizer.pad_token is None:
        if getattr(tokenizer, "eos_token", None):
            tokenizer.pad_token = tokenizer.eos_token
        elif getattr(tokenizer, "cls_token", None):
            tokenizer.pad_token = tokenizer.cls_token
        else:
            # Fallback: add a new pad token (requires resizing embeddings after model load)
            tokenizer.add_special_tokens({"pad_token": "[PAD]"})
            added_pad_token = True
    else:
        added_pad_token = False

    device = torch.device(args.device)

    # Load model using utils.load_checkpoint (returns model already on device and eval())
    model = load_checkpoint(args.checkpoint, map_location=args.device, device=device)

    # If we added a pad token to the tokenizer above, resize the model embeddings.
    if 'added_pad_token' in locals() and added_pad_token:
        try:
            model.backbone.resize_token_embeddings(len(tokenizer))
        except Exception:
            # DistilBertModel exposes resize_token_embeddings on the model; if not available, continue.
            pass

    temps = None
    if args.temps:
        with open(args.temps, "r") as f:
            temps = json.load(f)

    out_rows = []

    if args.payload:
        texts = [args.payload]
    elif args.input:
        df = pd.read_csv(args.input)
        if "payload" not in df.columns:
            raise SystemExit("input CSV must contain 'payload' column")
        texts = df["payload"].astype(str).tolist()
    else:
        raise SystemExit("Provide --payload or --input")

    batch_size = 32
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        ctx_logits, sev_logits = predict_batch(model, tokenizer, batch, args.max_length, device)
        if temps:
            if "context" in temps:
                ctx_logits = apply_temps(ctx_logits, temps["context"])
            if "severity" in temps:
                sev_logits = apply_temps(sev_logits, temps["severity"])
        ctx_probs = softmax_np(ctx_logits)
        sev_probs = softmax_np(sev_logits)
        for j, text in enumerate(batch):
            ctx_idx = int(np.argmax(ctx_probs[j]))
            sev_idx = int(np.argmax(sev_probs[j]))
            out_rows.append({
                "payload": text,
                "context": CONTEXT_LABELS[ctx_idx],
                "context_conf": float(ctx_probs[j][ctx_idx]),
                "severity": SEVERITY_LABELS[sev_idx],
                "severity_conf": float(sev_probs[j][sev_idx])
            })

    out_df = pd.DataFrame(out_rows)
    if args.output:
        out_df.to_csv(args.output, index=False)
        print(f"Wrote {args.output}")
    else:
        print(out_df.to_json(orient="records", lines=False))

if __name__ == "__main__":
    main()
