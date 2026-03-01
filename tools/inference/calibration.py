#!/usr/bin/env python3
"""
calibration.py
Fit a scalar temperature for each head using a validation CSV (payload, context_label, severity_label).
Saves temps.json with {"context": T_ctx, "severity": T_sev}.
"""
import argparse
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from transformers import AutoTokenizer
from utils import MultiHeadModel, load_checkpoint, DEFAULT_CHECKPOINT, DEFAULT_TOKENIZER, CONTEXT_LABELS, SEVERITY_LABELS, predict_batch, softmax_np, save_json

def collect_logits_labels(model, tokenizer, csv_path, max_length=128, device=torch.device("cpu")):
    df = pd.read_csv(csv_path)
    texts = df["payload"].astype(str).tolist()
    ctx_map = {l: i for i, l in enumerate(CONTEXT_LABELS)}
    sev_map = {l: i for i, l in enumerate(SEVERITY_LABELS)}
    ctx_col = "context_label" if "context_label" in df.columns else "context"
    sev_col = "severity_label" if "severity_label" in df.columns else "severity"
    ctx_idx = [ctx_map.get(x, 0) for x in df[ctx_col].astype(str).tolist()]
    sev_idx = [sev_map.get(x, 0) for x in df[sev_col].astype(str).tolist()]

    ctx_logits_all = []
    sev_logits_all = []
    batch_size = 32
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        ctx_logits, sev_logits = predict_batch(model, tokenizer, batch, max_length, device)
        ctx_logits_all.append(ctx_logits)
        sev_logits_all.append(sev_logits)
    ctx_logits_all = np.vstack(ctx_logits_all)
    sev_logits_all = np.vstack(sev_logits_all)
    return ctx_logits_all, np.array(ctx_idx), sev_logits_all, np.array(sev_idx)

def fit_temperature(logits: np.ndarray, labels: np.ndarray, max_iter=200):
    device = torch.device("cpu")
    logits_t = torch.from_numpy(logits).float().to(device)
    labels_t = torch.from_numpy(labels).long().to(device)
    logT = torch.nn.Parameter(torch.zeros(1, device=device))
    nll = nn.CrossEntropyLoss()
    optimizer = torch.optim.LBFGS([logT], lr=0.1, max_iter=max_iter, line_search_fn="strong_wolfe")

    def closure():
        optimizer.zero_grad()
        T = torch.exp(logT)
        loss = nll(logits_t / T, labels_t)
        loss.backward()
        return loss

    optimizer.step(closure)
    return float(torch.exp(logT).item())

def compute_ece(probs: np.ndarray, labels: np.ndarray, n_bins=10):
    """
    Expected Calibration Error (ECE) using max-confidence bins.
    probs: (N, C)
    labels: (N,)
    """
    confidences = probs.max(axis=1)
    predictions = probs.argmax(axis=1)
    accuracies = (predictions == labels).astype(float)
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        mask = (confidences > bins[i]) & (confidences <= bins[i + 1])
        if mask.sum() == 0:
            continue
        conf_bin = confidences[mask].mean()
        acc_bin = accuracies[mask].mean()
        ece += (mask.sum() / len(confidences)) * abs(conf_bin - acc_bin)
    return ece

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--val_csv", required=True)
    p.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT)
    p.add_argument("--tokenizer", default=DEFAULT_TOKENIZER)
    p.add_argument("--out", default="outputs/temps.json")
    p.add_argument("--max_length", type=int, default=128)
    p.add_argument("--device", default="cpu")
    args = p.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer)
    device = torch.device(args.device)
    model = load_checkpoint(args.checkpoint, map_location=args.device, device=device)

    ctx_logits, ctx_labels, sev_logits, sev_labels = collect_logits_labels(model, tokenizer, args.val_csv, max_length=args.max_length, device=device)
    ctx_probs = softmax_np(ctx_logits)
    sev_probs = softmax_np(sev_logits)
    ctx_pre_ece = compute_ece(ctx_probs, ctx_labels)
    sev_pre_ece = compute_ece(sev_probs, sev_labels)
    print(f"Pre-calibration ECE: context={ctx_pre_ece:.4f}, severity={sev_pre_ece:.4f}")

    print("Fitting context temperature...")
    T_ctx = fit_temperature(ctx_logits, ctx_labels)
    print("Fitting severity temperature...")
    T_sev = fit_temperature(sev_logits, sev_labels)

    # post
    ctx_probs_post = softmax_np(ctx_logits / T_ctx)
    sev_probs_post = softmax_np(sev_logits / T_sev)
    ctx_post_ece = compute_ece(ctx_probs_post, ctx_labels)
    sev_post_ece = compute_ece(sev_probs_post, sev_labels)
    print(f"Post-calibration ECE: context={ctx_post_ece:.4f}, severity={sev_post_ece:.4f}")

    temps = {"context": float(T_ctx), "severity": float(T_sev)}
    save_json(temps, args.out)
    print(f"Saved temps to {args.out}: {temps}")

if __name__ == "__main__":
    main()
