#!/usr/bin/env python3
"""
export_torchscript.py
Trace the multitask model into a TorchScript file. Output is concatenated logits:
[context_logits | severity_logits] -> split by label counts on consumer side.
"""
import argparse
import torch
from transformers import AutoTokenizer
import sys
sys.path.append("..")  # allow import utils when running from this file
from utils import MultiHeadModel, load_checkpoint, DEFAULT_CHECKPOINT, DEFAULT_TOKENIZER, CONTEXT_LABELS, SEVERITY_LABELS

def make_traceable(model):
    class TraceWrapper(torch.nn.Module):
        def __init__(self, m):
            super().__init__()
            self.m = m
        def forward(self, input_ids, attention_mask):
            ctx_logits, sev_logits = self.m(input_ids, attention_mask)
            return torch.cat([ctx_logits, sev_logits], dim=-1)
    return TraceWrapper(model)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT)
    p.add_argument("--tokenizer", default=DEFAULT_TOKENIZER)
    p.add_argument("--out", default="../../outputs/traced_model.pt")
    p.add_argument("--max_length", type=int, default=128)
    p.add_argument("--device", default="cpu")
    args = p.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer)
    model = MultiHeadModel(args.tokenizer, num_context=len(CONTEXT_LABELS), num_severity=len(SEVERITY_LABELS))
    model = load_checkpoint(model, args.checkpoint, map_location=args.device)
    model.eval()
    wrapper = make_traceable(model).to(torch.device(args.device))

    sample = "test"
    enc = tokenizer(sample, truncation=True, max_length=args.max_length, return_tensors="pt")
    input_ids = enc["input_ids"].to(torch.device(args.device))
    attention_mask = enc["attention_mask"].to(torch.device(args.device))

    with torch.no_grad():
        traced = torch.jit.trace(wrapper, (input_ids, attention_mask), strict=False)
        traced.save(args.out)
    print(f"Saved TorchScript model to {args.out}")
    print("Traced output is concatenated logits [context|severity]; split by label counts.")
