#!/usr/bin/env python3
"""
export_onnx.py
Export the multitask model to ONNX with dynamic axes and run an optional ONNXRuntime sanity test.
"""
import argparse
import torch
from transformers import AutoTokenizer
import onnx
import onnxruntime as ort
import numpy as np
import sys
sys.path.append("..")
from utils import MultiHeadModel, load_checkpoint, DEFAULT_CHECKPOINT, DEFAULT_TOKENIZER, CONTEXT_LABELS, SEVERITY_LABELS

def make_wrapper(model):
    class Wrapper(torch.nn.Module):
        def __init__(self, m):
            super().__init__()
            self.m = m
        def forward(self, input_ids, attention_mask):
            ctx, sev = self.m(input_ids, attention_mask)
            return torch.cat([ctx, sev], dim=-1)
    return Wrapper(model)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT)
    p.add_argument("--tokenizer", default=DEFAULT_TOKENIZER)
    p.add_argument("--out", default="../../outputs/model.onnx")
    p.add_argument("--max_length", type=int, default=128)
    p.add_argument("--device", default="cpu")
    p.add_argument("--test", action="store_true", help="Run a quick ONNXRuntime test")
    args = p.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer)
    model = MultiHeadModel(args.tokenizer, num_context=len(CONTEXT_LABELS), num_severity=len(SEVERITY_LABELS))
    model = load_checkpoint(model, args.checkpoint, map_location=args.device)
    model.eval()
    wrapper = make_wrapper(model).to(torch.device(args.device))

    sample = "test"
    enc = tokenizer(sample, truncation=True, max_length=args.max_length, return_tensors="pt")
    input_ids = enc["input_ids"]
    attention_mask = enc["attention_mask"]

    dynamic_axes = {
        "input_ids": {0: "batch", 1: "seq"},
        "attention_mask": {0: "batch", 1: "seq"},
        "output": {0: "batch"}
    }
    input_names = ["input_ids", "attention_mask"]
    output_names = ["output"]
    torch.onnx.export(wrapper, (input_ids, attention_mask), args.out,
                      input_names=input_names, output_names=output_names,
                      dynamic_axes=dynamic_axes, opset_version=13, do_constant_folding=True)
    print(f"Saved ONNX model to {args.out}")

    onnx_model = onnx.load(args.out)
    onnx.checker.check_model(onnx_model)
    print("ONNX model check passed.")

    if args.test:
        sess = ort.InferenceSession(args.out)
        ort_inputs = {"input_ids": input_ids.numpy(), "attention_mask": attention_mask.numpy()}
        ort_outs = sess.run(None, ort_inputs)
        print("ONNXRuntime output shape:", np.array(ort_outs[0]).shape)

if __name__ == "__main__":
    main()
