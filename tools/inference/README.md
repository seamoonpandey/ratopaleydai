# Inference Tools

Location: tools/inference/

Quick overview:
- utils.py: shared model & helpers (edit labels here if needed)
- infer.py: CLI for single / batch inference
- inspector.py: find misclassifications (requires test CSV with labels)
- calibration.py: temperature scaling using validation CSV
- export/: TorchScript & ONNX export helpers

Defaults:
- checkpoint: model/checkpoints/best.pt
- tokenizer: model/tokenizer
- splits: ai/splits/{train,val,test}.csv
- outputs: outputs/

Install:
python -m venv .venv
source .venv/bin/activate
pip install -r tools/inference/requirements.txt

Examples:
# Single inference
python tools/inference/infer.py --payload "<script>alert(1)</script>" --checkpoint model/checkpoints/best.pt --tokenizer model/tokenizer

# Batch
python tools/inference/infer.py --input ai/splits/test.csv --output outputs/preds.csv --checkpoint model/checkpoints/best.pt --tokenizer model/tokenizer

# Misclassifications (test CSV must contain payload, context_label, severity_label)
python tools/inference/inspector.py --test_csv ai/splits/test.csv --checkpoint model/checkpoints/best.pt --tokenizer model/tokenizer --out outputs/misclassified.csv

# Calibration
python tools/inference/calibration.py --val_csv ai/splits/val.csv --checkpoint model/checkpoints/best.pt --tokenizer model/tokenizer --out outputs/temps.json

# Export TorchScript
python tools/inference/export/export_torchscript.py --checkpoint model/checkpoints/best.pt --tokenizer model/tokenizer --out outputs/traced_model.pt

# Export ONNX (with quick test)
python tools/inference/export/export_onnx.py --checkpoint model/checkpoints/best.pt --tokenizer model/tokenizer --out outputs/model.onnx --test

