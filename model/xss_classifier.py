import torch
import torch.nn as nn
from transformers import DistilBertModel, DistilBertConfig

class XSSClassifier(nn.Module):
    """
    Red Sentinel XSS Classifier
    - Uses DistilBERT as backbone (lightweight, fast)
    - Multi-head output: context + severity
    """
    
    CONTEXT_LABELS = [
        "script_injection", "event_handler", "js_uri",
        "tag_injection", "template_injection", "dom_sink",
        "attribute_escape", "generic"
    ]
    SEVERITY_LABELS = ["low", "medium", "high"]

    def __init__(self, num_contexts=8, num_severities=3, dropout=0.3):
        super().__init__()
        
        self.backbone = DistilBertModel.from_pretrained("distilbert-base-uncased")
        hidden_size = self.backbone.config.hidden_size  # 768
        
        # Freeze first 2 layers (transfer learning)
        for param in self.backbone.embeddings.parameters():
            param.requires_grad = False
        for param in self.backbone.transformer.layer[:2].parameters():
            param.requires_grad = False
        
        # Classification heads
        self.dropout = nn.Dropout(dropout)
        
        # Context head
        self.context_head = nn.Sequential(
            nn.Linear(hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, num_contexts)
        )
        
        # Severity head
        self.severity_head = nn.Sequential(
            nn.Linear(hidden_size, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, num_severities)
        )
    
    def forward(self, input_ids, attention_mask=None):
        outputs = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
        # Use [CLS] token representation
        cls_output = outputs.last_hidden_state[:, 0, :]
        cls_output = self.dropout(cls_output)
        
        context_logits = self.context_head(cls_output)
        severity_logits = self.severity_head(cls_output)
        
        return context_logits, severity_logits
    
    def predict(self, input_ids, attention_mask=None):
        self.eval()
        with torch.no_grad():
            ctx_logits, sev_logits = self.forward(input_ids, attention_mask)
            ctx_pred = torch.argmax(ctx_logits, dim=1)
            sev_pred = torch.argmax(sev_logits, dim=1)
            ctx_conf = torch.softmax(ctx_logits, dim=1).max(dim=1).values
            sev_conf = torch.softmax(sev_logits, dim=1).max(dim=1).values
        return {
            "context": [self.CONTEXT_LABELS[i] for i in ctx_pred],
            "severity": [self.SEVERITY_LABELS[i] for i in sev_pred],
            "context_confidence": ctx_conf.tolist(),
            "severity_confidence": sev_conf.tolist(),
        }

    def count_params(self):
        total = sum(p.numel() for p in self.parameters())
        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        print(f"Total params:     {total:,}")
        print(f"Trainable params: {trainable:,}")
        print(f"Frozen params:    {total - trainable:,}")
        return trainable


if __name__ == "__main__":
    model = XSSClassifier()
    model.count_params()
    
    # Test forward pass
    dummy_input = torch.randint(0, 1000, (2, 64))
    dummy_mask = torch.ones(2, 64, dtype=torch.long)
    ctx, sev = model(dummy_input, dummy_mask)
    print(f"\nContext output shape:  {ctx.shape}")   # [2, 8]
    print(f"Severity output shape: {sev.shape}")     # [2, 3]
    print("\n[DONE] Model architecture OK!")
