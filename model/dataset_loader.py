import torch
from torch.utils.data import Dataset, DataLoader
import pandas as pd
from transformers import DistilBertTokenizerFast

CONTEXT_MAP = {
    "script_injection": 0, "event_handler": 1, "js_uri": 2,
    "tag_injection": 3, "template_injection": 4, "dom_sink": 5,
    "attribute_escape": 6, "generic": 7
}
SEVERITY_MAP = {"low": 0, "medium": 1, "high": 2}

class XSSDataset(Dataset):
    def __init__(self, csv_path, tokenizer, max_length=128):
        self.df = pd.read_csv(csv_path)
        self.tokenizer = tokenizer
        self.max_length = max_length
        
        # Map labels to integers
        self.df["context_id"] = self.df["context"].map(CONTEXT_MAP).fillna(7).astype(int)
        self.df["severity_id"] = self.df["severity"].map(SEVERITY_MAP).fillna(1).astype(int)
    
    def __len__(self):
        return len(self.df)
    
    def __getitem__(self, idx):
        row = self.df.iloc[idx]
        payload = str(row["payload"])
        
        encoding = self.tokenizer(
            payload,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )
        
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "context_label": torch.tensor(row["context_id"], dtype=torch.long),
            "severity_label": torch.tensor(row["severity_id"], dtype=torch.long),
        }


def get_dataloaders(batch_size=32, max_length=128):
    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
    
    train_ds = XSSDataset("../dataset/splits/train.csv", tokenizer, max_length)
    val_ds = XSSDataset("../dataset/splits/val.csv", tokenizer, max_length)
    test_ds = XSSDataset("../dataset/splits/test.csv", tokenizer, max_length)
    
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=2, pin_memory=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=2, pin_memory=True)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False, num_workers=2, pin_memory=True)
    
    print(f"[+] Train: {len(train_ds)} samples, {len(train_loader)} batches")
    print(f"[+] Val:   {len(val_ds)} samples, {len(val_loader)} batches")
    print(f"[+] Test:  {len(test_ds)} samples, {len(test_loader)} batches")
    
    return train_loader, val_loader, test_loader, tokenizer


if __name__ == "__main__":
    train_loader, val_loader, test_loader, tokenizer = get_dataloaders(batch_size=32)
    
    # Test one batch
    batch = next(iter(train_loader))
    print(f"\nBatch keys: {batch.keys()}")
    print(f"input_ids shape:    {batch['input_ids'].shape}")
    print(f"attention_mask:     {batch['attention_mask'].shape}")
    print(f"context_labels:     {batch['context_label'][:5]}")
    print(f"severity_labels:    {batch['severity_label'][:5]}")
    print("\n[DONE] DataLoader OK!")
