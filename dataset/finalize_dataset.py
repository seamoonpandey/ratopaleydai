import re
import os
import pandas as pd
from sklearn.model_selection import train_test_split

real = pd.read_csv("processed/payloads_labeled.csv")
synthetic = pd.read_csv("processed/synthetic_payloads.csv")

# ── Assign severity to synthetic payloads from payload content ────────────────
def get_severity(payload):
    p = str(payload).lower()
    if any(x in p for x in [
        "document.cookie", "fetch(", "xmlhttp", ".src=",
        "navigator.sendbeacon", "location=", "location.href=",
        "localstorage", "sessionstorage", "opener.", "parent.",
        "xmlhttprequest", "btoa(", "atob(", "fromcharcode",
        "new function(", "setinterval(", "innerhtml",
    ]):
        return "high"
    if any(x in p for x in ["alert(", "prompt(", "confirm(", "console.log("]):
        return "medium"
    return "low"

if "technique" not in synthetic.columns: synthetic["technique"] = "synthetic"
if "length" not in synthetic.columns:    synthetic["length"] = synthetic["payload"].str.len()

# Always recompute severity from content (never default to "medium")
synthetic["severity"] = synthetic["payload"].apply(get_severity)

real["source"] = "real"
synthetic["source"] = "synthetic"

df = pd.concat([real, synthetic], ignore_index=True)
df = df.drop_duplicates(subset=["payload"])

# ── Validity filter ───────────────────────────────────────────────────────────
XSS_PATTERNS = [
    # script / tag
    r'<\s*script', r'on\w+\s*=', r'javascript\s*:', r'data\s*:\s*text/html',
    r'<\s*svg', r'<\s*img', r'<\s*iframe', r'<\s*body',
    # function calls
    r'alert\s*[\(`]', r'prompt\s*[\(`]', r'confirm\s*[\(`]',
    # dom sinks
    r'document\.', r'eval\s*\(', r'window\.', r'innerHTML',
    r'String\.fromCharCode', r'setTimeout', r'location\s*=',
    # encoding markers
    r'&#', r'%3[cC]',
    # template injection patterns
    r'\{\{.*?\}\}', r'\$\{.*?\}', r'<%.*?%>', r'#\{.*?\}',
]

def is_valid(p):
    if not isinstance(p, str): return False
    if not (5 < len(p) < 2000): return False
    return any(re.search(pat, p, re.IGNORECASE) for pat in XSS_PATTERNS)

before = len(df)
df = df[df["payload"].apply(is_valid)]
print(f"[+] Removed {before - len(df)} invalid, kept {len(df)}")

print(f"\n=== BY SOURCE ===")
print(df["source"].value_counts())
print(f"\n=== BY CONTEXT ===")
print(df["context"].value_counts())
print(f"\n=== BY SEVERITY ===")
print(df["severity"].value_counts())

# ── Drop unknown context/severity labels ──────────────────────────────────────
VALID_CONTEXTS  = {
    "script_injection", "event_handler", "js_uri", "tag_injection",
    "template_injection", "dom_sink", "attribute_escape", "attribute", "generic",
}
VALID_SEVERITIES = {"low", "medium", "high"}

before = len(df)
df = df[df["context"].isin(VALID_CONTEXTS) & df["severity"].isin(VALID_SEVERITIES)]
print(f"\n[+] Dropped {before - len(df)} rows with unknown labels, kept {len(df)}")

os.makedirs("splits", exist_ok=True)
train, temp = train_test_split(df, test_size=0.30, random_state=42, stratify=df["context"])
val, test = train_test_split(temp, test_size=0.50, random_state=42, stratify=temp["context"])

train.to_csv("splits/train.csv", index=False)
val.to_csv("splits/val.csv", index=False)
test.to_csv("splits/test.csv", index=False)
train["payload"].to_csv("splits/train_payloads.txt", index=False, header=False)
val["payload"].to_csv("splits/val_payloads.txt", index=False, header=False)
test["payload"].to_csv("splits/test_payloads.txt", index=False, header=False)

print(f"\n=== SPLITS ===")
print(f"Train: {len(train)} ({len(train)/len(df)*100:.1f}%)")
print(f"Val:   {len(val)} ({len(val)/len(df)*100:.1f}%)")
print(f"Test:  {len(test)} ({len(test)/len(df)*100:.1f}%)")
print(f"\n[DONE] All files saved to splits/")

