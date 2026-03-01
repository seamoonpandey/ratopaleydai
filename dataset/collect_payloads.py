import os
import re
import glob
import pandas as pd

RAW_DIR = "raw"
OUTPUT_FILE = "processed/all_payloads_raw.csv"
payloads = set()

XSS_KEYWORDS = ["<script", "onerror", "onload", "alert(", "prompt(", "confirm(", "javascript:", "<svg", "<img", "<iframe", "onfocus", "onmouseover", "onclick"]

def has_xss(line):
    lower = line.lower()
    return any(k in lower for k in XSS_KEYWORDS)

def clean(line):
    line = re.sub(r'^[\s`\-\*\d\.>#]+', '', line)
    line = line.strip('`').strip()
    return line

# --- PayloadsAllTheThings ---
count_before = 0
xss_dir = os.path.join(RAW_DIR, "PayloadsAllTheThings/XSS Injection")
if os.path.exists(xss_dir):
    for f in glob.glob(f"{xss_dir}/**/*", recursive=True):
        if f.endswith((".md", ".txt")):
            with open(f, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    line = clean(line.strip())
                    if has_xss(line) and 5 < len(line) < 2000:
                        payloads.add(line)
    print(f"[+] PayloadsAllTheThings: +{len(payloads) - count_before} payloads")
    count_before = len(payloads)

# --- XSSGAI ---
xssgai_dir = os.path.join(RAW_DIR, "XSSGAI")
if os.path.exists(xssgai_dir):
    for f in glob.glob(f"{xssgai_dir}/**/*.txt", recursive=True):
        with open(f, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()
                if 5 < len(line) < 2000:
                    payloads.add(line)
    for f in glob.glob(f"{xssgai_dir}/**/*.csv", recursive=True):
        try:
            df = pd.read_csv(f, on_bad_lines='skip')
            for col in df.columns:
                for val in df[col].dropna().astype(str):
                    val = val.strip()
                    if has_xss(val) and 5 < len(val) < 2000:
                        payloads.add(val)
        except:
            pass
    print(f"[+] XSSGAI: +{len(payloads) - count_before} payloads")
    count_before = len(payloads)

# --- AwesomeXSS ---
awesome_dir = os.path.join(RAW_DIR, "AwesomeXSS")
if os.path.exists(awesome_dir):
    for f in glob.glob(f"{awesome_dir}/**/*", recursive=True):
        if f.endswith((".md", ".txt", ".js")):
            with open(f, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    line = clean(line.strip())
                    if has_xss(line) and 5 < len(line) < 2000:
                        payloads.add(line)
    print(f"[+] AwesomeXSS: +{len(payloads) - count_before} payloads")

# --- Save ---
os.makedirs("processed", exist_ok=True)
df = pd.DataFrame({"payload": list(payloads)})
df.to_csv(OUTPUT_FILE, index=False)
print(f"\n[DONE] Saved {len(df)} unique payloads to {OUTPUT_FILE}")
