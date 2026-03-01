import re
import pandas as pd

df = pd.read_csv("processed/all_payloads_raw.csv")

def classify_context(payload):
    p = str(payload).lower()
    if re.search(r'<\s*script', p): return "script_injection"
    if re.search(r'on\w+\s*=', p): return "event_handler"
    if re.search(r'javascript\s*:', p): return "js_uri"
    if re.search(r'(<svg|<img|<iframe|<video|<body|<marquee|<details|<embed|<object)', p): return "tag_injection"
    if re.search(r'(\{\{.*\}\}|\$\{.*\}|<%.*%>)', p): return "template_injection"
    if re.search(r'(document\.|window\.|\.innerHTML|eval\(|setTimeout\()', p): return "dom_sink"
    if re.search(r'["\'].*>', p): return "attribute_escape"
    return "generic"

def classify_technique(payload):
    p = str(payload)
    t = []
    if re.search(r'\\u[0-9a-fA-F]{4}', p): t.append("unicode_escape")
    if re.search(r'&#[xX]?[0-9a-fA-F]+;?', p): t.append("html_entity")
    if re.search(r'(atob|btoa|fromCharCode|eval\(|Function\()', p): t.append("encoding")
    if re.search(r'/\*.*\*/|<!--.*-->', p): t.append("comment_injection")
    if re.search(r'%[0-9a-fA-F]{2}', p): t.append("url_encoding")
    if re.search(r'(\t|\n|&#[x]?0?[9aAdD];)', p): t.append("whitespace_obfuscation")
    tag = re.search(r'<([a-zA-Z]+)', p)
    if tag and tag.group(1) != tag.group(1).lower(): t.append("case_variation")
    return "|".join(t) if t else "none"

def get_severity(payload):
    p = str(payload).lower()
    if any(x in p for x in ["document.cookie", "fetch(", "xmlhttp", ".src=", "eval("]): return "high"
    if any(x in p for x in ["alert(", "prompt(", "confirm("]): return "medium"
    return "low"

df["context"] = df["payload"].apply(classify_context)
df["technique"] = df["payload"].apply(classify_technique)
df["severity"] = df["payload"].apply(get_severity)
df["length"] = df["payload"].str.len()

print("\n=== CONTEXT ===")
print(df["context"].value_counts())
print("\n=== SEVERITY ===")
print(df["severity"].value_counts())

df.to_csv("processed/payloads_labeled.csv", index=False)
print(f"\n[DONE] Saved {len(df)} labeled payloads")
