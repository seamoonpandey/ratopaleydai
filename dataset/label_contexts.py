import re
import pandas as pd

df = pd.read_csv("processed/all_payloads_raw.csv")

def classify_context(payload):
    p = str(payload).lower()
    # 1. template injection — most specific, check first
    if re.search(r'(\{\{.*?\}\}|\$\{.*?\}|<%.*?%>|#\{.*?\}|\{%.+?%\})', p):
        return "template_injection"
    # 2. dom sink — JS execution context (before tag/event checks)
    if re.search(
        r'(document\.|window\.|\.innerHTML|\.outerHTML|eval\s*\('
        r'|setTimeout\s*\(|setInterval\s*\(|Function\s*\('
        r'|location\s*=|\.src\s*=|\.href\s*=)', p
    ):
        return "dom_sink"
    # 3. script block
    if re.search(r'<\s*script', p):
        return "script_injection"
    # 4. javascript: / data: URI
    if re.search(r'(javascript\s*:|data\s*:\s*text/html)', p):
        return "js_uri"
    # 5. tag injection — full HTML tag containing an event handler
    if re.search(r'<\s*\w+[^>]+on\w+\s*=', p):
        return "tag_injection"
    # 6. attribute escape — breaking out of a quoted attribute value
    if re.search(r'(^["\']|["\'][\s/]*>|["\'][\s]+on\w+\s*=)', p):
        return "attribute_escape"
    # 7. bare event handler (standalone, not inside a full tag)
    if re.search(r'on\w+\s*=', p):
        return "event_handler"
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
    # high — exfiltration / code execution with access to sensitive data
    if any(x in p for x in [
        "document.cookie", "fetch(", "xmlhttp", ".src=",
        "navigator.sendbeacon", "location=", "location.href=",
        "localstorage", "sessionstorage", "opener.", "parent.",
        "xmlhttprequest", "btoa(", "atob(", "fromcharcode",
        "new function(", "setinterval(", "innerhtml",
    ]):
        return "high"
    # medium — PoC execution (visible to user but no data exfil)
    if any(x in p for x in ["alert(", "prompt(", "confirm(", "console.log("]):
        return "medium"
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

