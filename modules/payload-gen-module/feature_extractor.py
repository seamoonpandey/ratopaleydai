"""
feature_extractor — extracts structured features from payloads for ML ranker
converts payload dict + context into feature vector for XGBoost
"""

import re
from typing import Any

# context labels from ai_classifier
CONTEXT_LABELS = [
    "script_injection",
    "event_handler",
    "js_uri",
    "tag_injection",
    "attribute",
    "template_injection",
    "dom_sink",
    "attribute_escape",
]

# WAF types
WAF_TYPES = [
    "cloudflare",
    "akamai",
    "aws_waf",
    "imperva",
    "f5",
    "modsecurity",
    "wordfence",
    "sucuri",
    "none",
]

# technique types
TECHNIQUE_TYPES = [
    "original",
    "mutated",
    "obfuscated:unicode_escape",
    "obfuscated:hex_escape",
    "obfuscated:html_entity",
    "obfuscated:url_encode",
    "obfuscated:double_url_encode",
    "obfuscated:mixed_case",
    "obfuscated:tab_newline_inject",
    "obfuscated:comment_inject",
    "obfuscated:concat_split",
]

# severity values
SEVERITY_MAP = {"high": 1.0, "medium": 0.7, "low": 0.4, "critical": 1.2}

# regex patterns for feature extraction
TAG_PATTERN = re.compile(r"<\w+", re.IGNORECASE)
EVENT_HANDLER_PATTERN = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
QUOTE_PATTERN = re.compile(r"['\"]")
AUTO_TRIGGER_PATTERN = re.compile(
    r"(\bonerror\s*=|\bonload\s*=|<script\b|<img\b|<svg\b|data:text/html|javascript:)",
    re.IGNORECASE,
)
SPECIAL_CHAR_PATTERN = re.compile(r"[<>'\"/\\()=;{}[\]`|&!@#$%^*~?]")
ENCODING_PATTERN = re.compile(r"(\\[ux]|&#|%[0-9a-f]{2})", re.IGNORECASE)
COMMENT_PATTERN = re.compile(r"//|/\*|\<!--")
EVAL_PATTERN = re.compile(r"\beval\s*\(|\bFunction\s*\(", re.IGNORECASE)
DOM_SINK_PATTERN = re.compile(
    r"\.(innerHTML|outerHTML|write|writeln|insertAdjacentHTML)", re.IGNORECASE
)
JS_URI_PATTERN = re.compile(r"(javascript:|data:text/html)", re.IGNORECASE)


def extract_features(
    payload: dict,
    context: str,
    waf: str | None = None,
    allowed_chars: list[str] | None = None,
) -> dict[str, Any]:
    """
    Extract feature vector from payload for ML ranker.
    
    Args:
        payload: dict with 'payload', 'technique', 'severity' keys
        context: target context label (e.g., 'script_injection')
        waf: optional WAF type detected
        allowed_chars: optional list of allowed special characters
    
    Returns:
        feature dict with ~30 features for XGBoost
    """
    text = payload.get("payload", "")
    technique = payload.get("technique", "original")
    severity = payload.get("severity", "medium")
    
    features = {}
    
    # context one-hot encoding (8 features)
    for ctx in CONTEXT_LABELS:
        features[f"context_{ctx}"] = 1 if ctx == context else 0
    
    # WAF one-hot encoding (9 features)
    waf_normalized = (waf or "none").lower()
    for waf_type in WAF_TYPES:
        features[f"waf_{waf_type}"] = 1 if waf_type == waf_normalized else 0
    
    # payload characteristics (numeric features)
    features["payload_length"] = len(text)
    features["tag_count"] = len(TAG_PATTERN.findall(text))
    features["event_handler_count"] = len(EVENT_HANDLER_PATTERN.findall(text))
    features["quote_count"] = len(QUOTE_PATTERN.findall(text))
    features["has_auto_trigger"] = 1 if AUTO_TRIGGER_PATTERN.search(text) else 0
    features["has_eval"] = 1 if EVAL_PATTERN.search(text) else 0
    features["has_dom_sink"] = 1 if DOM_SINK_PATTERN.search(text) else 0
    features["has_js_uri"] = 1 if JS_URI_PATTERN.search(text) else 0
    features["has_comment"] = 1 if COMMENT_PATTERN.search(text) else 0
    
    # special char diversity
    special_chars = set(SPECIAL_CHAR_PATTERN.findall(text))
    features["special_char_diversity"] = len(special_chars)
    
    # encoding depth (count of encoded sequences)
    features["encoding_depth"] = len(ENCODING_PATTERN.findall(text))
    
    # technique one-hot (simplified to categories)
    features["technique_original"] = 1 if technique == "original" else 0
    features["technique_mutated"] = 1 if technique == "mutated" else 0
    features["technique_obfuscated"] = 1 if technique.startswith("obfuscated:") else 0
    
    # technique effectiveness index (based on historical heuristics)
    technique_index = TECHNIQUE_TYPES.index(technique) if technique in TECHNIQUE_TYPES else len(TECHNIQUE_TYPES)
    features["technique_index"] = technique_index
    
    # severity numeric
    features["severity_value"] = SEVERITY_MAP.get(severity, 0.5)
    
    # char coverage if provided
    if allowed_chars:
        special_in_payload = set(SPECIAL_CHAR_PATTERN.findall(text))
        if special_in_payload:
            allowed_set = set(allowed_chars)
            covered = special_in_payload & allowed_set
            features["char_coverage_ratio"] = len(covered) / len(special_in_payload)
        else:
            features["char_coverage_ratio"] = 1.0
    else:
        features["char_coverage_ratio"] = 1.0
    
    # length bucket (categorical)
    if len(text) < 50:
        features["length_bucket"] = 0
    elif len(text) < 100:
        features["length_bucket"] = 1
    elif len(text) < 200:
        features["length_bucket"] = 2
    else:
        features["length_bucket"] = 3
    
    # context-technique alignment score (heuristic)
    features["context_technique_alignment"] = _compute_context_technique_alignment(
        context, technique, text
    )
    
    return features


def _compute_context_technique_alignment(
    context: str, technique: str, text: str
) -> float:
    """
    Heuristic score for how well technique matches context.
    Some contexts benefit more from certain techniques.
    """
    score = 0.5  # baseline
    
    # attribute contexts benefit from breaking out
    if context == "attribute" and ("onerror" in text.lower() or "onload" in text.lower()):
        score += 0.3
    
    # script injection benefits from direct execution
    if context == "script_injection" and technique == "original":
        score += 0.2
    
    # event handlers benefit from mutations
    if context == "event_handler" and technique == "mutated":
        score += 0.2
    
    # template injection benefits from template syntax
    if context == "template_injection" and ("{{" in text or "${" in text):
        score += 0.3
    
    # obfuscation can help bypass WAF in any context
    if technique.startswith("obfuscated:"):
        score += 0.1
    
    return min(score, 1.0)


def get_feature_names() -> list[str]:
    """
    Return ordered list of feature names for XGBoost model.
    Used during training and inference to ensure consistent ordering.
    """
    features = []
    
    # context features
    for ctx in CONTEXT_LABELS:
        features.append(f"context_{ctx}")
    
    # WAF features
    for waf_type in WAF_TYPES:
        features.append(f"waf_{waf_type}")
    
    # payload characteristics
    features.extend([
        "payload_length",
        "tag_count",
        "event_handler_count",
        "quote_count",
        "has_auto_trigger",
        "has_eval",
        "has_dom_sink",
        "has_js_uri",
        "has_comment",
        "special_char_diversity",
        "encoding_depth",
        "technique_original",
        "technique_mutated",
        "technique_obfuscated",
        "technique_index",
        "severity_value",
        "char_coverage_ratio",
        "length_bucket",
        "context_technique_alignment",
    ])
    
    return features
