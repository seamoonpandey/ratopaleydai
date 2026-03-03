"""
training_collector — collects payload execution results for ML ranker training
logs successful/failed payloads to build training dataset
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# training data directory — env-configurable for Docker
TRAINING_DIR = Path(os.environ.get(
    "TRAINING_DATA_DIR",
    str(Path(__file__).parent.parent.parent / "dataset" / "ranker_training"),
))
TRAINING_DIR.mkdir(parents=True, exist_ok=True)

# training data file (append mode)
TRAINING_FILE = TRAINING_DIR / "ranker_training_samples.jsonl"


def collect_training_sample(
    payload: str,
    target_param: str,
    context: str,
    waf: str | None,
    technique: str,
    severity: str,
    executed: bool,
    dialog_triggered: bool,
    reflected: bool,
    exact_match: bool,
    reflection_position: str,
    url: str,
    allowed_chars: list[str] | None = None,
) -> None:
    """
    Collect a single training sample from fuzzer execution result.
    
    Args:
        payload: the XSS payload text
        target_param: parameter name injected
        context: context label (e.g., 'script_injection')
        waf: WAF type detected (optional)
        technique: technique type (e.g., 'mutated', 'obfuscated:unicode_escape')
        severity: severity level (e.g., 'high', 'medium', 'low')
        executed: whether payload executed in browser
        dialog_triggered: whether alert/confirm/prompt was triggered
        reflected: whether payload was reflected in response
        exact_match: whether reflection was exact (not encoded)
        reflection_position: where in HTML (e.g., 'attribute', 'script')
        url: target URL
        allowed_chars: allowed special characters (optional)
    """
    sample = {
        "timestamp": datetime.utcnow().isoformat(),
        "url": url,
        "payload_text": payload,
        "target_param": target_param,
        "context": context,
        "waf": waf,
        "technique": technique,
        "severity": severity,
        "allowed_chars": allowed_chars,
        # labels
        "executed": executed,
        "dialog_triggered": dialog_triggered,
        "reflected": reflected,
        "exact_match": exact_match,
        "reflection_position": reflection_position,
        # derived label: success if executed OR (reflected exactly in dangerous position)
        "success": executed or (
            reflected
            and exact_match
            and reflection_position in {"html_body", "script", "attribute", "style"}
        ),
    }
    
    try:
        with open(TRAINING_FILE, "a") as f:
            f.write(json.dumps(sample) + "\n")
        logger.debug(f"Collected training sample: success={sample['success']}")
    except Exception as e:
        logger.error(f"Failed to write training sample: {e}")


def collect_batch_training_samples(
    payloads: list[dict],
    results: list[dict],
    context: str,
    waf: str | None = None,
    url: str = "",
    allowed_chars: list[str] | None = None,
) -> int:
    """
    Collect training samples from batch of fuzzer results.
    
    Args:
        payloads: list of payload dicts with 'payload', 'technique', 'severity'
        results: list of FuzzResult dicts from fuzzer
        context: target context label
        waf: optional WAF type
        url: target URL
        allowed_chars: optional allowed characters
    
    Returns:
        number of samples collected
    """
    # create lookup map for payload metadata
    payload_map = {}
    for p in payloads:
        key = f"{p.get('payload', '')}:{p.get('target_param', '')}"
        payload_map[key] = p
    
    collected = 0
    for result in results:
        payload_text = result.get("payload", "")
        target_param = result.get("target_param", "")
        key = f"{payload_text}:{target_param}"
        
        # get payload metadata — payloads now carry technique/severity/context
        payload_meta = payload_map.get(key, {})
        technique = payload_meta.get("technique", "original")
        severity = payload_meta.get("severity", "medium")
        # use per-payload context if available, else fall back to request-level
        sample_context = payload_meta.get("context", context)
        
        # get execution results
        executed = result.get("executed", False)
        reflected = result.get("reflected", False)
        evidence = result.get("evidence", {})
        
        dialog_triggered = evidence.get("browser_alert_triggered", False)
        exact_match = evidence.get("exact_match", False)
        reflection_position = evidence.get("reflection_position", "none")
        
        # only collect samples with meaningful results (reflected or executed)
        if reflected or executed:
            collect_training_sample(
                payload=payload_text,
                target_param=target_param,
                context=sample_context,
                waf=waf,
                technique=technique,
                severity=severity,
                executed=executed,
                dialog_triggered=dialog_triggered,
                reflected=reflected,
                exact_match=exact_match,
                reflection_position=reflection_position,
                url=url,
                allowed_chars=allowed_chars,
            )
            collected += 1
    
    if collected > 0:
        logger.info(f"Collected {collected} training samples for ranker")
    
    return collected


def get_training_sample_count() -> int:
    """
    Get total number of training samples collected.
    """
    if not TRAINING_FILE.exists():
        return 0
    
    try:
        with open(TRAINING_FILE, "r") as f:
            return sum(1 for _ in f)
    except Exception as e:
        logger.error(f"Failed to count training samples: {e}")
        return 0


def get_training_stats() -> dict[str, Any]:
    """
    Get statistics about collected training data.
    """
    if not TRAINING_FILE.exists():
        return {
            "total_samples": 0,
            "success_samples": 0,
            "failure_samples": 0,
            "success_rate": 0.0,
        }
    
    try:
        total = 0
        success = 0
        
        with open(TRAINING_FILE, "r") as f:
            for line in f:
                sample = json.loads(line)
                total += 1
                if sample.get("success", False):
                    success += 1
        
        return {
            "total_samples": total,
            "success_samples": success,
            "failure_samples": total - success,
            "success_rate": success / total if total > 0 else 0.0,
        }
    except Exception as e:
        logger.error(f"Failed to compute training stats: {e}")
        return {
            "total_samples": 0,
            "success_samples": 0,
            "failure_samples": 0,
            "success_rate": 0.0,
        }
