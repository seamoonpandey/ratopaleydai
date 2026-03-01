"""
context module — fastapi application
analyzes reflection contexts for xss parameters using probing, char fuzzing, and ai classification
"""

import logging
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from probe_injector import inject_probes
from reflection_analyzer import analyze_reflection, get_primary_context
from char_fuzzer import fuzz_chars
from html_parser import get_dom_context
from ai_classifier import AIClassifier

# ── logging ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("context-module")

# ── app ─────────────────────────────────────────────────────
app = FastAPI(
    title="RedSentinel Context Module",
    version="1.0.0",
    description="analyzes where and how input is reflected in target responses",
)

# ── ai classifier (loaded once at startup) ──────────────────
classifier = AIClassifier()


# ── schemas ─────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    url: str
    params: list[str]
    waf: str = "none"


class ParamContext(BaseModel):
    reflects_in: str = "none"
    allowed_chars: list[str] = Field(default_factory=list)
    context_confidence: float = 0.0


# ── routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "context-module",
        "ai_model_loaded": classifier.available,
    }


@app.post("/analyze")
async def analyze(req: AnalyzeRequest) -> dict[str, ParamContext]:
    """
    main endpoint: inject probes, analyze reflections, fuzz chars, classify context.
    returns a map of param -> context info.
    """
    if not req.params:
        raise HTTPException(status_code=400, detail="no params provided")

    logger.info(f"analyzing url={req.url} params={req.params} waf={req.waf}")

    # step 1: inject probe markers into all params
    probe_results = await inject_probes(req.url, req.params)

    results: dict[str, ParamContext] = {}

    for param in req.params:
        probe = probe_results.get(param)
        if not probe or probe["status_code"] == 0:
            results[param] = ParamContext()
            continue

        marker = probe["marker"]
        body = probe["body"]

        # step 2: check if marker is reflected
        reflections = analyze_reflection(body, marker)
        if not reflections:
            results[param] = ParamContext()
            continue

        # step 3: determine reflection context via multiple methods
        # method a: regex-based analysis
        regex_context = get_primary_context(reflections)

        # method b: dom-based analysis via beautifulsoup
        dom_context = get_dom_context(body, marker)

        # method c: ai classification on the reflection snippet
        snippet = reflections[0].get("context_snippet", "")
        ai_result = classifier.classify(snippet)
        ai_context = ai_result["context_type"]
        ai_confidence = ai_result["confidence"]

        # step 4: consensus — prefer ai if confident, else dom, else regex
        if ai_confidence >= 0.8:
            final_context = ai_context
            final_confidence = ai_confidence
        elif dom_context != "none":
            final_context = dom_context
            final_confidence = max(0.7, ai_confidence)
        else:
            final_context = regex_context
            final_confidence = max(0.5, ai_confidence)

        # step 5: fuzz which special chars survive
        allowed_chars = await fuzz_chars(req.url, param)

        results[param] = ParamContext(
            reflects_in=final_context,
            allowed_chars=allowed_chars,
            context_confidence=round(final_confidence, 4),
        )

        logger.info(
            f"param={param} context={final_context} confidence={final_confidence:.2f} "
            f"allowed_chars={len(allowed_chars)}"
        )

    return results


# ── entrypoint ──────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5001)
