"""
payload-gen module — generates context-aware xss payloads
fastapi service that selects, mutates, obfuscates, and ranks payloads
"""

import logging
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# add shared module to path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.schemas import GenerateRequest, GeneratedPayload, GenerateResponse, ParamContext
from bank import PayloadBank
from selector import select_payloads
from mutator import mutate_payloads
from obfuscator import obfuscate_payloads
from xgboost_ranker import rank_payloads

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("payload-gen")

DATASET_DIR = os.environ.get("DATASET_DIR", "/app/dataset/splits")
PORT = int(os.environ.get("PORT", "5002"))

app = FastAPI(
    title="RedSentinel Payload-Gen Module",
    version="0.1.0",
    description="context-aware xss payload generation with mutation and obfuscation",
)

# load payload bank at startup
bank: PayloadBank | None = None


@app.on_event("startup")
async def load_bank():
    global bank
    bank = PayloadBank()
    if bank.size > 0:
        logger.info(f"loaded payload bank with {bank.size} payloads")
    else:
        logger.warning("payload bank is empty — check DATA_DIR / dataset paths")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "payload-gen",
        "bank_loaded": bank is not None,
        "bank_size": bank.size if bank else 0,
    }


@app.post("/generate", response_model=GenerateResponse)
async def generate(request: GenerateRequest):
    """
    generate context-aware payloads for each parameter context.
    pipeline: select → mutate → obfuscate → rank → limit
    """
    if not bank or bank.size == 0:
        raise HTTPException(
            status_code=503,
            detail="payload bank is empty/unavailable (check DATA_DIR/DATASET_DIR)",
        )

    contexts = request.contexts
    waf = request.waf
    max_payloads = request.max_payloads

    if not contexts:
        return GenerateResponse(payloads=[])

    all_generated: list[GeneratedPayload] = []

    # budget per param, at least 10 each
    per_param = max(max_payloads // len(contexts), 10)

    for param_name, param_ctx in contexts.items():
        context_type = param_ctx.reflects_in
        allowed_chars = param_ctx.allowed_chars
        confidence = param_ctx.context_confidence

        logger.info(
            f"generating for param={param_name} context={context_type} "
            f"chars={len(allowed_chars)} confidence={confidence}"
        )

        # step 1: select base payloads from bank
        selected = select_payloads(
            bank=bank,
            param=param_name,
            reflects_in=context_type,
            allowed_chars=allowed_chars,
            max_payloads=per_param,
        )

        if not selected:
            logger.warning(f"no payloads selected for {param_name}, skipping")
            continue

        # step 2: mutate for novelty
        mutated = mutate_payloads(
            payloads=selected,
            mutations_per_payload=2,
            max_total=per_param * 2,
        )

        # step 3: obfuscate for waf bypass
        if waf and waf != "none":
            obfuscated = obfuscate_payloads(
                payloads=mutated,
                waf_name=waf,
                max_per_payload=2,
            )
        else:
            obfuscated = mutated

        # step 4: rank by execution probability (uses XGBoost model with fallback to heuristic)
        ranked = rank_payloads(
            payloads=obfuscated,
            context=context_type,
            waf=waf,
            allowed_chars=allowed_chars,
            limit=per_param,
        )

        # convert to response format
        for entry in ranked:
            is_bypass = entry.get("technique", "").startswith("obfuscated:")
            all_generated.append(GeneratedPayload(
                payload=entry["payload"],
                target_param=param_name,
                context=context_type,
                confidence=entry.get("score", confidence),
                waf_bypass=is_bypass,
            ))

    # final limit
    all_generated.sort(key=lambda p: p.confidence, reverse=True)
    all_generated = all_generated[:max_payloads]

    logger.info(f"generated {len(all_generated)} total payloads for {len(contexts)} params")
    return GenerateResponse(payloads=all_generated)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
