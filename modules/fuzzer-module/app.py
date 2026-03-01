"""
fuzzer module — executes xss payloads and confirms vulnerabilities
fastapi service that sends, checks reflection, verifies in browser, scans dom
"""

import asyncio
import logging
import os

from fastapi import FastAPI, HTTPException

# add shared module to path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.schemas import FuzzRequest, FuzzResult, FuzzResponse
from http_sender import send_payloads
from reflection_checker import check_reflection_batch
from browser_verifier import verify_payloads
from dom_xss_scanner import scan_response_body, findings_to_results

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("fuzzer")

PORT = int(os.environ.get("PORT", "5003"))

app = FastAPI(
    title="RedSentinel Fuzzer Module",
    version="0.1.0",
    description="xss payload execution and vulnerability confirmation",
)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "fuzzer"}


@app.post("/test", response_model=FuzzResponse)
async def test(request: FuzzRequest):
    """
    test payloads against target url.
    pipeline: send → check reflection → verify in browser → scan dom
    """
    url = request.url
    payloads = [p.model_dump() for p in request.payloads]
    verify_execution = request.verify_execution
    timeout_ms = request.timeout

    if not payloads:
        return FuzzResponse(results=[])

    logger.info(
        f"fuzzing {url} with {len(payloads)} payloads, "
        f"verify={verify_execution}, timeout={timeout_ms}ms"
    )

    # step 1: send http requests with injected payloads
    send_batch = await send_payloads(
        url=url,
        payloads=payloads,
        timeout_ms=timeout_ms,
        concurrency=10,
    )

    # step 2: check which payloads are reflected in responses
    send_dicts = [
        {
            "payload": r.payload,
            "target_param": r.target_param,
            "response_body": r.response_body,
            "status_code": r.status_code,
            "method": r.method,
            "error": r.error,
        }
        for r in send_batch.results
    ]

    reflected = check_reflection_batch(send_dicts)
    reflected_only = [r for r in reflected if r.get("reflected")]

    logger.info(
        f"reflection: {len(reflected_only)}/{len(reflected)} payloads reflected"
    )

    # step 3: verify js execution in headless browser (if enabled)
    verified_map: dict[str, dict] = {}
    if verify_execution and reflected_only:
        verify_results = await verify_payloads(
            url=url,
            reflected_results=reflected_only,
            timeout_ms=timeout_ms,
            concurrency=3,
        )
        for vr in verify_results:
            key = f"{vr.payload}:{vr.target_param}"
            verified_map[key] = {
                "executed": vr.executed,
                "dialog_triggered": vr.dialog_triggered,
                "dialog_message": vr.dialog_message,
            }

    # step 4: scan response bodies for dom-based xss
    dom_results: list[dict] = []
    seen_bodies: set[int] = set()
    for r in send_batch.results:
        body_hash = hash(r.response_body[:2000])
        if body_hash in seen_bodies or not r.response_body:
            continue
        seen_bodies.add(body_hash)

        scan_result = scan_response_body(r.response_body, url)
        if scan_result.findings:
            dom_findings = findings_to_results(scan_result.findings, url)
            dom_results.extend(dom_findings)

    # step 5: assemble final results
    final_results: list[FuzzResult] = []
    seen_payloads: set[str] = set()

    for r in reflected:
        payload = r["payload"]
        param = r["target_param"]
        key = f"{payload}:{param}"

        if key in seen_payloads:
            continue
        seen_payloads.add(key)

        is_reflected = r.get("reflected", False)
        verify_info = verified_map.get(key, {})
        is_executed = verify_info.get("executed", False)
        is_vuln = is_reflected and is_executed

        # also mark as vuln if reflected and we're not verifying
        if not verify_execution and is_reflected:
            is_vuln = True

        vuln_type = ""
        if is_vuln:
            vuln_type = "reflected_xss"

        final_results.append(FuzzResult(
            payload=payload,
            target_param=param,
            reflected=is_reflected,
            executed=is_executed,
            vuln=is_vuln,
            type=vuln_type,
            evidence={
                "response_code": r.get("status_code", 0),
                "reflection_position": r.get("reflection_position", "none"),
                "browser_alert_triggered": verify_info.get(
                    "dialog_triggered", False
                ),
                "context_snippet": r.get("context_snippet", ""),
            },
        ))

    # add dom xss findings
    for dom_r in dom_results:
        key = f"{dom_r['payload']}:{dom_r['target_param']}"
        if key not in seen_payloads:
            seen_payloads.add(key)
            final_results.append(FuzzResult(**dom_r))

    vuln_count = sum(1 for r in final_results if r.vuln)
    logger.info(
        f"fuzz complete: {len(final_results)} results, "
        f"{vuln_count} vulnerabilities confirmed"
    )

    return FuzzResponse(results=final_results)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
