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
from http_sender import send_payloads, fetch_url
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
        # DOM-only mode: fetch the page once and scan inline scripts for DOM sinks.
        logger.info(
            f"dom-only scan {url}, timeout={timeout_ms}ms"
        )
        fetched = await fetch_url(url=url, timeout_ms=timeout_ms)
        if fetched.error or not fetched.response_body:
            logger.warning(
                f"dom-only fetch failed for {url}: {fetched.error}"
            )
            return FuzzResponse(results=[])

        scan_result = scan_response_body(fetched.response_body, url)
        dom_results = findings_to_results(scan_result.findings, url)
        return FuzzResponse(results=[FuzzResult(**r) for r in dom_results])

    # Deduplicate payloads by (payload_text, target_param) before sending any
    # HTTP requests so identical payloads are never tested twice.
    seen_pre: set[str] = set()
    deduped_payloads: list[dict] = []
    for p in payloads:
        k = f"{p.get('payload', '')}:{p.get('target_param', '')}"
        if k not in seen_pre:
            seen_pre.add(k)
            deduped_payloads.append(p)
    if len(deduped_payloads) < len(payloads):
        logger.debug(
            f"deduped payloads {len(payloads)} → {len(deduped_payloads)} before send"
        )
    payloads = deduped_payloads

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

    # Split reflections: only exact (unencoded) matches are worth browser-testing.
    # Decoded-only matches (HTML-encoded e.g. &lt;script&gt;) can never execute
    # in a browser — sending them to Playwright wastes ~5s each for nothing.
    exact_reflected = [r for r in reflected_only if r.get("exact_match")]
    decoded_only = [r for r in reflected_only if not r.get("exact_match")]

    logger.info(
        f"reflection: {len(reflected_only)}/{len(reflected)} payloads reflected "
        f"({len(exact_reflected)} exact, {len(decoded_only)} decoded-only)"
    )

    # step 3: verify js execution in headless browser (if enabled)
    # Only test exact-match reflections — decoded-only will never execute.
    verified_map: dict[str, dict] = {}
    verify_unavailable = False
    if verify_execution and exact_reflected:
        verify_results = await verify_payloads(
            url=url,
            reflected_results=exact_reflected,
            timeout_ms=timeout_ms,
            concurrency=3,
        )
        for vr in verify_results:
            key = f"{vr.payload}:{vr.target_param}"
            verified_map[key] = {
                "executed": vr.executed,
                "dialog_triggered": vr.dialog_triggered,
                "dialog_message": vr.dialog_message,
                "error": vr.error,
            }

        # If playwright is missing / browser can't launch, we can end up with
        # every payload showing executed=false. In that case, avoid reporting
        # a misleading "0 vulns" by falling back to reflection-based marking.
        if verify_results and all((r.error is not None) for r in verify_results):
            verify_unavailable = True
            logger.warning(
                "browser verification unavailable; falling back to reflected-only vuln marking"
            )

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
    # — Dangerous positions where unencoded reflection = exploitable XSS
    DANGEROUS_POSITIONS = {"html_body", "script", "attribute", "style"}
    final_results: list[FuzzResult] = []
    seen_payloads: set[str] = set()

    # Sort so reflected (especially exact) results come first.
    # Without this, a non-reflected POST duplicate can mask a reflected
    # GET result during dedup, silently dropping real findings.
    reflected.sort(
        key=lambda r: (
            not r.get("reflected", False),      # reflected first
            not r.get("exact_match", False),     # exact before decoded
        )
    )

    for r in reflected:
        payload = r["payload"]
        param = r["target_param"]
        key = f"{payload}:{param}"

        if key in seen_payloads:
            continue
        seen_payloads.add(key)

        is_reflected = r.get("reflected", False)
        is_exact = r.get("exact_match", False)
        position = r.get("reflection_position", "none")
        verify_info = verified_map.get(key, {})
        is_executed = verify_info.get("executed", False)
        is_vuln = False
        vuln_type = ""

        # Tier 1 (HIGH confidence): browser-confirmed execution
        if is_reflected and is_executed:
            is_vuln = True
            vuln_type = "reflected_xss"

        # Tier 2 (MEDIUM confidence): exact unencoded reflection in a dangerous
        # HTML position. This IS exploitable even if the browser didn't fire an
        # alert (CSP, timing, non-alert payloads). Real scanners (Burp, ZAP)
        # report this as reflected XSS.
        if not is_vuln and is_reflected and is_exact and position in DANGEROUS_POSITIONS:
            is_vuln = True
            vuln_type = "reflected_xss"

        # Tier 3 (LOW confidence): decoded-only reflection in dangerous position.
        # The server reflects input but HTML-encodes it. This encoding may be
        # incomplete/bypassable with alternative payloads. Real scanners report
        # this as an informational / low-severity reflected input finding.
        if not is_vuln and is_reflected and not is_exact and position in DANGEROUS_POSITIONS:
            is_vuln = True
            vuln_type = "reflected_xss"

        # Tier 4: verification disabled or unavailable — any reflection counts
        if not is_vuln and (not verify_execution or verify_unavailable) and is_reflected:
            is_vuln = True
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
                "reflection_position": position,
                "browser_alert_triggered": verify_info.get(
                    "dialog_triggered", False
                ),
                "exact_match": is_exact,
                "context_snippet": r.get("context_snippet", ""),
                "browser_verification_error": verify_info.get("error"),
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
