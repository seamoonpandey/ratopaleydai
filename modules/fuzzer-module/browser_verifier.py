"""
browser_verifier — confirms xss execution using playwright headless browser
navigates to injected url and detects javascript alert/confirm/prompt dialogs
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

logger = logging.getLogger(__name__)

# try to import playwright, gracefully degrade if unavailable
try:
    from playwright.async_api import async_playwright, Dialog, Page, Error as PWError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("playwright not available, browser verification disabled")


@dataclass
class VerifyResult:
    """result of browser-based execution verification"""
    payload: str
    target_param: str
    executed: bool
    dialog_triggered: bool
    dialog_message: str
    console_errors: list[str] = field(default_factory=list)
    dom_mutations: int = 0
    elapsed_ms: float = 0
    error: str | None = None


async def verify_payloads(
    url: str,
    reflected_results: list[dict],
    timeout_ms: int = 10000,
    concurrency: int = 3,
) -> list[VerifyResult]:
    """
    verify reflected payloads using headless chromium.
    only tests payloads that were confirmed reflected in the response.
    """
    if not PLAYWRIGHT_AVAILABLE:
        logger.warning("playwright unavailable, skipping browser verification")
        return [
            VerifyResult(
                payload=r["payload"],
                target_param=r["target_param"],
                executed=False,
                dialog_triggered=False,
                dialog_message="",
                error="playwright not installed",
            )
            for r in reflected_results
        ]

    results: list[VerifyResult] = []
    semaphore = asyncio.Semaphore(concurrency)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-extensions",
            ],
        )

        try:
            tasks = [
                _verify_one(browser, semaphore, url, entry, timeout_ms)
                for entry in reflected_results
            ]
            raw = await asyncio.gather(*tasks, return_exceptions=True)

            for r in raw:
                if isinstance(r, VerifyResult):
                    results.append(r)
                elif isinstance(r, Exception):
                    logger.warning(f"verify error: {r}")
        finally:
            await browser.close()

    executed_count = sum(1 for r in results if r.executed)
    logger.info(f"browser verify: {executed_count}/{len(results)} executed")
    return results


async def _verify_one(
    browser,
    semaphore: asyncio.Semaphore,
    base_url: str,
    entry: dict,
    timeout_ms: int,
) -> VerifyResult:
    """verify a single payload in a fresh browser context"""
    async with semaphore:
        payload = entry.get("payload", "")
        param = entry.get("target_param", "")
        start = time.monotonic()

        context = await browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True,
        )

        page = await context.new_page()
        dialog_info: dict = {"triggered": False, "message": ""}
        console_errors: list[str] = []

        try:
            # listen for dialogs (alert, confirm, prompt)
            async def handle_dialog(dialog: Dialog):
                dialog_info["triggered"] = True
                dialog_info["message"] = dialog.message
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            # capture console errors
            page.on("console", lambda msg: (
                console_errors.append(msg.text)
                if msg.type == "error" else None
            ))

            # build the injected url
            injected_url = _inject_param(base_url, param, payload)

            # navigate and wait for network idle
            try:
                await page.goto(
                    injected_url,
                    wait_until="networkidle",
                    timeout=timeout_ms,
                )
            except Exception:
                # even on timeout/nav error, dialog may have fired
                pass

            # brief wait for any delayed js execution
            await page.wait_for_timeout(500)

            # check for dom mutations that indicate script injection
            dom_mutations = await _count_injected_elements(page, payload)

            elapsed = (time.monotonic() - start) * 1000
            executed = dialog_info["triggered"] or dom_mutations > 0

            return VerifyResult(
                payload=payload,
                target_param=param,
                executed=executed,
                dialog_triggered=dialog_info["triggered"],
                dialog_message=dialog_info["message"],
                console_errors=console_errors,
                dom_mutations=dom_mutations,
                elapsed_ms=round(elapsed, 2),
            )

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return VerifyResult(
                payload=payload,
                target_param=param,
                executed=False,
                dialog_triggered=dialog_info["triggered"],
                dialog_message=dialog_info["message"],
                console_errors=console_errors,
                elapsed_ms=round(elapsed, 2),
                error=str(e),
            )
        finally:
            await context.close()


async def _count_injected_elements(page, payload: str) -> int:
    """check if payload created new dom elements (img, svg, iframe, etc.)"""
    try:
        # look for elements likely created by xss payloads
        count = await page.evaluate("""() => {
            const suspicious = document.querySelectorAll(
                'img[onerror], svg[onload], iframe[src*="javascript:"], '
                + 'body[onload], input[onfocus], details[ontoggle], '
                + 'video[onerror], audio[onerror], math[onload]'
            );
            return suspicious.length;
        }""")
        return count
    except Exception:
        return 0


def _inject_param(url: str, param: str, value: str) -> str:
    """inject payload into url query parameter"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
