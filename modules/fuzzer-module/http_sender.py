"""
http_sender — sends http requests with injected xss payloads
supports get and post injection into target parameters
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

logger = logging.getLogger(__name__)

# default headers to mimic a real browser
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# methods to try when injecting
INJECT_METHODS = ["GET", "POST"]


@dataclass
class SendResult:
    """result of sending a single payload"""
    payload: str
    target_param: str
    method: str
    status_code: int
    response_body: str
    response_headers: dict[str, str]
    elapsed_ms: float
    error: str | None = None
    url: str = ""


@dataclass
class SendBatch:
    """batch of send results for one url"""
    results: list[SendResult] = field(default_factory=list)
    total_sent: int = 0
    total_errors: int = 0


async def send_payloads(
    url: str,
    payloads: list[dict],
    timeout_ms: int = 10000,
    concurrency: int = 10,
    methods: list[str] | None = None,
) -> SendBatch:
    """
    send all payloads against the target url.
    injects each payload into its target_param via get and post.
    returns batch of results with response bodies for reflection checking.
    """
    methods = methods or ["GET", "POST"]
    batch = SendBatch()
    semaphore = asyncio.Semaphore(concurrency)
    timeout_s = timeout_ms / 1000

    async with httpx.AsyncClient(
        headers=DEFAULT_HEADERS,
        timeout=httpx.Timeout(timeout_s, connect=5.0),
        follow_redirects=True,
        verify=False,
    ) as client:
        tasks = []
        for entry in payloads:
            payload_text = entry.get("payload", "")
            param = entry.get("target_param", "")
            for method in methods:
                tasks.append(
                    _send_one(client, semaphore, url, payload_text, param, method)
                )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, SendResult):
                batch.results.append(r)
                batch.total_sent += 1
                if r.error:
                    batch.total_errors += 1
            elif isinstance(r, Exception):
                batch.total_errors += 1
                logger.warning(f"send error: {r}")

    logger.info(
        f"sent {batch.total_sent} requests, {batch.total_errors} errors"
    )
    return batch


async def fetch_url(
    url: str,
    timeout_ms: int = 10000,
) -> SendResult:
    """Fetch a URL once (no injection).

    Used for DOM-only scanning on pages that have no injectable parameters.
    """
    timeout_s = timeout_ms / 1000
    start = time.monotonic()

    async with httpx.AsyncClient(
        headers=DEFAULT_HEADERS,
        timeout=httpx.Timeout(timeout_s, connect=5.0),
        follow_redirects=True,
        verify=False,
    ) as client:
        try:
            resp = await client.get(url)
            elapsed = (time.monotonic() - start) * 1000
            return SendResult(
                payload="",
                target_param="",
                method="GET",
                status_code=resp.status_code,
                response_body=resp.text,
                response_headers=dict(resp.headers),
                elapsed_ms=round(elapsed, 2),
                url=url,
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return SendResult(
                payload="",
                target_param="",
                method="GET",
                status_code=0,
                response_body="",
                response_headers={},
                elapsed_ms=round(elapsed, 2),
                error=str(e),
                url=url,
            )


async def _send_one(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    url: str,
    payload: str,
    param: str,
    method: str,
) -> SendResult:
    """send a single payload via the specified method"""
    async with semaphore:
        start = time.monotonic()
        try:
            if method.upper() == "GET":
                injected_url = _inject_param_get(url, param, payload)
                resp = await client.get(injected_url)
                final_url = injected_url
            else:
                form_data = {param: payload}
                resp = await client.post(url, data=form_data)
                final_url = url

            elapsed = (time.monotonic() - start) * 1000

            return SendResult(
                payload=payload,
                target_param=param,
                method=method,
                status_code=resp.status_code,
                response_body=resp.text,
                response_headers=dict(resp.headers),
                elapsed_ms=round(elapsed, 2),
                url=final_url,
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return SendResult(
                payload=payload,
                target_param=param,
                method=method,
                status_code=0,
                response_body="",
                response_headers={},
                elapsed_ms=round(elapsed, 2),
                error=str(e),
                url=url,
            )


def _inject_param_get(url: str, param: str, value: str) -> str:
    """inject payload value into a url query parameter"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
