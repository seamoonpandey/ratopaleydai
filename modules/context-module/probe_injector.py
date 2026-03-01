"""
probe injector — injects unique markers into each parameter to detect reflection
"""

import hashlib
import logging
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

logger = logging.getLogger(__name__)

MARKER_PREFIX = "rs0x"


def generate_marker(param: str, salt: str = "redsentinel") -> str:
    """generate a unique probe marker for a parameter"""
    raw = f"{salt}:{param}"
    digest = hashlib.md5(raw.encode()).hexdigest()[:8]
    return f"{MARKER_PREFIX}{digest}"


def build_probe_url(url: str, param: str, marker: str) -> str:
    """replace or append the param value with the probe marker"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [marker]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def inject_probes(
    url: str,
    params: list[str],
    timeout: float = 10.0,
) -> dict[str, dict]:
    """
    inject probe markers into each param and fetch the response.
    returns {param: {marker, status_code, body, headers}} for each param.
    """
    results: dict[str, dict] = {}

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        for param in params:
            marker = generate_marker(param)
            probe_url = build_probe_url(url, param, marker)

            try:
                response = await client.get(probe_url)
                results[param] = {
                    "marker": marker,
                    "status_code": response.status_code,
                    "body": response.text,
                    "headers": dict(response.headers),
                }
                logger.debug(f"probe injected param={param} marker={marker} status={response.status_code}")
            except Exception as e:
                logger.warning(f"probe failed param={param}: {e}")
                results[param] = {
                    "marker": marker,
                    "status_code": 0,
                    "body": "",
                    "headers": {},
                }

    return results
