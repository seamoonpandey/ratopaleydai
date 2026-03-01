"""
char fuzzer — tests which special characters survive sanitization for each parameter
"""

import logging
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

logger = logging.getLogger(__name__)

SPECIAL_CHARS = ["<", ">", '"', "'", "/", "\\", "(", ")", "{", "}", ";", "=", "`", "&", "|"]


def build_char_test_url(url: str, param: str, test_value: str) -> str:
    """build url with the char test payload in the given param"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [test_value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def fuzz_chars(
    url: str,
    param: str,
    chars: list[str] | None = None,
    timeout: float = 10.0,
) -> list[str]:
    """
    test which special characters are reflected unencoded for a given param.
    returns the list of allowed (unfiltered) characters.
    """
    if chars is None:
        chars = SPECIAL_CHARS

    allowed: list[str] = []

    # build a single test string with all chars wrapped in unique markers
    # this is more efficient than one request per char
    marker_prefix = "cF"
    marker_suffix = "Fc"
    test_parts: list[str] = []
    char_markers: list[tuple[str, str]] = []

    for i, char in enumerate(chars):
        marker = f"{marker_prefix}{i:02d}{marker_suffix}"
        test_parts.append(f"{marker}{char}")
        char_markers.append((char, marker))

    test_value = "".join(test_parts)
    test_url = build_char_test_url(url, param, test_value)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        try:
            response = await client.get(test_url)
            body = response.text

            for char, marker in char_markers:
                # check if the marker + char appears unencoded
                if f"{marker}{char}" in body:
                    allowed.append(char)

        except Exception as e:
            logger.warning(f"char fuzz failed param={param}: {e}")
            # fallback: test chars individually
            allowed = await _fuzz_chars_individually(client, url, param, chars)

    logger.debug(f"param={param} allowed_chars={allowed}")
    return allowed


async def _fuzz_chars_individually(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    chars: list[str],
) -> list[str]:
    """fallback: test each char in a separate request"""
    allowed: list[str] = []
    marker = "rsCHK"

    for char in chars:
        test_value = f"{marker}{char}{marker}"
        test_url = build_char_test_url(url, param, test_value)

        try:
            response = await client.get(test_url)
            if f"{marker}{char}{marker}" in response.text:
                allowed.append(char)
        except Exception:
            pass

    return allowed
