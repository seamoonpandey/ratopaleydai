"""
dom_xss_scanner — detects dom-based xss vulnerabilities
scans javascript sources for dangerous sink patterns with tainted inputs.

uses lightweight data-flow analysis to reduce false positives:
  1. skips sinks whose argument is a hardcoded string literal
  2. requires the tainted source to appear on the same line as the sink,
     OR in a variable assignment that feeds into the sink
  3. downgrades confidence for proximity-only matches
"""

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# dangerous dom sinks that can execute arbitrary js
DOM_SINKS = {
    "innerHTML": {
        "pattern": r"\.\s*innerHTML\s*[=+]",
        "severity": "high",
        "type": "dom_xss",
    },
    "outerHTML": {
        "pattern": r"\.\s*outerHTML\s*[=+]",
        "severity": "high",
        "type": "dom_xss",
    },
    "document.write": {
        "pattern": r"document\s*\.\s*write\s*\(",
        "severity": "high",
        "type": "dom_xss",
    },
    "document.writeln": {
        "pattern": r"document\s*\.\s*writeln\s*\(",
        "severity": "high",
        "type": "dom_xss",
    },
    "eval": {
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "type": "dom_xss",
    },
    "setTimeout_string": {
        "pattern": r"setTimeout\s*\(\s*['\"`]",
        "severity": "high",
        "type": "dom_xss",
    },
    "setInterval_string": {
        "pattern": r"setInterval\s*\(\s*['\"`]",
        "severity": "high",
        "type": "dom_xss",
    },
    "Function_constructor": {
        "pattern": r"new\s+Function\s*\(",
        "severity": "high",
        "type": "dom_xss",
    },
    "insertAdjacentHTML": {
        "pattern": r"\.\s*insertAdjacentHTML\s*\(",
        "severity": "high",
        "type": "dom_xss",
    },
    "src_assign": {
        "pattern": r"\.\s*src\s*=\s*[^=]",
        "severity": "medium",
        "type": "dom_xss",
    },
    "href_assign": {
        "pattern": r"\.\s*href\s*=\s*[^=]",
        "severity": "medium",
        "type": "dom_xss",
    },
    "location_assign": {
        "pattern": (
            r"(?:window\.|document\.)?location\s*="
            r"|(?:window\.|document\.)?location\s*\.\s*(?:href|pathname)\s*="
            r"|(?:window\.|document\.)?location\s*\.\s*(?:assign|replace)\s*\("
        ),
        "severity": "medium",
        "type": "open_redirect",
    },
    "jQuery_html": {
        "pattern": r"\$\s*\([^)]*\)\s*\.\s*html\s*\(",
        "severity": "high",
        "type": "dom_xss",
    },
    "jQuery_append": {
        "pattern": r"\$\s*\([^)]*\)\s*\.\s*append\s*\(",
        "severity": "medium",
        "type": "dom_xss",
    },
    "postMessage": {
        "pattern": r"\.postMessage\s*\(",
        "severity": "low",
        "type": "dom_xss",
    },
}

# tainted sources — user-controlled input that flows into sinks
TAINTED_SOURCES = [
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"document\.cookie",
    r"location\.(hash|search|href|pathname)",
    r"window\.name",
    r"window\.location\.(hash|search|href)",
    r"URLSearchParams",
    r"\.getParameter\s*\(",
    r"localStorage\.",
    r"sessionStorage\.",
    r"postMessage",
    r"\be\.data\b",           # message event data (postMessage receiver)
    r"\bevent\.data\b",       # message event data (named 'event')
]

TAINTED_PATTERN = re.compile("|".join(TAINTED_SOURCES), re.IGNORECASE)

# pattern to detect if a sink's argument is a hardcoded string literal
# matches: document.write('...'), .innerHTML = '...', eval("..."), etc.
_STATIC_ARG_CALL = re.compile(
    r"""(?:document\.write(?:ln)?|eval|setTimeout|setInterval|new\s+Function"""
    r"""|insertAdjacentHTML)\s*\(\s*(['"`])""",
    re.IGNORECASE,
)
_STATIC_ARG_ASSIGN = re.compile(
    r"""\.(?:innerHTML|outerHTML|src|href)\s*=\s*(['"`])""",
    re.IGNORECASE,
)

# pattern to detect if a tainted source appears inside a string literal
# e.g.: 'localStorage.getItem' as a key name, not actual usage
_INSIDE_STRING_LITERAL = re.compile(
    r"""(['"`]).*?(?:""" + "|".join(TAINTED_SOURCES) + r""").*?\1""",
    re.IGNORECASE,
)

# pattern to detect feature-detection / typeof / in-operator checks
# e.g.: 'localStorage' in window, typeof localStorage
_FEATURE_DETECT = re.compile(
    r"""(?:typeof\s+|['"]\w*(?:localStorage|sessionStorage|URLSearchParams"""
    r"""|location|postMessage)\w*['"]\s+in\s+|['"](?:localStorage|sessionStorage"""
    r"""|URLSearchParams)['"]\s+in\s+)""",
    re.IGNORECASE,
)

# comment patterns
_COMMENT_LINE = re.compile(r"^\s*(?://|/\*|\*)")


@dataclass
class DomXssFinding:
    """a potential dom-based xss vulnerability"""
    sink_name: str
    sink_type: str
    severity: str
    line_number: int
    line_content: str
    has_tainted_source: bool
    source_name: str
    script_url: str
    confidence: str = "high"  # high, medium, low


@dataclass
class DomScanResult:
    """results from scanning all scripts on a page"""
    findings: list[DomXssFinding] = field(default_factory=list)
    scripts_scanned: int = 0
    total_sinks: int = 0


def scan_scripts(
    scripts: list[dict],
    base_url: str = "",
) -> DomScanResult:
    """
    scan javascript sources for dom-based xss patterns.
    scripts: list of {content: str, url: str} dicts
    """
    result = DomScanResult()

    for script in scripts:
        content = script.get("content", "")
        script_url = script.get("url", base_url)

        if not content or len(content) < 10:
            continue

        result.scripts_scanned += 1
        findings = _scan_single_script(content, script_url)
        result.findings.extend(findings)
        result.total_sinks += len(findings)

    logger.info(
        f"dom scan: {result.scripts_scanned} scripts, "
        f"{result.total_sinks} potential sinks found"
    )
    return result


def scan_response_body(
    body: str,
    url: str = "",
) -> DomScanResult:
    """
    extract inline scripts from html response body and scan them.
    """
    scripts = _extract_inline_scripts(body, url)
    return scan_scripts(scripts, url)


def _has_static_argument(sink_name: str, line: str) -> bool:
    """
    check if the sink on this line has a hardcoded string literal argument.
    e.g. document.write('<p>hello</p>') or .innerHTML = '<div>static</div>'
    returns True if the argument is a static string (no tainted data).
    returns False if there is string concatenation (+ operator) or
    template literal interpolation (${...}).
    """
    # reject if there's string concatenation (dynamic data mixed in)
    # patterns like: write('...' + var), innerHTML = '...' + var
    if re.search(r"""['"]\s*\+|\+\s*['"]""", line):
        return False
    # reject if there's template literal interpolation
    if "${" in line:
        return False
    # for function-call sinks: check if arg starts with a quote
    if _STATIC_ARG_CALL.search(line):
        return True
    # for assignment sinks: check if rhs starts with a quote
    if _STATIC_ARG_ASSIGN.search(line):
        return True
    return False


def _is_source_in_string_context(line: str) -> bool:
    """
    check if the tainted source on this line is inside a string literal
    (e.g. used as a property name or feature-detection string, not actual usage).
    """
    if _FEATURE_DETECT.search(line):
        return True
    if _INSIDE_STRING_LITERAL.search(line):
        # additional check: is there also an un-quoted usage?
        # remove all string literals and re-check
        cleaned = re.sub(r"""(['"`])(?:(?!\1).)*\1""", '""', line)
        if not TAINTED_PATTERN.search(cleaned):
            return True
    return False


def _is_comment_line(line: str) -> bool:
    """check if a line is a comment"""
    return bool(_COMMENT_LINE.match(line))


def _extract_var_from_line(line: str) -> str | None:
    """extract the variable name being assigned on this line, if any."""
    m = re.match(r"\s*(?:var|let|const)\s+(\w+)\s*=", line)
    if m:
        return m.group(1)
    # plain assignment (but not comparison: ==, ===, !=)
    m = re.match(r"\s*(\w+)\s*=[^=]", line)
    if m:
        return m.group(1)
    return None


def _line_uses_var(line: str, var_name: str) -> bool:
    """check if var_name is used (not just assigned) on this line, outside strings."""
    cleaned = re.sub(r"""(['"`])(?:(?!\1).)*\1""", '""', line)
    pat = re.compile(r"\b" + re.escape(var_name) + r"\b")
    return bool(pat.search(cleaned))


def _build_taint_set(lines: list[str]) -> tuple[set[str], str]:
    """
    multi-hop taint propagation across all lines of a script.
    starts from known tainted sources and propagates through assignments.

    returns (set of tainted variable names, original source name)
    """
    tainted: set[str] = set()
    original_source = ""

    # pass 1: seed taint from lines that directly contain a tainted source
    for i, line in enumerate(lines):
        if _is_comment_line(line):
            continue
        src = TAINTED_PATTERN.search(line)
        if not src:
            continue
        if _is_source_in_string_context(line):
            continue
        if not original_source:
            original_source = src.group(0)
        var = _extract_var_from_line(line)
        if var:
            tainted.add(var)

    # pass 2: propagate taint through variable assignments (up to 3 hops)
    # e.g. params = URLSearchParams → name = params.get() → ...
    for _ in range(3):
        new_tainted: set[str] = set()
        for i, line in enumerate(lines):
            if _is_comment_line(line):
                continue
            var = _extract_var_from_line(line)
            if not var or var in tainted:
                continue
            # check if any already-tainted variable is used on the RHS
            # get the RHS (everything after the first =)
            eq_pos = line.find("=")
            if eq_pos < 0:
                continue
            rhs = line[eq_pos + 1:]
            # skip if it's == or ===
            if rhs.startswith("="):
                continue
            cleaned_rhs = re.sub(r"""(['"`])(?:(?!\1).)*\1""", '""', rhs)
            for tv in tainted:
                pat = re.compile(r"\b" + re.escape(tv) + r"\b")
                if pat.search(cleaned_rhs):
                    new_tainted.add(var)
                    break
        if not new_tainted:
            break
        tainted |= new_tainted

    return tainted, original_source


def _trace_data_flow(
    lines: list[str],
    sink_line_idx: int,
    sink_name: str,
) -> tuple[bool, str, str]:
    """
    lightweight data-flow analysis to check if a tainted source can
    reach the sink. uses multi-hop taint propagation:
      1. same line — source directly in the sink argument (high confidence)
      2. taint propagation — source flows through variable assignments into
         any variable that appears on the sink line (medium confidence)
      3. proximity — logged for debugging only, never reported

    returns (has_tainted_source, source_name, confidence)
    """
    sink_line = lines[sink_line_idx]

    # --- level 1: direct — tainted source on the same line as the sink ---
    source_match = TAINTED_PATTERN.search(sink_line)
    if source_match:
        source_name = source_match.group(0)
        # make sure the source isn't just inside a string literal on this line
        if not _is_source_in_string_context(sink_line):
            return True, source_name, "high"

    # --- level 2: multi-hop taint propagation ---
    tainted_vars, original_source = _build_taint_set(lines)

    if tainted_vars and original_source:
        # check if any tainted variable appears on the sink line (outside strings)
        cleaned_sink = re.sub(r"""(['"`])(?:(?!\1).)*\1""", '""', sink_line)
        for var_name in tainted_vars:
            var_pattern = re.compile(r"\b" + re.escape(var_name) + r"\b")
            if var_pattern.search(cleaned_sink):
                return True, original_source, "medium"

    # --- level 3: proximity fallback (±3 lines, strict) ---
    # only log for debugging, never report (too high FP rate)
    prox_start = max(0, sink_line_idx - 3)
    prox_end = min(len(lines), sink_line_idx + 4)

    for i in range(prox_start, prox_end):
        if i == sink_line_idx:
            continue
        check_line = lines[i]
        if _is_comment_line(check_line):
            continue
        src = TAINTED_PATTERN.search(check_line)
        if not src:
            continue
        if _is_source_in_string_context(check_line):
            continue
        logger.debug(
            f"proximity source {src.group(0)} near sink {sink_name} "
            f"at line {sink_line_idx + 1}, but no data-flow link — skipping"
        )

    return False, "", ""


def _scan_single_script(content: str, script_url: str) -> list[DomXssFinding]:
    """scan a single javascript source for sink patterns with data-flow analysis"""
    findings: list[DomXssFinding] = []
    lines = content.split("\n")

    for sink_name, sink_info in DOM_SINKS.items():
        pattern = re.compile(sink_info["pattern"], re.IGNORECASE)

        for line_idx, line in enumerate(lines):
            if pattern.search(line):
                # skip sinks in comments
                if _is_comment_line(line):
                    continue

                # skip sinks with static string literal arguments
                if _has_static_argument(sink_name, line):
                    logger.debug(
                        f"skipping {sink_name} at line {line_idx + 1}: "
                        f"static string argument"
                    )
                    continue

                # data-flow analysis to find tainted sources
                has_source, source_name, confidence = _trace_data_flow(
                    lines, line_idx, sink_name
                )

                # only create findings when a tainted source is confirmed
                if not has_source:
                    continue

                findings.append(DomXssFinding(
                    sink_name=sink_name,
                    sink_type=sink_info["type"],
                    severity=sink_info["severity"] if confidence == "high"
                        else "medium" if confidence == "medium"
                        else sink_info["severity"],
                    line_number=line_idx + 1,
                    line_content=line.strip()[:200],
                    has_tainted_source=True,
                    source_name=source_name,
                    script_url=script_url,
                    confidence=confidence,
                ))

    return findings


def _extract_inline_scripts(body: str, url: str) -> list[dict]:
    """extract inline script contents from html"""
    scripts: list[dict] = []
    pattern = re.compile(
        r"<script[^>]*>(.*?)</script>",
        re.DOTALL | re.IGNORECASE,
    )

    for match in pattern.finditer(body):
        content = match.group(1).strip()
        if content and len(content) > 10:
            scripts.append({
                "content": content,
                "url": url,
            })

    return scripts


def findings_to_results(
    findings: list[DomXssFinding],
    url: str,
) -> list[dict]:
    """convert dom xss findings to fuzz result format"""
    results = []
    for f in findings:
        if not f.has_tainted_source:
            continue  # only report sinks with confirmed tainted sources

        results.append({
            "payload": f"DOM-XSS: {f.sink_name} <- {f.source_name}",
            "target_param": f.source_name,
            "reflected": False,
            "executed": False,
            "vuln": True,
            "type": f.sink_type,
            "evidence": {
                "response_code": 200,
                "reflection_position": "script",
                "browser_alert_triggered": False,
                "sink": f.sink_name,
                "source": f.source_name,
                "line": f.line_number,
                "snippet": f.line_content,
                "severity": f.severity,
                "confidence": f.confidence,
                "script_url": f.script_url,
            },
        })

    return results
