"""
dom_xss_scanner — detects dom-based xss vulnerabilities
scans javascript sources for dangerous sink patterns with tainted inputs
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
        "pattern": r"(location\s*[=.]|window\.location\s*=|document\.location\s*=)",
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
]

TAINTED_PATTERN = re.compile("|".join(TAINTED_SOURCES), re.IGNORECASE)


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


def _scan_single_script(content: str, script_url: str) -> list[DomXssFinding]:
    """scan a single javascript source for sink patterns"""
    findings: list[DomXssFinding] = []
    lines = content.split("\n")

    for sink_name, sink_info in DOM_SINKS.items():
        pattern = re.compile(sink_info["pattern"], re.IGNORECASE)

        for line_idx, line in enumerate(lines, start=1):
            if pattern.search(line):
                # check surrounding context for tainted sources
                context_start = max(0, line_idx - 6)
                context_end = min(len(lines), line_idx + 5)
                context_block = "\n".join(lines[context_start:context_end])

                source_match = TAINTED_PATTERN.search(context_block)
                has_source = source_match is not None
                source_name = source_match.group(0) if source_match else ""

                findings.append(DomXssFinding(
                    sink_name=sink_name,
                    sink_type=sink_info["type"],
                    severity=sink_info["severity"],
                    line_number=line_idx,
                    line_content=line.strip()[:200],
                    has_tainted_source=has_source,
                    source_name=source_name,
                    script_url=script_url,
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
                "script_url": f.script_url,
            },
        })

    return results
