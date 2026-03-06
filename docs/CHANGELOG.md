# Changelog — Problems Faced & Solutions

This document logs all significant bugs, design issues, and implementation challenges encountered during development, along with their root causes and solutions.

---

## 1. In-Memory Storage — Data Loss on Restart

**Problem:** Scan results were stored in a `Map<string, ScanRecord>` inside `ScanService`. All scan data was lost whenever the NestJS core service restarted.

**Root Cause:** The initial implementation prioritized development speed by using an in-memory data structure. TypeORM and PostgreSQL dependencies were already present but not wired up.

**Solution:**
- Created TypeORM entities: `scan.entity.ts` (scans table) and `vuln.entity.ts` (vulns table)
- Configured TypeORM with `synchronize: true` for auto-schema creation
- Replaced all `Map` operations in `ScanService` with `Repository<ScanEntity>` and `Repository<VulnEntity>` queries
- Used `simple-json` column type for complex objects (`options`, `evidence`) for cross-DB compatibility
- OneToMany/ManyToOne relations with CASCADE delete (deleting a scan removes all its vulns)

**Affected Files:**
- `core/src/scan/entities/scan.entity.ts` (new)
- `core/src/scan/entities/vuln.entity.ts` (new)
- `core/src/scan/scan.module.ts` (TypeORM registration)
- `core/src/scan/scan.service.ts` (complete rewrite of storage layer)
- `core/src/app.module.ts` (TypeORM root configuration)

**Testing:** Uses `better-sqlite3` as the test database to avoid PostgreSQL dependency in CI. All entities use cross-DB compatible column types.

---

## 2. Null Byte Crash — PostgreSQL INSERT Failure

**Problem:** XSS payloads containing null bytes (`\x00`) caused PostgreSQL to reject INSERT operations with the error: `invalid byte sequence for encoding "UTF8": 0x00`. This crashed the entire scan pipeline when a payload with null bytes was found.

**Root Cause:** Some XSS payloads legitimately include null byte characters as part of WAF bypass techniques. PostgreSQL's text columns do not accept null bytes, unlike the in-memory `Map` that previously stored these values.

**Solution:** Added null byte sanitization in `ScanService.addVuln()` — all string fields (`url`, `param`, `payload`, `type`, `severity`) are stripped of `\x00` characters before INSERT. The `evidence` object's string values are also recursively sanitized.

```typescript
// Strip null bytes that crash PostgreSQL
const clean = (s: string) => s?.replace(/\x00/g, '') ?? s;
```

**Affected Files:**
- `core/src/scan/scan.service.ts` — `addVuln()` method

**Trade-off:** Stored payloads lose their null bytes, but the actual fuzzing has already completed by this point. The null bytes served their purpose during the HTTP injection phase.

---

## 3. Vuln Deduplication Key Too Broad

**Problem:** The original dedup key format `type|url|param` was too broad, causing two different issues:
1. Different sinks on the same page were merged into one finding (e.g., `innerHTML` and `eval` on the same URL)
2. Different sources (e.g., `location.hash` vs `document.referrer`) were treated as the same vulnerability

**Root Cause:** The dedup key did not account for the specific injection point (source → sink path). Two distinct DOM XSS vulnerabilities on the same page with different taint flows were incorrectly deduplicated.

**Solution:** Changed the dedup key format to `page::source::sink`:
- `page` = normalized URL (protocol + hostname + pathname, no query/hash)
- `source` = derived from evidence (e.g., `url_param`, `location.hash`, `e.data`)
- `sink` = derived from evidence (e.g., `innerHTML`, `eval`, `document.write`)

Helper functions `deriveSource()` and `deriveSink()` extract values from the vuln's evidence object, with sane defaults when evidence is incomplete.

**Affected Files:**
- `core/src/scan/scan.service.ts` — `buildVulnKey()`, `normalizeUrlForDedup()`, `deriveSource()`, `deriveSink()`

---

## 4. Severity Under-Scoring — Reflected XSS All MEDIUM

**Problem:** All reflected XSS findings were scored as MEDIUM regardless of actual risk factors. A reflected XSS with `document.cookie` exfiltration via `eval` sink was rated the same as a simple `alert()` in an attribute context.

**Root Cause:** No severity scoring engine existed. The fuzzer module returned a hardcoded `severity: "medium"` for all confirmed reflected findings.

**Solution:** Built a rule-based 4-axis severity scoring engine (`severity-scorer.ts`):

| Axis | What It Measures | Score Range |
|------|-----------------|-------------|
| Execution | Was the payload executed, reflected, or DOM-only? | 1-3 |
| Shareability | How easily can the URL be shared to attack others? | 1-3 |
| Sink Danger | How dangerous is the injection sink? | 1-3 |
| Payload Impact | What does the payload actually do? | 0-4+ |

Total score → severity mapping: 8+ CRITICAL, 6-7 HIGH, 4-5 MEDIUM, 0-3 LOW

Plus 5 override rules for edge cases (see ARCHITECTURE.md §5 for details).

**Affected Files:**
- `core/src/common/utils/severity-scorer.ts` (new — 241 lines)
- `core/src/common/utils/severity-scorer.spec.ts` (new — 62 tests)
- `core/src/report/report.service.ts` — `buildVuln()` calls `scoreSeverity()`

---

## 5. Severity Over-Scoring — DOM XSS False CRITICALs

**Problem:** After building the severity scorer, 10 out of 23 DOM XSS test cases were over-scored. Expected 7 CRITICALs but got 13. DOM findings that should have been HIGH or MEDIUM were incorrectly rated CRITICAL.

**Root Cause:** Five distinct bugs in the scoring logic:

### Bug 5a: URLSearchParams Shareability
- **Wrong:** `URLSearchParams` scored shareability = 3 (highest, same as `url_param`)
- **Fix:** `URLSearchParams` → shareability = 1 (requires JavaScript to construct, not URL-shareable)

### Bug 5b: Missing Sink Mappings
- **Wrong:** `comment` and `jQuery_html` sinks had no mapping, defaulting to danger = 3 (max)
- **Fix:** Added explicit mappings: `comment` → 1 (low danger), `jQuery_html` → 2 (medium, equivalent to innerHTML)

### Bug 5c: Payload Score False Positives
- **Wrong:** DOM XSS taint descriptions like `"Tainted value from URLSearchParams flows to innerHTML"` contained the word `document`, triggering the `document.cookie` payload score (+3)
- **Fix:** Changed payload scoring from substring match to regex word-boundary match: `/\bdocument\.cookie\b/`

### Bug 5d: EVAL Override Too Broad
- **Wrong:** Override rule `EVAL_SINK_MINIMUM_HIGH` matched both `eval` and `script` sinks
- **Fix:** Narrowed to match only `eval` sink. `script` sinks are already scored appropriately by the regular axis scoring.

### Bug 5e: deriveSource Default
- **Wrong:** When source couldn't be determined from evidence, default was `URLSearchParams`
- **Fix:** Changed default to `url_param` (most common real-world source, appropriate default risk level)

**Affected Files:**
- `core/src/common/utils/severity-scorer.ts` — all 5 fixes
- `core/src/common/utils/severity-scorer.spec.ts` — added test cases for each bug

**Test Results After Fix:** 62/62 severity scorer tests pass. 135/136 total tests pass (1 pre-existing failure in `bridge-clients.spec.ts` unrelated to scoring).

---

## 6. DOM XSS False Positives — Multi-Hop Taint

**Problem:** The DOM XSS scanner was producing false positive findings due to multi-hop taint propagation — tracking data flow through intermediate variables that were not actually user-controlled.

**Root Cause:** The static analysis in `dom_xss_scanner.py` was too aggressive in propagating taint through assignment chains, leading to findings where the actual user input had been sanitized or transformed before reaching the sink.

**Solution:** Tightened the taint propagation rules to require direct data flow from source to sink, reducing false positives while maintaining detection of genuine DOM XSS vulnerabilities.

**Affected Files:**
- `modules/fuzzer-module/dom_xss_scanner.py`

---

## 7. Missing postMessage Source Detection

**Problem:** The scanner was not detecting `window.addEventListener('message', ...)` / `e.data` as a DOM XSS source, missing an entire class of postMessage-based XSS vulnerabilities.

**Root Cause:** The source list in `dom_xss_scanner.py` did not include `e.data` / `event.data` patterns for postMessage handlers.

**Solution:** Added `e.data` and `event.data` as recognized taint sources. Also added the `POSTMESSAGE_MEDIUM_MINIMUM` override rule in the severity scorer to ensure postMessage-based findings are rated at least MEDIUM (they require attacker-controlled iframe but are exploitable).

**Affected Files:**
- `modules/fuzzer-module/dom_xss_scanner.py` — source detection
- `core/src/common/utils/severity-scorer.ts` — override rule #5

---

## 8. `datetime` Column Type — Cross-DB Incompatibility

**Problem:** The `completedAt` column in `ScanEntity` had an explicit `{ type: 'datetime' }` TypeORM annotation. This worked in SQLite (test DB) but caused issues with PostgreSQL's timestamp handling.

**Root Cause:** TypeORM's `datetime` type maps differently across database engines. SQLite uses text-based datetime, PostgreSQL uses native `timestamp` type, and the explicit annotation prevented TypeORM from choosing the correct mapping per-engine.

**Solution:** Removed the explicit `type: 'datetime'` annotation, letting TypeORM infer the correct column type based on the connected database engine. The `Date` TypeScript type is sufficient for TypeORM to make the right choice.

**Affected Files:**
- `core/src/scan/entities/scan.entity.ts` — `completedAt` column definition

---

---

## 9. Dataset Pipeline Overhaul — Class Imbalance & Mislabeling

**Problem:** The training dataset had severe class imbalance and widespread mislabeling that would cause the model to be near-useless for most context classes.

**Root Causes (4 compounding issues):**

### 9a: Wrong regex priority in `label_contexts.py`
The labeler checked `on\w+=` (event_handler) *before* checking for full HTML tags, template patterns, and DOM sinks. This caused `<img onerror=…>`, `<svg onload=…>`, `document.body.innerHTML=…`, and `{{template}}` payloads to all be classified as `event_handler`, inflating that class to 78% of the dataset.

**Fix:** Reordered to 7-step priority: `template_injection → dom_sink → script_injection → js_uri → tag_injection → attribute_escape → event_handler`. More specific patterns win first.

### 9b: Missing and underrepresented context classes in synthetic generator
`template_injection` had only 88 samples, `attribute_escape` 370, `dom_sink` 194. The generator had no `event_handler` class, no template injection patterns, and a flat 600-combo budget shared across all classes with no per-class control.

**Fix:** Rewrote `generate_synthetic.py` with:
- Per-class budgets (200–400 combos/pattern for starved classes)
- 14 `dom_sink` templates including `innerHTML`, `location.href`, `eval`, `Function`, `insertAdjacentHTML`
- 12 `attribute_escape` templates including `&quot;` entity, double-backslash, backtick vectors
- Standalone `event_handler` templates (no wrapping tag — distinct from `tag_injection`)
- 31 `template_injection` patterns across 8 template engines: AngularJS, Jinja2/Twig, Mustache/Handlebars, ERB, Velocity, FreeMarker, Smarty, Pebble/Thymeleaf, Mako

### 9c: No high-severity training examples
Severity scoring in `label_contexts.py` only matched `document.cookie`, `fetch(`, `xmlhttp`, `.src=`, and `eval(` as `high` — mapping just 2% of data to `high`. The severity head was learning from near-zero signal.

**Fix:** Expanded `get_severity()` to match 14 high-severity patterns: `navigator.sendBeacon`, `location.href=`, `localStorage`, `sessionStorage`, `opener.`, `parent.`, `btoa(`, `atob(`, `fromCharCode`, `new Function(`, `setInterval(`, `innerHTML`. Also added high-severity exfil args (`document.cookie`, `localStorage.getItem('token')`, `navigator.sendBeacon(…)`, etc.) to `dom_sink` templates in generator.

**Fix in `finalize_dataset.py`:** Synthetic payloads were always assigned `severity: medium`. Changed to compute severity from payload content at merge time, not hardcode it.

### 9d: Insufficient event/tag coverage
Synthetic templates referenced only 8 events and 12 tags. Modern/uncommon event handlers (`onbeforetoggle`, `onpointerdown`, `onanimationend`, `ongestureend`, etc.) and tags (`audio`, `math`, `dialog`, `keygen`, `base`, `xss`, etc.) were absent, leaving the model blind to these bypass vectors.

**Fix:** Extracted events and tags into dedicated modules:
- `dataset/events.py` — 145 events across 16 categories + `HIGH_VALUE_EVENTS` subset of 87 + `SPECIAL_VARIANTS` dict for attribute-dependent triggers
- `dataset/tags.py` — 149 tags across 11 categories + `HIGH_VALUE_TAGS` subset of 44

**Final distribution after pipeline rerun:**

| Class | Before | After |
|---|---|---|
| `event_handler` | 15,150 (78%) | 6,027 (10%) |
| `tag_injection` | 276 | 23,157 |
| `attribute_escape` | 370 | 16,774 |
| `dom_sink` | 194 | 6,365 |
| `script_injection` | 1,400 | 2,535 |
| `js_uri` | 844 | 2,327 |
| `template_injection` | 88 | 1,221 |
| `generic` | 1,015 | 716 |
| **Total** | **~19,378** | **59,122** |

Severity `high` went from 2% → 15.5% of the dataset.

**Affected Files:**
- `dataset/events.py` (new — 145 events, 87 high-value, 4 special variants)
- `dataset/tags.py` (new — 149 tags, 44 high-value)
- `dataset/label_contexts.py` — 7-step priority ordering, expanded severity patterns
- `dataset/generate_synthetic.py` — per-class budgets, 31 template injection patterns, high-severity args
- `dataset/finalize_dataset.py` — per-payload severity computation, template patterns in validity filter

---

## Summary

| # | Problem | Category | Severity | Status |
|---|---------|----------|----------|--------|
| 1 | In-memory storage data loss | Architecture | High | ✅ Fixed |
| 2 | Null byte PostgreSQL crash | Data integrity | Critical | ✅ Fixed |
| 3 | Dedup key too broad | Logic | Medium | ✅ Fixed |
| 4 | Reflected XSS all MEDIUM | Scoring | High | ✅ Fixed |
| 5 | DOM XSS false CRITICALs (5 bugs) | Scoring | High | ✅ Fixed |
| 6 | DOM XSS false positives | Detection | Medium | ✅ Fixed |
| 7 | Missing postMessage source | Detection | Medium | ✅ Fixed |
| 8 | datetime column cross-DB issue | Persistence | Low | ✅ Fixed |
| 9 | Dataset class imbalance + mislabeling (4 root causes) | ML/Data | Critical | ✅ Fixed |

**Test coverage after all fixes:** 135/136 tests pass (62 severity scorer + 73 other). The single failing test (`bridge-clients.spec.ts`) is a pre-existing mock configuration issue unrelated to any of the above changes.
