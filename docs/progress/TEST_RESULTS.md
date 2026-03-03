# RedSentinel — Test Results Report

> **Date:** March 3, 2026
> **Version:** v0.x (pre-release)
> **Tester:** Manual + automated

---

## 1. Automated Test Suites

### 1.1 NestJS Core Tests

| Suite | Tests | Status | Notes |
|-------|-------|--------|-------|
| `app.controller.spec.ts` | 1 | ✅ Pass | Basic controller wiring |
| `scan-lifecycle.e2e-spec.ts` | 14 | ✅ Pass | Scan CRUD, auth guards, status transitions |
| `scan-pipeline.e2e-spec.ts` | 7 | ✅ Pass | Pipeline phase ordering, module bridge calls |
| `websocket.e2e-spec.ts` | 6 | ✅ Pass | Socket.io event emission + client subscription |
| **Subtotal** | **28** | | |

### 1.2 Python Integration Tests

| Suite | Tests | Status | Notes |
|-------|-------|--------|-------|
| `tests/test_integration.py` | 6 | ✅ Pass | Cross-module payload flow, schema validation |
| **Subtotal** | **6** | | |

### 1.3 Compilation / Type Checks

| Check | Status | Notes |
|-------|--------|-------|
| `tsc --noEmit` (core) | ✅ 0 errors | Full TypeScript strict mode |
| `tsc --noEmit` (dashboard) | ✅ 0 errors | Next.js + React types |
| Python import validation | ✅ | All modules importable, schemas validate |

---

## 2. ML Model Evaluation

### 2.1 DistilBERT Context Classifier

**Test set:** 3,632 samples (held out from training)

| Metric | Value |
|--------|-------|
| **Context Accuracy** | **99.53%** |
| **Severity Accuracy** | **99.56%** |
| Context F1 (weighted) | 0.9953 |
| Context F1 (macro) | 0.9953 |

**Per-class breakdown (context):**

| Class | Precision | Recall | F1 | Support |
|-------|-----------|--------|-----|---------|
| attribute | 1.00 | 0.99 | 0.99 | 482 |
| attribute_escape | 0.99 | 1.00 | 1.00 | 413 |
| dom_sink | 1.00 | 1.00 | 1.00 | 458 |
| event_handler | 1.00 | 1.00 | 1.00 | 463 |
| js_uri | 1.00 | 1.00 | 1.00 | 471 |
| script_injection | 1.00 | 0.99 | 1.00 | 466 |
| tag_injection | 0.99 | 1.00 | 0.99 | 447 |
| template_injection | 1.00 | 1.00 | 1.00 | 432 |

### 2.2 XGBoost Payload Ranker

**Test set:** 1,000 samples from synthetic data split

| Metric | Value |
|--------|-------|
| **Accuracy** | **60.67%** |
| **AUC** | **0.6343** |
| **F1** | **0.6223** |

> **Note:** Model trained on synthetic data only. With real-world scan data collection (auto-collected by the fuzzer), accuracy is expected to improve significantly. The model serves as a starting point — the training collector writes real execution results to JSONL for retraining.

**Top 10 features by importance:**

| Rank | Feature | Importance |
|------|---------|------------|
| 1 | `context_attribute_escape` | 0.0714 |
| 2 | `waf_f5` | 0.0491 |
| 3 | `context_dom_sink` | 0.0489 |
| 4 | `has_auto_trigger` | 0.0477 |
| 5 | `special_char_count` | 0.0462 |
| 6 | `technique_event_handler` | 0.0452 |
| 7 | `distinct_special_chars` | 0.0446 |
| 8 | `has_encoding` | 0.0432 |
| 9 | `tag_count` | 0.0420 |
| 10 | `waf_none` | 0.0410 |

---

## 3. Live Target Testing

### 3.1 Test: `alf.nu/alert1` (XSS Challenge)

**Date:** March 3, 2026

| Field | Detail |
|-------|--------|
| **Target URL** | `https://alf.nu/alert1` |
| **Challenge** | Classic XSS challenge site — injection into a reflected context via URL fragment/parameter |
| **Expected Result** | Detect reflected XSS vulnerability (payload reflects into page and executes) |
| **Actual Result** | ❌ **False Positive** — reported DOM XSS only (not the actual reflected XSS) |

#### What was reported:

```
Vulnerability: DOM-XSS: document.write <- localStorage.
Type: dom_xss
Severity: high
Script: (inline)
Source: localStorage.
Sink: document.write
```

#### Root cause analysis:

The page contains an inline `<script>` with a **fetch polyfill** that includes:

```javascript
// Static string containing "localStorage." as part of feature detection
var support = {
  searchParams: 'URLSearchParams' in self,
  iterable: 'Symbol' in self && 'iterator' in Symbol,
  blob: ...,
  formData: ...,
  arrayBuffer: ...
};
// ... later in the same script:
document.write('...');  // static string, not user-controlled
```

The scanner found:
1. **Sink:** `document.write(` on some line
2. **Tainted source:** `localStorage.` within ±5 lines of the sink

Because the scanner uses **proximity matching** (±5 lines) without any data-flow analysis, it concluded that the `localStorage` flows into `document.write` — which is false. Both are just static strings in a polyfill library.

#### What should have happened:

1. The DOM XSS scanner should have recognized that `document.write('...')` has a **hardcoded string literal argument** (not a variable or expression containing user input) and skipped it
2. The scanner should require **actual data flow** between the source and the sink — not just proximity
3. The reflected XSS on the page should have been found by the main injection + browser verification pipeline

#### Classification:

| Aspect | Assessment |
|--------|------------|
| Finding type | False Positive |
| Root cause | Proximity matching without data-flow analysis |
| Component | `dom_xss_scanner.py` → `_scan_single_script()` |
| Lines | 175-202 (context window ±5 lines) |
| Fix priority | HIGH — false positives undermine scanner credibility |

---

## 4. Known Issues Summary

| # | Issue | Component | Severity | Status |
|---|-------|-----------|----------|--------|
| 1 | DOM XSS false positive on static string sinks | `dom_xss_scanner.py` | HIGH | ✅ Fixed — static arg detection + concat awareness + tighter location pattern |
| 2 | XGBoost ranker low accuracy (synthetic data) | `xgboost_ranker.py` | LOW | ⚠️ Will self-improve with real data |
| 3 | No database persistence for scans | `scan.service.ts` | MEDIUM | 🔴 Open |
| 4 | WebSocket has no heartbeat/ping | `scan.gateway.ts` | LOW | 🔴 Open |

---

## 6. DOM XSS Scanner Fix Verification

**Date:** March 3, 2026
**Changes:** `dom_xss_scanner.py` — 3 targeted improvements

### 6.1 Changes Made

| Change | Description |
|--------|-------------|
| **Static arg concatenation** | `_has_static_argument()` now returns `False` when `+ '...'` or `'...' +` patterns exist (string concat = dynamic data) |
| **Template literal interpolation** | Detects `${...}` in template literals — not static |
| **location_assign pattern** | Tightened from `location\s*[=.]` (matched `location.hash` = source!) to explicit `location =`, `location.href =`, `location.assign()`, `location.replace()` |
| **Finding creation** | Only creates `DomXssFinding` when tainted source is confirmed (cleaner counts) |

### 6.2 Test Results

| # | Test Case | Expected | Actual | Result |
|---|-----------|----------|--------|--------|
| 1 | Static string arg (`document.write('<script src=...')`) | 0 findings | 0 findings | ✅ PASS |
| 2 | Variable tracing (`var x = location.hash; el.innerHTML = x`) | 1 finding (medium) | 1 finding (medium) | ✅ PASS |
| 3 | Concatenated sink (`document.write('<h1>' + q + '</h1>')`) | ≥1 finding | 1 finding (medium) | ✅ PASS |
| 4 | No tainted source (purely static code) | 0 findings | 0 findings | ✅ PASS |
| 5 | Direct source in sink (`el.innerHTML = location.hash`) | 1 finding (high) | 1 finding (high) | ✅ PASS |
| 6 | Feature detection (`typeof localStorage`) | 0 findings | 0 findings | ✅ PASS |

### 6.3 Regression Check

- `location.hash` no longer falsely matched as `location_assign` sink
- Concatenated sinks (`'<h1>' + q`) no longer skipped as "static argument"
- All true positives still detected with correct confidence levels

---

## 7. Payload Bank Enrichment

**Date:** March 3, 2026
**Source:** PortSwigger XSS Cheat Sheet (https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

| Metric | Value |
|--------|-------|
| Code blocks found | 538 |
| Unique payloads extracted | 526 |
| Duplicates with existing bank | 163 |
| **New payloads added** | **363** |
| Bank before | 19,015 |
| **Bank after** | **19,378** |

**Context distribution of new payloads:**

| Context | Count |
|---------|-------|
| event_handler | 143 |
| script_injection | 82 |
| attribute_escape | 68 |
| template_injection | 67 |
| attribute | 55 |
| tag_injection | 34 |
| generic | 29 |
| dom_sink | 24 |
| js_uri | 24 |

**Updated dataset splits (after merge + finalize):**

| Split | Samples |
|-------|---------|
| Train | 17,147 (70%) |
| Val | 3,675 (15%) |
| Test | 3,675 (15%) |
| **Total valid** | **24,497** |

| Area | Gap | Risk |
|------|-----|------|
| **DOM XSS scanner** | No unit tests for false positive scenarios | High — the alf.nu bug |
| **Mutator/Obfuscator** | Tested only through integration, no isolated unit tests | Medium |
| **Browser verification** | Not tested without real Playwright (mock only) | Medium |
| **WAF fingerprinting** | No tests against real WAFs | Medium |
| **Stored XSS** | No dedicated E2E for stored XSS flow | Medium |
| **Report generation** | No test for PDF/HTML correctness | Low |
