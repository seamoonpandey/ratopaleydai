# RedSentinel — Progress Report

> **Date:** March 6, 2026
> **Branch:** `main`
> **Overall Completion:** ~75% of v1.0 scope

---

## 1. Project Scope

RedSentinel is an **AI-powered XSS vulnerability scanner** designed to:

- **Crawl** target websites, discover parameterized URLs and forms
- **Analyze** injection contexts using a fine-tuned DistilBERT model
- **Generate** context-aware payloads from a 24K+ bank with mutation/obfuscation
- **Rank** payloads using an XGBoost model trained on execution success data
- **Fuzz** targets with HTTP injection + headless browser verification
- **Detect** DOM-based XSS via static sink/source analysis
- **Report** findings in HTML/JSON/PDF with severity classification
- **Stream** real-time progress and findings via WebSocket to a live dashboard

### Target Architecture

```
Dashboard (Next.js) ←→ Core (NestJS) ←→ Python Microservices
                            ↓
         5-Phase Pipeline: CRAWL → CONTEXT → PAYLOAD_GEN → FUZZ → REPORT
```

### v1.0 Feature Scope

| Feature | Status |
|---------|--------|
| Web crawling with depth control | ✅ Done |
| WAF fingerprinting (8 signatures) | ✅ Done |
| AI context classification (DistilBERT) | ✅ Done |
| Character fuzzing (allowed char detection) | ✅ Done |
| Payload bank (24K+ payloads) | ✅ Done |
| Context-aware payload selection | ✅ Done |
| Payload mutation (6 strategies) | ✅ Done |
| WAF-specific obfuscation (9 strategies) | ✅ Done |
| XGBoost payload ranking | ✅ Done |
| HTTP payload injection | ✅ Done |
| Reflection checking (exact + decoded) | ✅ Done |
| Browser-verified execution (Playwright) | ✅ Done |
| DOM XSS scanning (sink/source) | ✅ Done — data-flow analysis, static arg filtering |
| Stored XSS detection | ✅ Done |
| Report generation (HTML/JSON/PDF) | ✅ Done |
| Real-time WebSocket streaming | ✅ Done |
| Live dashboard (Next.js) | ✅ Done |
| Docker Compose orchestration | ✅ Done |
| API key authentication | ✅ Done |
| Database persistence (PostgreSQL) | ❌ Schema exists, not wired |
| Strict state machine enforcement | ❌ Not implemented |
| CLI tool | ❌ Not implemented |
| CI/CD pipeline | ❌ Not implemented |
| Training data auto-collection | ✅ Done |
| XGBoost model retraining pipeline | ✅ Done |

---

## 2. What Has Been Built

### 2.1 Infrastructure

| Component | Details |
|-----------|---------|
| **Docker Compose** | 7 services: redis, postgres, context, payload-gen, fuzzer, core, dashboard |
| **Named volumes** | `pgdata`, `reports`, `training_data` |
| **Health checks** | Every service has a health endpoint + Docker healthcheck |
| **Dev compose** | Separate `docker-compose.dev.yml` for development |

### 2.2 NestJS Core (`core/`)

| Module | Purpose | Status |
|--------|---------|--------|
| `ScanProcessor` | 5-phase pipeline orchestration (651 lines) | ✅ Complete |
| `ScanService` | Scan lifecycle + vuln tracking | ✅ In-memory (no DB) |
| `ScanGateway` | WebSocket event broadcasting | ✅ 4 event types |
| `CrawlerService` | Playwright-based crawling | ✅ Depth-aware, dedup |
| `ReportService` | HTML/JSON/PDF report generation | ✅ Handlebars + Puppeteer |
| `AuthGuard` | API key validation | ✅ Header-based |
| `ContextClient` | HTTP bridge to context module | ✅ |
| `PayloadClient` | HTTP bridge to payload-gen module | ✅ |
| `FuzzerClient` | HTTP bridge to fuzzer module | ✅ With training metadata |
| `HealthController` | Aggregated service health | ✅ |

### 2.3 Python Microservices (`modules/`)

#### Context Module (`:5001`)
| File | Purpose |
|------|---------|
| `app.py` | FastAPI service — `/analyze` endpoint |
| `ai_classifier.py` | DistilBERT inference (8 contexts × 3 severities) |
| `html_parser.py` | BeautifulSoup HTML analysis |
| `probe_injector.py` | Reflection probe injection |
| `reflection_analyzer.py` | Where/how input reflects in DOM |
| `char_fuzzer.py` | Detect allowed special characters |

#### Payload-Gen Module (`:5002`)
| File | Purpose |
|------|---------|
| `app.py` | FastAPI service — `/generate` + `/ranker/info` endpoints |
| `bank.py` | 24K+ payload bank with CSV loading |
| `selector.py` | Context-aware payload selection |
| `mutator.py` | 6 mutation strategies (tag swap, event swap, JS func swap, whitespace, etc.) |
| `obfuscator.py` | 9 encoding strategies with per-WAF preferences |
| `ranker.py` | Heuristic ranker (5-component weighted score) — fallback |
| `xgboost_ranker.py` | XGBoost ML ranker with auto-fallback |
| `feature_extractor.py` | 36-feature extraction for XGBoost |

#### Fuzzer Module (`:5003`)
| File | Purpose |
|------|---------|
| `app.py` | FastAPI service — `/test` + `/training/stats` endpoints |
| `http_sender.py` | HTTP payload injection (GET/POST) |
| `reflection_checker.py` | Exact + decoded reflection detection |
| `browser_verifier.py` | Playwright dialog interception for execution proof |
| `dom_xss_scanner.py` | Static sink/source pattern scanner |
| `training_collector.py` | Logs execution results for XGBoost retraining |

### 2.4 AI / ML Models

#### DistilBERT Context Classifier
| Metric | Value |
|--------|-------|
| Architecture | DistilBERT + dual classification heads (context + severity) |
| Training data | **41,385 samples (train) + 8,868 (val) + 8,869 (test)** |
| Context accuracy | 99.53% (previous run — retraining required with new dataset) |
| Severity accuracy | 99.56% (previous run — retraining required with new dataset) |
| Context F1 (weighted) | 0.9953 (previous run) |
| Context classes | 8 (script_injection, event_handler, js_uri, tag_injection, attribute, template_injection, dom_sink, attribute_escape) |
| Severity classes | 3 (high, medium, low) |
| Epochs | 15 |
| Inference | ~10ms per sample on CPU |
| ⚠️ Status | **Dataset rebuilt — model pending retrain** |

#### XGBoost Payload Ranker
| Metric | Value |
|--------|-------|
| Architecture | XGBoost binary classifier (probability output) |
| Features | 36 (8 context + 9 WAF + 11 payload characteristics + 4 technique + 4 derived) |
| Training data | 5,000 synthetic samples (bootstrap) |
| Accuracy | **60.67%** (will improve with real scan data) |
| AUC | **0.6343** |
| F1 | **0.6223** |
| Top features | `context_attribute_escape`, `waf_f5`, `context_dom_sink`, `has_auto_trigger` |
| Self-improving | Fuzzer auto-collects execution results → retrain to improve |

### 2.5 Dashboard (`dashboard/`)

| Component | Purpose |
|-----------|---------|
| `page.tsx` | Main scan list with live stats |
| `scan/[id]/page.tsx` | Individual scan detail view |
| `new-scan-form.tsx` | Scan creation form |
| `scan-table.tsx` | Sortable scan history table |
| `vuln-list.tsx` | Vulnerability findings list with severity colors |
| `ui.tsx` | Shared UI components |
| `use-scan-socket.ts` | WebSocket hook for real-time updates |
| `api.ts` | REST API client |

### 2.6 Testing

| Test Suite | Count | Type |
|------------|-------|------|
| `app.controller.spec.ts` | 1 | Unit |
| `scan-lifecycle.e2e-spec.ts` | 14 | E2E (API CRUD + auth) |
| `scan-pipeline.e2e-spec.ts` | 7 | E2E (pipeline phases) |
| `websocket.e2e-spec.ts` | 6 | E2E (WebSocket events) |
| `test_integration.py` | 6 | Integration (Python inter-module) |
| Module-level tests | ~10 | Unit (per-module) |
| `scripts/e2e-smoke.sh` | 1 | Smoke test |
| **Total** | **~44** | |

### 2.7 Dataset

| File | Samples |
|------|---------|
| `dataset/splits/train.csv` | **41,385** |
| `dataset/splits/val.csv` | **8,868** |
| `dataset/splits/test.csv` | **8,869** |
| `dataset/ranker_training/ranker_training_samples.jsonl` | 5,001 |
| `dataset/processed/all_payloads_raw.csv` | ~19,015 |
| `dataset/processed/payloads_labeled.csv` | ~19,015 |
| `dataset/processed/synthetic_payloads.csv` | ~42,212 |
| `dataset/events.py` | 145 events (87 high-value) |
| `dataset/tags.py` | 149 tags (44 high-value) |
| **Total (train+val+test)** | **59,122** |

**Context breakdown (final splits):** `tag_injection` 39% / `attribute_escape` 28% / `dom_sink` 11% / `event_handler` 10% / `script_injection` 4% / `js_uri` 4% / `template_injection` 2% / `generic` 1%

**Severity breakdown:** `medium` 67% / `low` 17% / `high` 15.5% — significant improvement from prior 2% high coverage.

---

## 3. What Remains (v1.0 Gaps)

### 3.1 Critical Bugs

| Issue | Severity | Status |
|-------|----------|--------|
| **DOM XSS false positives** — proximity-based sink/source matching without data-flow analysis reports static string sinks as vulnerable | HIGH | ✅ Fixed — static arg filter + concatenation detection + location_assign pattern tightened |

### 3.2 Missing Features

| Feature | Priority | Effort |
|---------|----------|--------|
| **Database persistence** — scans stored in-memory Map, lost on restart | HIGH | Medium |
| **Strict state machine** — phase transitions not enforced (can skip phases) | MEDIUM | Low |
| **CLI tool** — headless scan from command line | MEDIUM | Low |
| **API key UI** — dashboard has no prompt for API key | MEDIUM | Low |
| **CI/CD pipeline** — no GitHub Actions workflow | LOW | Low |
| **Scan heartbeat** — no WebSocket heartbeat/reconnection | LOW | Low |
| **WAF bypass tracking** — no intelligence persistence for successful bypass strategies | LOW | Medium |

### 3.3 Quality Improvements Needed

| Area | Issue | Impact |
|------|-------|--------|
| **Mutator/Obfuscator** | Use `random.choice()` — not deterministic/reproducible | Test reproducibility |
| **XGBoost ranker** | Trained on synthetic data only (60% accuracy) | Will improve with real scan data |
| **DOM XSS scanner** | ✅ Fixed: 3-level data-flow (direct, variable trace, proximity skip) + static arg detection with concatenation awareness | Resolved |
| **WebSocket protocol** | Missing `scan:started`, `scan:phase` events, no heartbeat | Client robustness |
| **Error handling** | No structured error taxonomy or retry budgets | Reliability |

---

## 4. Codebase Statistics

| Metric | Count |
|--------|-------|
| Python source files | 49 |
| TypeScript/TSX source files | 57 |
| Test files | 16 |
| Test cases | ~44 |
| Docker services | 7 |
| API endpoints (Core) | ~15 |
| API endpoints (Python) | 8 |
| ML models | 2 (DistilBERT classifier + XGBoost ranker) |
| Dataset samples | **59,122** |
| Payload bank | **59,122** (incl. ~19K real-world + ~42K synthetic; 363 PortSwigger curated) |

---

## 5. Technology Stack Summary

| Layer | Technology | Version |
|-------|-----------|---------|
| Core API | NestJS | 11.0.1 |
| Job Queue | BullMQ | 5.70.1 |
| WebSocket | Socket.io | 4.8.3 |
| TypeScript | TS | 5.7.3 |
| AI Inference | PyTorch + Transformers | 2.4.0 / 4.44.0 |
| Payload Ranker | XGBoost | 2.0.3 |
| Python Services | FastAPI | 0.115.0 |
| Browser Automation | Playwright | 1.58.2 |
| Frontend | Next.js + React | 16.1.6 / 19 |
| Database | PostgreSQL | 16 |
| Cache/Queue | Redis | 7 |
| Container | Docker Compose | 3.8 |
