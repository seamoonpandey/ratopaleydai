# RedSentinel — Project Documentation

> AI-powered Cross-Site Scripting (XSS) vulnerability scanner with real-time dashboard, headless browser verification, and context-aware payload generation.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Technology Stack & Rationale](#3-technology-stack--rationale)
4. [The Scan Pipeline — 5 Phases](#4-the-scan-pipeline--5-phases)
5. [NestJS Core (Orchestration API)](#5-nestjs-core-orchestration-api)
6. [Python Microservices](#6-python-microservices)
7. [AI / ML Architecture](#7-ai--ml-architecture)
8. [Dataset Pipeline](#8-dataset-pipeline)
9. [Dashboard (Next.js Frontend)](#9-dashboard-nextjs-frontend)
10. [Real-Time WebSocket Protocol](#10-real-time-websocket-protocol)
11. [Exploitable Test Application](#11-exploitable-test-application)
12. [Infrastructure & Deployment](#12-infrastructure--deployment)
13. [Testing Strategy](#13-testing-strategy)
14. [Configuration Reference](#14-configuration-reference)
15. [Design Decisions & Trade-offs](#15-design-decisions--trade-offs)

---

## 1. Project Overview

RedSentinel is a full-stack, AI-driven XSS scanner built as a hybrid microservices system. It doesn't just throw payloads at a target — it **understands** where user input reflects in the DOM, classifies the injection context using a fine-tuned DistilBERT model, generates payloads tailored to that context, delivers them through HTTP and headless-browser verification, and streams results to a live dashboard over WebSockets.

### What makes it different from traditional scanners

| Traditional Scanner | RedSentinel |
|---|---|
| Static payload lists | Context-aware payload selection from a 24K+ bank, mutated and obfuscated per-context |
| Regex-based detection | Multi-layer consensus: AI classification → DOM parsing → regex fallback |
| Blind fuzzing | Reflection-aware: only tests payloads where input is confirmed to reflect |
| Binary pass/fail | Headless Chromium verification — confirms actual JS execution via dialog interception |
| WAF-agnostic | Fingerprints 8 WAFs and applies WAF-specific encoding bypass strategies |
| Batch reports | Real-time: WebSocket push of each finding as it happens, live progress bars |

### High-Level Numbers

- **42+ vulnerability endpoints** in the test application
- **24,000+ curated payloads** with labeled context metadata
- **16 DOM sink patterns** × **12 tainted source patterns** for DOM-XSS detection
- **8 WAF signatures** with per-WAF obfuscation preferences
- **6 mutation strategies** + **9 encoding strategies** for payload transformation
- **8 AI context classes** + **3 severity classes** in the DistilBERT model

---

## 2. System Architecture

```
┌──────────────────┐      REST / WebSocket
│    Dashboard      │ ◄──────────────────────┐
│  (Next.js :8080)  │                        │
└──────────────────┘                         │
                                             │
┌───────────────────────────────────────────────────────────┐
│                Core — NestJS  :3000                        │
│   REST API  │  WebSocket Gateway  │  BullMQ Job Queue      │
│                                                            │
│   ┌──────────┐   ┌─────────────┐   ┌──────────────┐       │
│   │ Crawler  │   │ Scan Manager│   │ Report Engine│       │
│   │(Playwright)│  │ (Processor) │   │ (Handlebars) │       │
│   └────┬─────┘   └──────┬──────┘   └──────┬───────┘       │
└────────┼────────────────┼──────────────────┼───────────────┘
         │                │                  │
         │        HTTP / JSON calls          │
    ┌────▼───────┐ ┌─────▼──────┐ ┌─────────▼────┐
    │  Context   │ │  Payload   │ │    Fuzzer     │
    │  Module    │ │  Generator │ │    Module     │
    │   :5001    │ │   :5002    │ │    :5003      │
    │  (Python)  │ │  (Python)  │ │   (Python)    │
    └────────────┘ └────────────┘ └───────────────┘
         │                │                │
         ▼                ▼                ▼
    DistilBERT       Payload Bank      Playwright
    AI Model        (24K+ CSV)       Headless Browser
```

### Communication Pattern

The project follows a **hub-and-spoke microservices** pattern:

- **NestJS Core** is the hub — it orchestrates everything. It owns the REST API, WebSocket gateway, job queue, crawling, and report generation.
- **Python microservices** are spokes — stateless, single-purpose services called via HTTP/JSON. They own the AI/ML inference, payload logic, and fuzzing.
- **Redis** serves as the BullMQ job queue backend. Scans are enqueued as jobs and processed asynchronously.
- **Dashboard** is a pure frontend consumer — it talks to Core via REST + WebSocket.

This separation was deliberate: NestJS excels at orchestration, routing, DI, and real-time communication. Python excels at ML/AI (PyTorch, Transformers, BeautifulSoup) and has the richer security tooling ecosystem.

---

## 3. Technology Stack & Rationale

### Backend — NestJS Core

| Package | Version | Why |
|---|---|---|
| `@nestjs/core` | 11.x | Enterprise-grade DI, interceptors, guards, exception filters. Production-grade for the orchestration layer. |
| `@nestjs/bullmq` | 11.x | First-class BullMQ integration for async job processing with retry semantics. Scans run as background jobs, not blocking API requests. |
| `@nestjs/websockets` + `socket.io` | 4.8 | Built-in NestJS adapter. Push scan progress/findings to the dashboard in real-time without polling. |
| `@nestjs/axios` | 4.x | HTTP client with DI injection for calling Python microservices. Configurable timeouts per request. |
| `@nestjs/swagger` | 11.x | Auto-generated API docs at `/docs` from decorators + DTOs. |
| `@nestjs/throttler` | 6.x | Rate limiting (100 requests/60s) at the API gateway level. |
| `playwright` | 1.52 | Headless Chromium for crawling JS-rendered SPAs. Chosen over Puppeteer for crawling because of its better multi-browser API and auto-wait mechanisms. |
| `puppeteer` | 24.x | Used specifically for HTML→PDF report generation (Puppeteer's PDF API is more mature). |
| `handlebars` | 4.7 | Template engine for HTML/PDF reports. Compiles once at startup, renders per-scan. |
| `helmet` | 8.x | Security headers middleware. |
| `class-validator` / `class-transformer` | — | DTO validation with decorators. Whitelist mode strips unknown properties. |

### Python Microservices

| Package | Version | Why |
|---|---|---|
| `fastapi` | 0.115 | Async-native, Pydantic-validated web framework. `POST /analyze`, `/generate`, `/test` endpoints with automatic OpenAPI docs. |
| `uvicorn` | 0.30 | ASGI server. Production-grade with `--workers` for multi-process. |
| `torch` | 2.4 | PyTorch runtime for the DistilBERT model. Powers the AI context classifier in the context module. |
| `transformers` | 4.44 | HuggingFace Transformers. Loads `distilbert-base-uncased` as the backbone, with custom classification heads. |
| `httpx` | 0.27 | Async HTTP client for probe injection (context module) and payload delivery (fuzzer). Browser-like headers, redirect following. |
| `beautifulsoup4` + `lxml` | 4.12 | DOM parsing for reflection position detection, context path building, and snippet extraction. |
| `playwright` | ≥1.48 | Headless Chromium in the fuzzer for confirming XSS execution via JS dialog interception. |
| `pandas` | 2.2 | Payload bank loading and dataset processing. |
| `pydantic` | 2.9 | Shared schema contracts across all three microservices (via `modules/shared/schemas.py`). |

### Frontend — Dashboard

| Package | Version | Why |
|---|---|---|
| `next` | 16.1.6 | React 19 + App Router. API route rewrites proxy `/api/*` → Core. `standalone` output mode for deployment. |
| `react` | 19.2 | The UI framework. Leverages hooks throughout. |
| `tailwindcss` | 4.x | Utility-first CSS. Dark theme (`zinc-900` palette) with emerald accents. Zero custom CSS files. |
| `socket.io-client` | 4.8 | WebSocket client matching Core's socket.io server. Auto-reconnection (10 attempts, 2s delay). |
| `lucide-react` | 0.475 | Icon library. Clean, consistent iconography. |

### Infrastructure

| Component | Version | Purpose |
|---|---|---|
| Redis | 7-alpine | BullMQ job queue backend + health check cache |
| PostgreSQL | 16-alpine | Persistent storage (TypeORM dependency present; currently in-memory for dev speed) |
| Docker Compose | — | 7-service orchestration with health checks, named volumes, restart policies |

---

## 4. The Scan Pipeline — 5 Phases

When a user submits a scan, here's exactly what happens:

### Phase 1: CRAWL

**Owner:** NestJS `CrawlerService` (TypeScript + Playwright)

```
User URL → Headless Chromium → BFS page traversal → Extract params + forms + scripts
```

- Launches headless Chromium and performs breadth-first crawling
- **Configurable depth** (1–10, default 3) — or **single-page mode** to skip crawling entirely
- Extracts: URL query parameters, form fields (action URL + input names), inline `<script>` contents
- **URL pattern deduplication:** replaces UUIDs, numeric IDs, and hashes in paths with placeholders to avoid recrawling structural duplicates (e.g., `/user/123` and `/user/456` → one target)
- **WAF fingerprinting:** checks response headers, body, and cookies against 8 signatures (Cloudflare, Akamai, AWS WAF, Sucuri, Imperva, ModSecurity, Wordfence, F5 BigIP) with a ≥50% confidence threshold
- **DOM sink pre-analysis:** scans inline scripts for 14 dangerous sink patterns cross-referenced with 8 tainted source patterns to identify DOM-XSS candidates early
- Hard caps: `CRAWLER_MAX_URLS=50`, `CRAWLER_TIMEOUT_MS=30000`

**Output:** `{ urls[], forms[], waf, domSinks[] }` → builds a `Map<url, params[]>` for subsequent phases.

---

### Phase 2: CONTEXT

**Owner:** Python Context Module (:5001)

```
For each URL+params → Inject probe → Analyze reflection → AI classify → Char fuzz
```

This is where the AI comes in. For each parameter on each URL:

1. **Probe injection:** Generates a unique MD5-based marker (prefix `rs0x`) per parameter. Sends HTTP request with marker injected. This is not a payload — it's a canary to see if and where the input appears in the response.

2. **Reflection analysis (3-layer consensus):**
   - **AI layer:** Fine-tuned DistilBERT classifies the HTML surrounding the reflection into one of 8 context classes (see [§7](#7-ai--ml-architecture)). Used when confidence ≥ 0.8.
   - **DOM layer:** BeautifulSoup parses the response, locates the marker in the DOM tree, and classifies based on parent elements and attributes.
   - **Regex layer:** Pattern matching as the final fallback.
   - Consensus: AI (if confident) → DOM → Regex.

3. **Character fuzzing:** Tests 15 special characters (`< > " ' / \ ( ) { } ; = \` & |`) to determine which are allowed through any server-side filtering. Uses batch requests first, falls back to individual char testing.

**Output:** `{ param → { reflects_in, allowed_chars, context_confidence, dom_context_path } }`

The `reflects_in` value is one of: `html_body`, `attribute`, `js_string`, `js_block`, `url`, `none`.

---

### Phase 3: PAYLOAD_GEN

**Owner:** Python Payload-Gen Module (:5002)

```
Context data → Select from bank → Mutate → Obfuscate (if WAF) → Rank → Top N
```

1. **Selection:** Maps the reflection context to a dataset label (e.g., `html_body` → `tag_injection`). Queries the 24K+ payload CSV bank filtered by matching context. Prioritizes payloads with auto-trigger mechanisms (no user interaction needed). Uses round-robin across parameters.

2. **Mutation (6 strategies):**
   - `swap_tag` — Swap `<img>` → 17 other tags (`svg`, `body`, `details`, `video`, etc.)
   - `swap_event` — Swap `onerror=` → 22 other event handlers (`onload`, `onfocus`, `onmouseover`, etc.)
   - `swap_js_func` — Swap `alert(1)` → 10 other functions (`confirm`, `prompt`, `fetch`, etc.)
   - `add_whitespace` — Inject tabs, newlines, null bytes between tag and attribute
   - `case_variation` — Random upper/lower case per character
   - `null_bytes` — Insert `%00` at strategic positions

3. **WAF-specific obfuscation (9 encoding strategies):**
   - Unicode escapes, hex encoding, HTML entities, URL encoding, double URL encoding, mixed case, whitespace padding, comment injection, concatenation splitting
   - Each of the 8 detected WAFs has a preferred strategy order (e.g., Cloudflare → unicode first, ModSecurity → comment injection first)

4. **Ranking (5-component weighted score):**
   - Context fit (0.35) — does the payload match the reflection context?
   - Complexity (0.25) — more sophisticated bypass techniques score higher
   - Length (0.15) — shorter payloads preferred (less likely to be truncated)
   - Technique (0.15) — event handlers > script tags > URI schemes
   - Char coverage (0.10) — uses more of the allowed chars from Phase 2

   Bonus: +0.15 for auto-trigger payloads (no click/hover needed)

**Output:** Top `maxPayloadsPerParam` (default 50) ranked payloads per parameter.

---

### Phase 4: FUZZ

**Owner:** Python Fuzzer Module (:5003)

```
Payloads → HTTP send → Reflection check → Browser verify → DOM scan
```

1. **HTTP injection:** Sends each payload via GET (query parameter injection) using `httpx` with semaphore-controlled concurrency (10 parallel requests). Browser-like headers to avoid bot detection.

2. **Reflection check:** For each response:
   - Exact string match of payload in response body
   - HTML-entity decoded match (e.g., `&lt;` → `<`)
   - Case-insensitive match
   - If reflected: classifies position via BeautifulSoup (`script`, `attribute`, `comment`, `style`, `html_body`) and extracts an 80-character context snippet

3. **Browser verification** (optional, enabled by default):
   - Opens reflected payloads in headless Chromium via Playwright
   - Intercepts JavaScript `dialog` events (alert, confirm, prompt) — this is the gold standard for XSS confirmation
   - Counts DOM mutations (injected `<img>`, `<svg>`, `<iframe>` elements with event handlers)
   - `DOMContentLoaded` wait + 1.5s networkidle cap + 300ms idle delay per page
   - Graceful degradation: if Playwright is unavailable, falls back to reflection-only marking

4. **DOM-XSS scanning:** Scans response bodies for dangerous DOM patterns:
   - 16 sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `insertAdjacentHTML`, `.src=`, `.href=`, `location.assign`, jQuery `.html()`, `.append()`, etc.
   - 12 tainted sources: `document.URL`, `document.referrer`, `location.hash`, `location.search`, `window.name`, `URLSearchParams`, `localStorage`, `postMessage`, etc.
   - Only reports findings where a tainted source flows into a dangerous sink (within ±5 lines)

**Output:** `{ results: [{ payload, reflected, executed, vuln, type, evidence }] }`

`evidence` includes: `response_code`, `reflection_position`, `browser_alert_triggered`, `sink`, `source`, `line`, `snippet`, `script_url`.

---

### Phase 5: REPORT

**Owner:** NestJS `ReportService`

```
Confirmed vulns → Dedup → Template render → HTML + JSON + PDF
```

- Deduplicates vulnerabilities using composite keys (`type|url|param` for reflected, `type|url|payload` for DOM XSS)
- **JSON report:** Raw structured data with all evidence fields
- **HTML report:** Handlebars template with severity-colored cards, "what happened" + "how to fix" per vuln, risk level summary, affected page list
- **PDF report:** Renders the HTML via Puppeteer's Chrome PDF API
- Risk level classification: Critical (any high+executed) → High → Medium → Low → None
- Reports stored at `core/reports/{scanId}.{html,json,pdf}`

---

## 5. NestJS Core (Orchestration API)

### Module Structure

```
AppModule
├── ConfigModule (global)
├── ThrottlerModule (100 req / 60s)
├── ScanModule
│   ├── ScanController — REST endpoints
│   ├── ScanService — in-memory scan storage (Map)
│   ├── ScanGateway — WebSocket event emitter
│   └── QueueModule
│       ├── ScanProducer — enqueues BullMQ jobs
│       └── ScanProcessor — THE HEART (~490 lines, runs the 5-phase pipeline)
├── CrawlerModule
│   ├── CrawlerService — Playwright BFS crawl
│   ├── WafDetectorService — 8 WAF fingerprints
│   └── DomAnalyzerService — URL/form param extraction, DOM sink analysis
├── ModulesBridgeModule
│   ├── ContextClientService → POST :5001/analyze
│   ├── PayloadClientService → POST :5002/generate
│   └── FuzzerClientService → POST :5003/test
├── ReportModule
│   ├── ReportService — HTML/JSON/PDF generation
│   └── ReportController — download/regenerate endpoints
├── HealthModule
│   └── HealthController — aggregated health for all services
└── AuthModule
    └── ApiKeyGuard — x-api-key / Bearer token (dev mode = open)
```

### Key API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/scan` | Create scan. Body: `{ url, options? }`. Returns scan object with ID. |
| `GET` | `/scan/:id` | Get scan status, progress, vulns. |
| `DELETE` | `/scan/:id` | Cancel a running scan. |
| `GET` | `/scans` | List all scans (paginated). |
| `GET` | `/scan/:id/report` | Get available report formats. |
| `GET` | `/reports/:id/download?format=` | Download report (html/json/pdf). |
| `GET` | `/health` | Aggregated health of all services. |

Swagger documentation auto-generated at `/docs`.

### Job Queue Semantics

- Queue: `scan-queue` backed by Redis
- Jobs: `run-scan` with `{ scanId }` payload
- Retry: 2 attempts with exponential backoff (2s base)
- Concurrency: `SCAN_WORKER_CONCURRENCY` (default 2) — parallel scan jobs
- Completed jobs cleaned after 100 accumulate

### Scan Modes

| Mode | Behavior | Use Case |
|---|---|---|
| **Single Page** (`singlePage: true`) | Skips crawling. Parses query params from the given URL only. | Quick check, specific page, minimal resource usage |
| **Full Crawl** (`singlePage: false`) | BFS crawls with configurable depth and discovers all pages/params. | Comprehensive site audit |

---

## 6. Python Microservices

All three microservices share:
- **FastAPI** with Pydantic request/response models
- **`/health` endpoint** for Docker/orchestration health checks
- **Shared schemas** in `modules/shared/schemas.py` ensuring contract compatibility
- **Shared constants** in `modules/shared/constants.py` (context types, labels, chars)

### Context Module (:5001)

| Endpoint | Purpose |
|---|---|
| `POST /analyze` | Accepts `{ url, params[], waf }`. Returns `{ param → ParamContext }` |
| `GET /health` | Service health |

Key files:
- `probe_injector.py` — MD5-based unique marker generation + async injection
- `reflection_analyzer.py` — Regex-based reflection position detection (6 context types)
- `html_parser.py` — BeautifulSoup DOM traversal, CSS-path building to reflection point
- `ai_classifier.py` — Loads DistilBERT checkpoint, runs inference, maps AI labels to context types
- `char_fuzzer.py` — Special character allowlist detection (batch + individual fallback)

### Payload-Gen Module (:5002)

| Endpoint | Purpose |
|---|---|
| `POST /generate` | Accepts `{ contexts, waf, max_payloads }`. Returns `{ payloads[] }` |
| `GET /health` | Service health |

Key files:
- `bank.py` — Loads 24K+ payloads from labeled CSV, indexes by context
- `selector.py` — Context-to-label mapping, char filtering, round-robin, auto-trigger priority
- `mutator.py` — 6 mutation strategies (tag/event/func swap, whitespace, case, null bytes)
- `obfuscator.py` — 9 encoding strategies with WAF-specific preference ordering
- `ranker.py` — 5-component weighted scoring with auto-trigger bonus

### Fuzzer Module (:5003)

| Endpoint | Purpose |
|---|---|
| `POST /test` | Accepts `{ url, payloads[], verify_execution, timeout }`. Returns `{ results[] }` |
| `GET /health` | Service health |

Key files:
- `http_sender.py` — Async HTTP delivery with semaphore concurrency (10), GET param injection
- `reflection_checker.py` — Multi-method match (exact, decoded, case-insensitive) + BS4 position classification
- `browser_verifier.py` — Playwright headless: dialog interception, DOM mutation counting
- `dom_xss_scanner.py` — Static analysis: 16 sinks × 12 sources, line-level findings

---

## 7. AI / ML Architecture

### Model: XSSClassifier

**Backbone:** `distilbert-base-uncased` (66M parameters, 6 transformer layers, 768 hidden size)

We chose DistilBERT specifically because:
- 40% smaller than BERT-base, 60% faster inference — critical for real-time scanning
- Retains 97% of BERT's language understanding
- Pretrained on English web text — already understands HTML/JS token patterns

**Architecture:**

```
Input: "<div class=\"user\" onclick=\"...{marker}...\">...</div>"
                          │
                    DistilBERT Encoder
                    (layers 0-1 frozen)
                          │
                    [CLS] token (768-d)
                    ┌─────┴──────┐
                    │            │
            Context Head    Severity Head
            768→256→ReLU    768→128→ReLU
            Dropout(0.3)    Dropout(0.3)
            256→8           128→3
                    │            │
              softmax(8)   softmax(3)
```

**Dual-head design:** A single forward pass produces both:
- **Context classification (8 classes):** `script_injection`, `event_handler`, `js_uri`, `tag_injection`, `template_injection`, `dom_sink`, `attribute_escape`, `generic`
- **Severity classification (3 classes):** `low`, `medium`, `high`

This is more efficient than running two separate models — the DistilBERT encoding is computed once and shared.

**Transfer learning strategy:**
- Embeddings + first 2 transformer layers are **frozen** (pretrained knowledge preserved)
- Remaining 4 layers + classification heads are fine-tuned on our XSS dataset
- This prevents catastrophic forgetting while allowing the model to specialize

### Training Configuration

| Hyperparameter | Value | Rationale |
|---|---|---|
| Epochs | 15 | With early stopping (patience=5) |
| Batch size | 32 | Balances GPU memory and gradient stability |
| Learning rate | 2×10⁻⁵ | Standard for BERT fine-tuning |
| Weight decay | 0.01 | L2 regularization |
| Warmup | 10% of steps | Linear warmup prevents early divergence |
| LR schedule | Linear warmup → cosine decay | Smooth convergence |
| Label smoothing | 0.1 | Reduces overconfidence |
| Loss weights | Context: 0.7, Severity: 0.3 | Context classification is the primary objective |
| Max sequence length | 128 tokens | HTML context snippets are short |
| Dropout | 0.3 | Regularization in classification heads |

**Training features:**
- Mixed-precision training (AMP with GradScaler) for 2× speed on GPU
- Dual weighted CrossEntropyLoss (context loss × 0.7 + severity loss × 0.3)
- Per-class validation metrics with breakdown
- Full checkpoint saving (model + optimizer + scheduler + scaler state)
- Metrics JSON logging per epoch

### Inference in Production

The trained model is loaded in `modules/context-module/ai_classifier.py`:
1. Loads checkpoint from `model/checkpoints/best.pt`
2. Runs on CPU (no GPU required for inference — DistilBERT is fast enough)
3. Returns context label + confidence score
4. **Confidence threshold ≥ 0.8** — below this, falls back to DOM/regex classification
5. Rule-based fallback if model file is missing (graceful degradation)

### Calibration

Post-training temperature scaling is applied via `tools/inference/calibration.py`:
- Optimizes a temperature parameter on the validation set using LBFGS
- Computes Expected Calibration Error (ECE)
- Saves calibration parameters to `outputs/temps.json`

---

## 8. Dataset Pipeline

The dataset is built through a 4-stage pipeline:

### Stage 1: Collection (`dataset/collect_payloads.py`)
- Aggregates payloads from public sources (PayloadsAllTheThings, XSSGAI, AwesomeXSS)
- Outputs: `processed/all_payloads_raw.csv`

### Stage 2: Labeling (`dataset/label_contexts.py`)
- Regex-based automatic labeling:
  - **Context** (8 classes): matches structural patterns in each payload
  - **Technique**: tag injection, event handler, JS URI, template, etc.
  - **Severity**: based on execution potential
- Outputs: `processed/payloads_labeled.csv`

### Stage 3: Synthetic Generation (`dataset/generate_synthetic.py`)
- Template-based expansion:
  - 5 context templates × multiple tags × events × functions × args × obfuscation variants
  - Ensures underrepresented classes have sufficient training samples
- Outputs: `processed/synthetic_payloads.csv`

### Stage 4: Finalization (`dataset/finalize_dataset.py`)
- Merges real + synthetic payloads
- Deduplication
- Validation: 16 XSS-specific regex patterns to verify payload quality
- **Stratified split** (70/15/15): ensures each context class is proportionally represented in train/val/test
- Outputs: `splits/train.csv`, `splits/val.csv`, `splits/test.csv`

---

## 9. Dashboard (Next.js Frontend)

### Stack
- **Next.js 16** with App Router
- **React 19** with hooks-based state management
- **Tailwind CSS v4** — dark zinc-900 palette, emerald-500 accents
- **Lucide React** for icons
- **Socket.io Client** for real-time updates

### API Integration

The dashboard proxies all API calls through Next.js rewrites:
```
/api/* → http://localhost:3000/* (Core API)
```
This avoids CORS issues and keeps the API URL internal.

### Pages

| Route | Page | Description |
|---|---|---|
| `/` | Dashboard | Stats cards (active/completed/total vulns), new scan form, scan table. Polls every 10s + WebSocket real-time. |
| `/scan/[id]` | Scan Detail | Live progress bar, phase indicator, real-time finding feed, cancel button, report downloads (HTML/JSON/PDF), full vulnerability list. |

### Components

| Component | Purpose |
|---|---|
| `NewScanForm` | URL input + scan mode toggle (Single Page / Full Crawl) + max payloads config |
| `ScanTable` | Sortable table with status badges, progress bars, vuln counts, timestamps |
| `VulnList` | Rich vulnerability cards: severity badge, type, page URL, payload code block, DOM XSS details (sink, source, line, snippet, script URL) |
| `ui.tsx` | Design system: `StatusBadge` (9 colors), `SeverityBadge` (5 levels), `ProgressBar`, `Card`, `StatCard` |

### Real-Time Hook

`useScanSocket` — a custom React hook that:
1. Connects to Core's WebSocket on mount
2. Registers callbacks for `scan:progress`, `scan:finding`, `scan:complete`, `scan:error`
3. Auto-reconnects (10 attempts, 2s delay)
4. Disconnects on unmount

---

## 10. Real-Time WebSocket Protocol

**Server:** NestJS `@WebSocketGateway()` at root namespace (`/`)  
**Client:** `socket.io-client` in the dashboard  
**Transport:** WebSocket with HTTP long-polling fallback

| Event | Direction | Payload | When |
|---|---|---|---|
| `scan:progress` | Server → Client | `{ scanId, phase, progress (0-100), message }` | Every pipeline step, typically 10-20 per scan |
| `scan:finding` | Server → Client | `{ scanId, vuln }` | Each confirmed vulnerability, as discovered |
| `scan:complete` | Server → Client | `{ scanId, summary, reportUrl }` | Scan finished |
| `scan:error` | Server → Client | `{ scanId, message }` | Scan failed |

The summary in `scan:complete` includes:
```json
{
  "totalParams": 15,
  "paramsTested": 12,
  "vulnsFound": 7,
  "durationMs": 45000
}
```

---

## 11. Exploitable Test Application

`exploitable/app.py` — a **750-line Flask application** called "Nexora" running on port 9090. It's an intentionally vulnerable web app designed to exercise every detection capability of RedSentinel.

### Vulnerability Coverage

| Category | Count | Examples |
|---|---|---|
| **Reflected XSS** | 16 endpoints | Body injection, attribute injection, JS string context, event handlers, href, meta refresh, textarea, comments, iframe, CSS, headers, JSONP, multi-param |
| **Stored XSS** | 4 endpoints | Comments (raw), guestbook (weak filter), profile (multi-field), notes (title+content) |
| **DOM-based XSS** | 12 endpoints | `innerHTML`, `document.write`, `eval`, `postMessage`, jQuery `.html()`, `location.replace`, `setTimeout(string)`, `cookie→innerHTML`, iframe `srcdoc`, `localStorage` |
| **Filter Bypass** | 9 endpoints | Blacklist, case-sensitive, double-encode, angle-only, quote-escape, recursive removal, WAF simulation, tag-strip, comment removal |
| **Mutation XSS** | 6 endpoints | innerHTML sanitizer bypass, AngularJS template injection, SVG, prototype pollution, srcdoc re-parse, dangerouslySetInnerHTML |

Total: **42+ distinct vulnerability endpoints**, each with different filtering, context, and escape characteristics.

---

## 12. Infrastructure & Deployment

### Docker Compose — Production (7 services)

```yaml
redis       → redis:7-alpine           :6379   (health: redis-cli ping)
postgres    → postgres:16-alpine        :5432   (health: pg_isready)
context     → ./modules (Python)        :5001   (health: curl /health)
payload-gen → ./modules (Python)        :5002   (health: curl /health)
fuzzer      → ./modules (Python)        :5003   (health: curl /health)
core        → ./core (NestJS)           :3000   (health: curl /health)
dashboard   → ./dashboard (Next.js)     :8080   (health: curl /)
```

Named volumes: `pgdata` (PostgreSQL data), `reports` (generated reports)

### Docker Compose — Development

Same services but with:
- Source code volume mounts for hot-reload
- `--reload` flag for Python (uvicorn auto-restart)
- `npm run start:dev` for NestJS (watch mode)
- `next dev` for dashboard (HMR)
- Debug port 9229 exposed for NestJS `--inspect`

### Local Development (tmux)

`start.sh` launches a tmux session with 5 windows:

| Window | Service | Port |
|---|---|---|
| python | Context + Payload-Gen + Fuzzer (3 panes) | 5001, 5002, 5003 |
| core | NestJS API | 3000 |
| dashboard | Next.js | 8080 |
| exploit | Vulnerable test site | 9090 |
| shell | Free terminal with info card | — |

### Setup Script

`setup.sh` (207 lines) automates the complete environment setup:
1. System packages (build-essential, curl, etc.)
2. Node.js 20+ (via nvm or system)
3. Python 3.10+ with venv
4. PostgreSQL (creates role `rs`, database `redsentinel`)
5. Redis server
6. Python dependencies (`pip install -r requirements.txt`)
7. Playwright browser binaries
8. Puppeteer Chromium binary
9. Node.js dependencies (`npm install` for core + dashboard)
10. Environment files (`.env` creation)
11. NestJS production build

---

## 13. Testing Strategy

### Unit Tests (NestJS — Jest)

```bash
cd core && npm run test        # unit tests
cd core && npm run test:e2e    # end-to-end API tests
cd core && npm run test:cov    # with coverage
```

Test files: `*.spec.ts` co-located with source files.

### Integration Tests (Python — pytest)

```bash
pytest tests/test_integration.py
```

`tests/test_integration.py` (405 lines) validates cross-module contract compatibility:
1. Context module output schema validation
2. Payload-gen accepts context module output
3. Fuzzer accepts payload-gen output
4. Full pipeline data flow: context → payload-gen → fuzzer
5. Pydantic schema contract validation

Uses `httpx.ASGITransport` for in-process testing (no network). Heavy dependencies (AI model, browser) are mocked.

### Module Tests

Each Python module has its own test file (`test_context.py`, `test_payload_gen.py`, `test_fuzzer.py`).

### E2E Smoke Test

`scripts/e2e-smoke.sh` (210 lines):
- Service readiness polling with timeout
- Health endpoint validation
- Swagger docs accessibility
- Full scan lifecycle (create → poll → list → report)
- Supports `--up` flag to auto-start Docker Compose

### Coverage

`coverage.sh` runs everything:
- Jest unit + e2e with coverage for NestJS
- pytest-cov for all Python modules + integration tests

---

## 14. Configuration Reference

### Environment Variables

```bash
# ── Core API ──────────────────────────────────────────────
NODE_ENV=development|production
PORT=3000                          # API server port
API_KEY_SECRET=<secret>            # Omit for dev mode (all requests pass)

# ── Python Microservice URLs ──────────────────────────────
CONTEXT_URL=http://localhost:5001
PAYLOAD_GEN_URL=http://localhost:5002
FUZZER_URL=http://localhost:5003

# ── Infrastructure ────────────────────────────────────────
REDIS_HOST=localhost
REDIS_PORT=6379
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel

# ── Scan Defaults ─────────────────────────────────────────
SCAN_WORKER_CONCURRENCY=2         # Parallel scan jobs
CRAWLER_MAX_URLS=50               # Max pages to crawl
CRAWLER_TIMEOUT_MS=30000          # Crawl timeout
HTTP_TIMEOUT=120000               # Module bridge HTTP timeout

# ── Dashboard ─────────────────────────────────────────────
NEXT_PUBLIC_API_URL=http://localhost:3000
```

### Scan Options (API)

```json
{
  "url": "https://target.com",
  "options": {
    "singlePage": false,           // true = skip crawling
    "depth": 3,                    // crawl depth (1-10)
    "maxParams": 100,              // max params to discover (1-500)
    "maxPayloadsPerParam": 50,     // payloads per parameter (1-200)
    "verifyExecution": true,       // headless browser verification
    "wafBypass": true,             // enable WAF-specific obfuscation
    "timeout": 60000,              // per-request timeout in ms (5000-300000)
    "reportFormat": ["html", "json", "pdf"]
  }
}
```

---

## 15. Design Decisions & Trade-offs

| Decision | What We Chose | Why | Trade-off |
|---|---|---|---|
| **Hybrid TS + Python** | NestJS for orchestration, Python for AI/security | Best-of-both: NestJS DI/WS/queue + Python ML ecosystem | HTTP overhead between services (~1-5ms per call) |
| **DistilBERT over BERT-base** | `distilbert-base-uncased` | 40% smaller, 60% faster, retains 97% accuracy | Slightly less nuanced understanding of complex contexts |
| **Dual-head model** | Single encoder, two classification heads | One forward pass for both context + severity | Coupled training — poor context classification affects severity |
| **In-memory scan storage** | `Map<string, ScanRecord>` | Fast iteration, no DB setup required | Data lost on restart; TypeORM dep ready for migration |
| **BullMQ over direct execution** | Redis-backed job queue | Retry semantics, concurrency control, job persistence | Redis dependency; slight latency for job pickup |
| **Playwright for crawling** | Headless Chromium | Handles JS-rendered SPAs, consistent API | ~200MB browser binary; 500ms+ startup time |
| **Puppeteer for PDF** | Separate from Playwright | More mature PDF API, better page.pdf() | Two browser engines in the project |
| **Reflection-first pipeline** | Only fuzz reflected parameters | Avoids wasting requests on non-injectable params | Misses stored XSS on first touch (separate endpoints handle stored) |
| **3-layer context consensus** | AI → DOM → Regex | Graceful degradation; works without the model | Added complexity in context module |
| **Single-page mode** | Optional crawl skip | Fast checks with minimal resources | User must know exact URL to test |
| **Extended fuzzer timeout** | `req.timeout + 90s, min 120s` | Browser verification is slow per-payload | Long-running requests tie up connections |
| **WAF-specific strategies** | Per-WAF encoding preferences | Different WAFs have different weak points | Requires maintenance as WAFs update |

---

## Appendix: Repository Structure

```
majorproject/
├── ai/training/           # Training pipeline: config, dataset, model, train, evaluate
├── core/                  # NestJS orchestration API
│   ├── src/
│   │   ├── auth/          # API key guard
│   │   ├── common/        # Interfaces, exceptions
│   │   ├── crawler/       # Playwright crawler, WAF detector, DOM analyzer
│   │   ├── health/        # Health aggregation
│   │   ├── modules-bridge/ # HTTP clients to Python microservices
│   │   ├── queue/         # BullMQ processor + producer
│   │   ├── report/        # Handlebars templates, HTML/JSON/PDF generation
│   │   └── scan/          # REST controller, service, WebSocket gateway, DTOs
│   ├── reports/           # Generated report files
│   └── test/              # E2E tests
├── dashboard/             # Next.js 16 frontend
│   ├── app/               # App Router pages
│   ├── components/        # React components
│   ├── hooks/             # WebSocket hook
│   └── lib/               # API client, types
├── dataset/               # 4-stage dataset pipeline
│   ├── processed/         # Intermediate CSVs
│   └── splits/            # Final train/val/test CSVs
├── docs/                  # Documentation
├── exploitable/           # Intentionally vulnerable Flask app (42+ endpoints)
├── model/                 # XSSClassifier, tokenizer, checkpoints
├── modules/               # Python microservices
│   ├── context-module/    # :5001 — reflection analysis + AI classification
│   ├── fuzzer-module/     # :5003 — HTTP fuzzing + browser verification
│   ├── payload-gen-module/ # :5002 — payload selection, mutation, obfuscation
│   └── shared/            # Pydantic schemas, constants
├── scripts/               # E2E smoke test
├── tests/                 # Cross-module integration tests
├── tools/                 # Inference CLI, calibration, export
│   ├── export/            # ONNX/TorchScript export
│   └── inference/         # CLI inference, inspector, calibration
├── docker-compose.yml     # Production (7 services)
├── docker-compose.dev.yml # Development (hot-reload)
├── setup.sh               # Automated environment setup
├── start.sh               # tmux session launcher
├── stop.sh                # Kill everything
├── coverage.sh            # Unified test coverage
└── requirements.txt       # Shared Python dependencies
```
