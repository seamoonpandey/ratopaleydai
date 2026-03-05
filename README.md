# RedSentinel

AI-powered XSS vulnerability scanner with real-time dashboard.

RedSentinel combines a NestJS orchestration core with Python AI microservices
to crawl, analyze, generate payloads, fuzz, and report cross-site scripting
vulnerabilities — all coordinated through a job queue with live WebSocket
progress streaming.

---

## Architecture

```markdown
┌─────────────────┐      REST / WebSocket
│    Dashboard     │ ◄──────────────────────┐
│  (Next.js :8080) │                        │
└─────────────────┘                        │
                                            │
┌──────────────────────────────────────────────────────┐
│              Core — NestJS  :3000                      │
│  REST API │ WebSocket Gateway │ BullMQ Job Queue       │
│                    │                                  │
│         ┌──────────┼──────────┐                       │
│    Crawler    Scan Manager   Report Engine             │
└─────┬─────────────┬───────────────┬──────────────────┘
      │             │               │  HTTP / JSON
┌─────▼─────┐ ┌────▼─────┐ ┌──────▼──────┐
│  Context   │ │ Payload  │ │   Fuzzer    │
│   :5001    │ │ Gen :5002│ │   :5003     │
│ (Python)   │ │ (Python) │ │  (Python)   │
└────────────┘ └──────────┘ └─────────────┘
```

**Scan Pipeline** — 5 sequential phases per scan:

1. **CRAWL** — Spider target, discover params, forms, DOM sinks, detect WAF
2. **CONTEXT** — Probe injection, reflection analysis, AI context classification
3. **PAYLOAD-GEN** — Select from 24K bank, mutate, obfuscate, rank
4. **FUZZ** — HTTP injection, reflection check, headless browser verification
5. **REPORT** — Generate HTML / PDF / JSON reports

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 22+ (for local dev)
- Python 3.11+ (for local dev)

### Run with Docker Compose

```bash
# copy env file and adjust secrets
cp .env.example .env

# start all services
docker compose up -d

# verify health
curl http://localhost:3000/health
curl http://localhost:8080
```

### Run in Development Mode

```bash
# start with live reload for all services
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

### Run Locally (without Docker)

```bash
# terminal 1 — redis
docker run -d -p 6379:6379 redis:7-alpine

# terminal 2 — context module
cd modules/context-module && pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 5001

# terminal 3 — payload-gen module
cd modules/payload-gen-module && pip install -r requirements.txt
DATASET_DIR=../../dataset/splits uvicorn app:app --host 0.0.0.0 --port 5002

# terminal 4 — fuzzer module
cd modules/fuzzer-module && pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 5003

# terminal 5 — core
cd core && npm install && npm run start:dev

# terminal 6 — dashboard
cd dashboard && npm install && npm run dev
```

---

## API

All endpoints require `x-api-key` header (or `Authorization: Bearer <key>`)
unless `API_KEY_SECRET` is unset (dev mode = open).

| Method   | Endpoint             | Description                    |
|----------|----------------------|--------------------------------|
| `POST`   | `/scan`              | Start a new scan               |
| `GET`    | `/scan/:id`          | Get scan status + vulns        |
| `DELETE` | `/scan/:id`          | Cancel an active scan          |
| `GET`    | `/scans`             | List scans (paginated)         |
| `GET`    | `/scan/:id/report`   | Get report URL                 |
| `GET`    | `/health`            | Aggregated health check        |

**WebSocket Events** (socket.io on `:3000`):

- `scan:progress` — phase, progress %, message
- `scan:finding` — real-time vulnerability discovery
- `scan:complete` — scan finished with summary
- `scan:error` — scan failed

**Swagger docs**: `http://localhost:3000/api`

---

## Project Structure

```bash
red-sentinel/
├── core/                    # NestJS orchestration (TypeScript)
│   └── src/
│       ├── scan/            # scan CRUD, controller, gateway
│       ├── queue/           # BullMQ processor + producer
│       ├── report/          # HTML/PDF/JSON report engine
│       ├── modules-bridge/  # HTTP clients for Python services
│       ├── auth/            # API key guard
│       ├── health/          # aggregated health checks
│       └── common/          # interfaces, exceptions, utils
├── modules/
│   ├── context-module/      # Python — reflection + AI classification
│   ├── payload-gen-module/  # Python — select, mutate, obfuscate, rank
│   ├── fuzzer-module/       # Python — send, verify, DOM scan
│   └── shared/              # shared pydantic schemas
├── dashboard/               # Next.js real-time dashboard
│   └── app/
│       ├── page.tsx         # home — stats, new scan, scan table
│       └── scan/[id]/       # detail — live progress, vulns, reports
├── dataset/                 # 24K labeled XSS payload dataset
├── model/                   # DistilBERT training + checkpoints
├── ai/                      # AI model artifacts
├── tools/                   # inference, export utilities
├── scripts/                 # e2e smoke test
├── docker-compose.yml       # production compose
├── docker-compose.dev.yml   # dev override (hot reload)
└── docs/ARCHITECTURE.md     # full architecture document
```

---

## Testing

### NestJS Core

```bash
cd core

# unit tests (66 tests)
npm test

# integration & e2e tests (31 tests)
npm run test:e2e

# unit tests with coverage
npm run test:cov

# watch mode
npm run test:watch
```

### Python Modules

```bash
# from project root with venv active — run all unit tests together
pytest modules/ -v

# or individually
cd modules/context-module && python -m pytest test_context.py -v
cd modules/payload-gen-module && python -m pytest test_payload_gen.py -v
cd modules/fuzzer-module && python -m pytest test_fuzzer.py -v
```

### Integration Tests

```bash
# python cross-module integration (6 tests)
pytest tests/test_integration.py -v

# nestjs integration — scan lifecycle, pipeline, websocket
cd core && npm run test:e2e
```

### End-to-End Smoke Test

```bash
# requires running docker compose stack
./scripts/e2e-smoke.sh

# or start stack, test, and tear down:
./scripts/e2e-smoke.sh --up
```

---

## Environment Variables

| Variable                | Default                    | Description                        |
|-------------------------|----------------------------|------------------------------------|
| `NODE_ENV`              | `production`               | Node environment                   |
| `PORT`                  | `3000`                     | Core API port                      |
| `CORS_ORIGIN`           | `*`                        | Allowed CORS origins               |
| `CONTEXT_URL`           | `http://localhost:5001`    | Context module URL                 |
| `PAYLOAD_GEN_URL`       | `http://localhost:5002`    | Payload-gen module URL             |
| `FUZZER_URL`            | `http://localhost:5003`    | Fuzzer module URL                  |
| `REDIS_HOST`            | `localhost`                | Redis host                         |
| `REDIS_PORT`            | `6379`                     | Redis port                         |
| `DATABASE_URL`          | —                          | PostgreSQL connection string       |
| `API_KEY_SECRET`        | —                          | API key (unset = open/dev mode)    |
| `DEFAULT_SCAN_DEPTH`    | `3`                        | Default crawl depth                |
| `DEFAULT_MAX_PAYLOADS`  | `50`                       | Default payloads per param         |
| `NEXT_PUBLIC_API_URL`   | `http://localhost:3000`    | Dashboard → Core API URL           |
| `NEXT_PUBLIC_WS_URL`    | —                          | Dashboard → Core WebSocket URL     |

---

## Tech Stack

| Layer            | Technology                  |
|------------------|-----------------------------|
| Core / API       | NestJS (TypeScript)         |
| Real-time        | Socket.io (WebSocket)       |
| Job Queue        | BullMQ + Redis              |
| AI / Security    | Python 3.11 + FastAPI       |
| AI Model         | DistilBERT (HuggingFace)    |
| Frontend         | Next.js 16 + Tailwind CSS 4 |
| Containers       | Docker Compose              |
| Database         | PostgreSQL 16               |
| Reports          | Handlebars + Puppeteer PDF  |

---

## License

MIT
