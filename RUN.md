# Red Sentinel — Run Guide

Everything you need to set up and run the project from scratch on a fresh Ubuntu/Debian machine.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| **Node.js** | 20+ | `curl -fsSL https://deb.nodesource.com/setup_20.x \| sudo -E bash - && sudo apt install -y nodejs` |
| **Python** | 3.10+ | `sudo apt install -y python3 python3-pip` |
| **PostgreSQL** | 14+ | `sudo apt install -y postgresql postgresql-contrib` |
| **Redis** | 6.0+ | `sudo apt install -y redis-server` |
| **tmux** | any | `sudo apt install -y tmux` |
| **Git** | any | `sudo apt install -y git` |

---

## Quick Start (automated)

```bash
# 1. First-time setup — installs everything
./setup.sh

# 2. Start all services in tmux
./start.sh

# 3. Stop everything
./stop.sh
```

That's it. The rest of this document is for **running things manually one by one**.

---

## Step-by-Step Manual Setup

### 1. Clone the repo

```bash
git clone <your-repo-url> red-sentinel
cd red-sentinel
```

### 2. System packages

```bash
sudo apt update
sudo apt install -y redis-server postgresql postgresql-contrib tmux curl lsof
```

### 3. PostgreSQL — create role and database

```bash
# Start Postgres if not running
sudo systemctl start postgresql

# Create the role and database
sudo -u postgres psql -c "CREATE ROLE rs WITH LOGIN PASSWORD 'rs';"
sudo -u postgres psql -c "CREATE DATABASE redsentinel OWNER rs;"

# Verify
psql -h localhost -U rs -d redsentinel -c "SELECT 1;"
# (password: rs)
```

### 4. Python dependencies

All Python services share a **single virtual environment** at the project root:

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
```

### 5. Playwright browser

The fuzzer uses Playwright to launch a real browser for XSS verification:

```bash
source venv/bin/activate
python -m playwright install chromium
python -m playwright install-deps chromium
deactivate
```

### 6. Node.js dependencies

```bash
# Core API (NestJS)
cd core
npm install

# Dashboard (Next.js)
cd ../dashboard
npm install

cd ..
```

### 7. Puppeteer browser (for PDF reports)

```bash
cd core
npx puppeteer browsers install chrome
cd ..
```

### 8. Build the NestJS core

```bash
cd core
npx nest build
cd ..
```

### 8b. Run database migrations

Migrations apply the schema to the PostgreSQL database. This step is
idempotent — safe to run multiple times.

```bash
cd core
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel npm run migration:run
cd ..
```

To see which migrations have been applied:
```bash
cd core && DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel npm run migration:show
```

> **Note:** The NestJS app is configured with `migrationsRun: true`, so
> pending migrations also run automatically when the server starts.
> Running them manually here catches any SQL errors before the first boot.

### 9. Environment variables

```bash
# Create .env from the example
cp .env.example .env
```

Edit `.env` and change the Docker hostnames to `localhost`:

```dotenv
# ── core (nestjs) ────────────────────────────────────────────
NODE_ENV=development
PORT=3000
CORS_ORIGIN=*

# ── python microservice urls ─────────────────────────────────
CONTEXT_URL=http://localhost:5001
PAYLOAD_GEN_URL=http://localhost:5002
FUZZER_URL=http://localhost:5003

# ── redis ────────────────────────────────────────────────────
REDIS_HOST=localhost
REDIS_PORT=6379

# ── postgres ─────────────────────────────────────────────────
POSTGRES_USER=rs
POSTGRES_PASSWORD=rs
POSTGRES_DB=redsentinel
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel
```

---

## Running Services Manually (one by one)

Open **6 separate terminals** (or use tmux panes). Start them in this order:

### Terminal 1 — Redis

```bash
redis-server
```

Verify: `redis-cli ping` → should print `PONG`

### Terminal 2 — Context Module (port 5001)

```bash
source venv/bin/activate
cd modules/context-module
python app.py
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:5001
```

Verify: `curl http://localhost:5001/health`

### Terminal 3 — Payload Generator (port 5002)

```bash
source venv/bin/activate
cd modules/payload-gen-module
python app.py
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:5002
```

Verify: `curl http://localhost:5002/health`

### Terminal 4 — Fuzzer (port 5003)

```bash
source venv/bin/activate
cd modules/fuzzer-module
python app.py
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:5003
```

Verify: `curl http://localhost:5003/health`

### Terminal 5 — Core API (port 3000)

```bash
cd core

# Option A: dev mode (auto-reload on changes)
npm run start:dev

# Option B: production mode
npx nest build && node dist/main.js
```

You should see:
```
[Nest] LOG [NestApplication] Nest application successfully started
```

Verify: `curl http://localhost:3000/docs` (Swagger UI)

### Terminal 6 — Dashboard (port 8080)

```bash
cd dashboard
npx next dev -p 8080
```

Open: http://localhost:8080

### Terminal 7 (optional) — Vulnerable Test Site (port 9090)

```bash
source venv/bin/activate
cd exploitable
python app.py
```

Open: http://localhost:9090

---

## Running a Scan

Once all services are up:

```bash
# Start a scan against the vulnerable test site
curl -X POST http://localhost:3000/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "http://localhost:9090"}'
```

This returns a scan ID. Check progress:

```bash
curl http://localhost:3000/scan/<SCAN_ID>
```

When status is `DONE`, view the report:
- **HTML**: http://localhost:3000/reports/`<SCAN_ID>`/download?format=html
- **JSON**: http://localhost:3000/reports/`<SCAN_ID>`/download?format=json
- **PDF**: http://localhost:3000/reports/`<SCAN_ID>`/download?format=pdf

Or regenerate it:
```bash
curl "http://localhost:3000/reports/<SCAN_ID>/regenerate?formats=html,json,pdf"
```

---

## Port Summary

| Service | Port | Tech |
|---------|------|------|
| Redis | 6379 | Redis 6+ |
| PostgreSQL | 5432 | PostgreSQL 14+ |
| Context Analyzer | 5001 | Python / FastAPI |
| Payload Generator | 5002 | Python / FastAPI |
| Fuzzer | 5003 | Python / FastAPI / Playwright |
| Core API | 3000 | Node.js / NestJS |
| Dashboard | 8080 | Node.js / Next.js |
| Vuln Test Site | 9090 | Python / Flask |

---

## Troubleshooting

### "Address already in use"
Something is already running on that port. Kill it:
```bash
# Find and kill process on a port (e.g. 3000)
kill $(lsof -t -i:3000)
```

### Redis version warning
```
It is highly recommended to use a minimum Redis version of 6.2.0
```
This is a BullMQ warning — it still works fine with Redis 6.0. Ignore it or upgrade Redis.

### Playwright browser not found
```bash
python3 -m playwright install chromium
python3 -m playwright install-deps chromium
```

### Context module says "ai model not loaded"
The AI model checkpoint (`model/checkpoints/best.pt`) may be missing. The context module falls back to rule-based classification automatically — this is fine for testing.

To train the model:
```bash
cd ai/training
python3 train.py
```

### PostgreSQL auth failure
Make sure the `rs` role exists:
```bash
sudo -u postgres psql -c "CREATE ROLE rs WITH LOGIN PASSWORD 'rs';"
sudo -u postgres psql -c "CREATE DATABASE redsentinel OWNER rs;"
```

---

## Scripts Reference

| Script | Description |
|--------|-------------|
| `./setup.sh` | One-time install of all packages, deps, databases, browsers, migrations |
| `./start.sh` | Launch everything in a tmux session (`rs`) |
| `./start.sh --detach` | Same but don't attach to tmux |
| `./stop.sh` | Kill the tmux session and orphaned processes |
| `cd core && npm run migration:run` | Apply pending database migrations |
| `cd core && npm run migration:revert` | Roll back the last migration |
| `cd core && npm run migration:show` | List all migrations and their status |
| `cd core && npm run migration:generate -- src/migrations/Name` | Auto-generate a migration from entity changes |
