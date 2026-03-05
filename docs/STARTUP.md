# RedSentinel — Complete Startup Guide

Everything you need to get RedSentinel running on a brand-new machine from zero.

---

## Table of Contents

1. [What Is RedSentinel?](#1-what-is-redsentinel)
2. [System Requirements](#2-system-requirements)
3. [Install System Packages](#3-install-system-packages)
4. [Install Node.js 20+](#4-install-nodejs-20)
5. [Install Python 3.10+](#5-install-python-310)
6. [Clone the Repository](#6-clone-the-repository)
7. [Python Virtual Environment & Dependencies](#7-python-virtual-environment--dependencies)
8. [Install Playwright Browsers](#8-install-playwright-browsers)
9. [PostgreSQL — Create Role & Database](#9-postgresql--create-role--database)
10. [Redis](#10-redis)
11. [Node.js Dependencies (Core & Dashboard)](#11-nodejs-dependencies-core--dashboard)
12. [Install Puppeteer Chrome (PDF Reports)](#12-install-puppeteer-chrome-pdf-reports)
13. [Environment Variables](#13-environment-variables)
14. [Build NestJS & Run Migrations](#14-build-nestjs--run-migrations)
15. [Dataset — Collection & Processing](#15-dataset--collection--processing)
16. [AI Model Training](#16-ai-model-training)
17. [XGBoost Ranker Training](#17-xgboost-ranker-training)
18. [Start All Services](#18-start-all-services)
19. [Verify Everything Is Running](#19-verify-everything-is-running)
20. [Run Your First Scan](#20-run-your-first-scan)
21. [Port Reference](#21-port-reference)
22. [Troubleshooting](#22-troubleshooting)

---

## 1. What Is RedSentinel?

RedSentinel is an AI-powered XSS vulnerability scanner. It consists of:

| Service | Tech | Port |
| --------- | ------ | ------ |
| **Core API** | NestJS (TypeScript) + BullMQ | 3000 |
| **Dashboard** | Next.js (TypeScript) | 8080 |
| **Context Module** | Python / FastAPI + DistilBERT | 5001 |
| **Payload Generator** | Python / FastAPI + XGBoost | 5002 |
| **Fuzzer** | Python / FastAPI + Playwright | 5003 |
| **Vulnerable Test Site** | Python / Flask | 9090 |
| **Redis** | Job queue backend | 6379 |
| **PostgreSQL** | Scan result storage | 5432 |

> **Shortcut:** If you only want Docker, skip to the [Docker section](#option-c--docker-compose-easiest) at the end.

---

## 2. System Requirements

| Requirement | Minimum | Notes |
| ------------ | --------- | ------- |
| OS | Ubuntu 22.04 / Debian 12 | Tested. Other Debian-based distros work. |
| CPU | 4 cores | 8+ recommended for training |
| RAM | 8 GB | 16 GB recommended; DistilBERT needs ~4 GB during training |
| Disk | 10 GB free | ~3 GB models + datasets + node_modules |
| GPU | Optional | CUDA-capable GPU speeds up training ~10×; CPU works |

---

## 3. Install System Packages

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
  git \
  curl \
  wget \
  lsof \
  tmux \
  build-essential \
  redis-server \
  postgresql \
  postgresql-contrib \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev \
  libpq-dev \
  ca-certificates \
  gnupg
```

---

## 4. Install Node.js 20+

The project requires Node.js **v20 or higher**.

### Option A — NodeSource (recommended)

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### Option B — nvm (lets you manage multiple Node versions)

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash

# Reload shell
source ~/.bashrc   # or ~/.zshrc if you use zsh

# Install and use Node 20
nvm install 20
nvm use 20
nvm alias default 20
```

### Verify

```bash
node -v   # should print v20.x.x or higher
npm -v    # should print 10.x.x or higher
```

---

## 5. Install Python 3.10+

Ubuntu 22.04 ships with Python 3.10 by default. Check your version:

```bash
python3 --version
```

If below 3.10, add the deadsnakes PPA:

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev
# Then use python3.11 instead of python3 throughout this guide
```

---

## 6. Clone the Repository

```bash
git clone <your-repo-url> red-sentinel
cd red-sentinel
```

> Replace `<your-repo-url>` with your actual GitHub/GitLab repository URL.

All further commands in this guide assume you are inside the **`red-sentinel/`** root.

---

## 7. Python Virtual Environment & Dependencies

All Python microservices share **one virtualenv** at the project root.

```bash
# Create the virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip setuptools wheel

# Install all Python dependencies (FastAPI, PyTorch, Transformers, XGBoost, Playwright, Flask…)
pip install -r requirements.txt

# Deactivate when done
deactivate
```

> **Note on PyTorch:** `requirements.txt` installs `torch==2.4.0`. If you have a CUDA GPU, install the CUDA-enabled build instead:
>
> ```bash
> pip install torch==2.4.0 --index-url https://download.pytorch.org/whl/cu121
> ```
>
> Check your CUDA version with `nvidia-smi` first.

---

## 8. Install Playwright Browsers

The Fuzzer module uses Playwright to launch a headless Chromium browser for XSS verification.

```bash
source venv/bin/activate

python -m playwright install chromium
python -m playwright install-deps chromium

deactivate
```

> `install-deps` installs the system-level OS libraries Chromium needs (fonts, shared libraries). It may ask for `sudo`.

---

## 9. PostgreSQL — Create Role & Database

```bash
# Make sure PostgreSQL is running
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create the database role and database
sudo -u postgres psql -c "CREATE ROLE rs WITH LOGIN PASSWORD 'rs';"
sudo -u postgres psql -c "CREATE DATABASE redsentinel OWNER rs;"

# Verify the connection works
psql -h localhost -U rs -d redsentinel -c "SELECT version();"
# Enter password: rs
```

If you get a `peer authentication` error, edit the PostgreSQL `pg_hba.conf`
to allow `md5` auth for local connections:

```bash
# Find pg_hba.conf (path varies by version)
sudo find /etc/postgresql -name pg_hba.conf

# Edit it and change the local lines to use md5 instead of peer
sudo nano /etc/postgresql/14/main/pg_hba.conf
```

Change:

```bash
local   all   all   peer
```

to:

```bash
local   all   all   md5
```

Then restart:

```bash
sudo systemctl restart postgresql
```

---

## 10. Redis

Redis should have been installed in step 3. Start and enable it:

```bash
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Verify
redis-cli ping
# Expected output: PONG
```

---

## 11. Node.js Dependencies (Core & Dashboard)

```bash
# Install Core API dependencies (NestJS)
cd core
npm install
cd ..

# Install Dashboard dependencies (Next.js)
cd dashboard
npm install
cd ..
```

---

## 12. Install Puppeteer Chrome (PDF Reports)

The Core API uses Puppeteer to generate PDF reports.

```bash
cd core
npx puppeteer browsers install chrome
cd ..
```

---

## 13. Environment Variables

```bash
# Copy the example file
cp .env.example .env

# Open it and update for local development
nano .env
```

Change the Docker service hostnames to `localhost`:

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

# ── auth ─────────────────────────────────────────────────────
API_KEY_SECRET=change-me-in-prod

# ── scan defaults ────────────────────────────────────────────
DEFAULT_SCAN_DEPTH=3
DEFAULT_MAX_PAYLOADS=50
DEFAULT_TIMEOUT_MS=60000

# ── http client ──────────────────────────────────────────────
HTTP_TIMEOUT=30000
```

> The `.env` file is read by both the NestJS core and the `start.sh` script.

---

## 14. Build NestJS & Run Migrations

```bash
# Build the NestJS application
cd core
npx nest build

# Apply database migrations (creates all tables)
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel npm run migration:run

cd ..
```

To see which migrations have been applied:

```bash
cd core
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel npm run migration:show
cd ..
```

---

## 15. Dataset — Collection & Processing

> **Skip this section if the `dataset/splits/` directory already contains `train.csv`, `val.csv`, and `test.csv`.** Those files are the only thing the AI training needs. If they exist, jump to [Section 16](#16-ai-model-training).

The dataset is built from three open-source XSS payload repositories. Follow these steps in order.

### 15a. Clone raw data sources

```bash
mkdir -p dataset/raw
cd dataset/raw

git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
git clone https://github.com/AnonKryptiQuz/XSSGAI.git
git clone https://github.com/s0md3v/AwesomeXSS.git

cd ../..
```

### 15b. Collect and deduplicate payloads

```bash
source venv/bin/activate
cd dataset

python collect_payloads.py
# Output: processed/all_payloads_raw.csv
```

### 15c. Collect PortSwigger examples (optional)

```bash
python collect_portswigger.py
# Output: appends to processed/
```

### 15d. Generate synthetic payloads

```bash
python generate_synthetic.py
# Augments the dataset with mutation-based synthetic samples
```

### 15e. Label context types

```bash
python label_contexts.py
# Assigns context labels (script_injection, event_handler, dom_sink, etc.)
```

### 15f. Finalize and split dataset

```bash
python finalize_dataset.py
# Output: splits/train.csv, splits/val.csv, splits/test.csv
```

```bash
deactivate
cd ..
```

---

## 16. AI Model Training

> **Skip this section if `model/checkpoints/best.pt` already exists.** The context module will load it automatically. If it is missing, the context module falls back to rule-based classification (still functional, just less accurate).

The AI model is a dual-head DistilBERT classifier that predicts:

- **Context type** (8 classes): `script_injection`, `event_handler`, `js_uri`, `tag_injection`, `template_injection`, `dom_sink`, `attribute_escape`, `generic`
- **Severity** (3 classes): `low`, `medium`, `high`

### Prerequisites check

```bash
# Make sure splits exist
ls dataset/splits/
# Expected: train.csv  val.csv  test.csv  train_payloads.txt  val_payloads.txt  test_payloads.txt
```

### Train the model

```bash
source venv/bin/activate
cd ai/training

# Default training (15 epochs, batch=32, lr=2e-5)
python train.py

# Or customize hyperparameters
python train.py --epochs 20 --lr 3e-5 --batch_size 64

# Resume from the latest checkpoint (if interrupted)
python train.py --resume
```

**What happens during training:**

1. Downloads `distilbert-base-uncased` from HuggingFace (~260 MB, first run only)
2. Loads `dataset/splits/train.csv` and `val.csv`
3. Trains for up to 15 epochs with early stopping (patience=3)
4. Saves checkpoints to `model/checkpoints/epoch_N.pt`
5. Saves the best validation checkpoint to `model/checkpoints/best.pt`
6. Logs metrics to `model/checkpoints/logs/train_<timestamp>.log`

**Expected training time:**

| Hardware | Time per epoch | Total (15 epochs) |
| ---------- | --------------- | ------------------- |
| CPU only | ~20–40 min | ~5–10 hours |
| NVIDIA GPU (CUDA) | ~2–5 min | ~30–75 min |

### Evaluate the model

```bash
python evaluate.py
# Prints accuracy, F1, confusion matrix on test.csv
# Saves results to model/checkpoints/test_results.json
```

```bash
deactivate
cd ../..
```

---

## 17. XGBoost Ranker Training

> **Skip this section if `model/ranker/xgboost_ranker.json` already exists.** If it is missing, the payload-gen module scores payloads with a simple heuristic instead.

The XGBoost ranker scores candidate payloads by predicted effectiveness.

```bash
source venv/bin/activate
cd ai/training

python generate_ranker_data.py
# Generates ranker_training/ feature CSVs from the payload splits

python train_ranker.py
# Trains the XGBoost model
# Output: model/ranker/xgboost_ranker.json
#         model/ranker/ranker_metrics.json

deactivate
cd ../..
```

---

## 18. Start All Services

### Option A — Automated (tmux, recommended)

The `start.sh` script launches everything — Redis, Postgres, all Python modules, NestJS, Dashboard, and the vulnerable test site — each in a labeled tmux window.

```bash
# First time only
chmod +x setup.sh start.sh stop.sh

# Start everything
./start.sh
```

This creates a tmux session called `rs` with these windows:

| tmux window | Contents |
| ------------- | ---------- |
| `python` | 3 panes: Context :5001, Payload-Gen :5002, Fuzzer :5003 |
| `core` | NestJS API :3000 |
| `dashboard` | Next.js :8080 |
| `exploit` | Vulnerable test site :9090 |
| `shell` | Free terminal |

Navigate tmux windows: `Ctrl+b` then the window number (0–4).
Navigate panes: `Ctrl+b` then arrow keys.
Detach without stopping: `Ctrl+b d`.
Re-attach: `tmux attach -t rs`.

To stop everything:

```bash
./stop.sh
```

---

### Option B — Manual (one terminal per service)

Open 7 terminals (or tmux panes). Run in this exact order:

**Terminal 1 — Redis**

```bash
redis-server
```

**Terminal 2 — Context Module (port 5001)**

```bash
source venv/bin/activate
cd modules/context-module
python app.py
```

**Terminal 3 — Payload Generator (port 5002)**

```bash
source venv/bin/activate
cd modules/payload-gen-module
python app.py
```

**Terminal 4 — Fuzzer (port 5003)**

```bash
source venv/bin/activate
cd modules/fuzzer-module
python app.py
```

**Terminal 5 — Core API (port 3000)**

```bash
cd core
# Development mode (auto-reload)
npm run start:dev

# OR production mode
node dist/main.js
```

**Terminal 6 — Dashboard (port 8080)**

```bash
cd dashboard
npx next dev -p 8080
```

**Terminal 7 — Vulnerable Test Site (port 9090, optional)**

```bash
source venv/bin/activate
cd exploitable
python app.py
```

---

### Option C — Docker Compose (easiest)

Requires Docker and Docker Compose installed:

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Copy env file (keep Docker hostnames as-is)
cp .env.example .env

# Start all services (builds images on first run)
docker compose up -d

# Follow logs
docker compose logs -f

# Stop everything
docker compose down
```

---

## 19. Verify Everything Is Running

Run these health checks after startup:

```bash
# Redis
redis-cli ping
# → PONG

# PostgreSQL
pg_isready -h localhost -U rs -d redsentinel
# → localhost:5432 - accepting connections

# Context Module
curl http://localhost:5001/health
# → {"status":"ok"}

# Payload Generator
curl http://localhost:5002/health
# → {"status":"ok"}

# Fuzzer
curl http://localhost:5003/health
# → {"status":"ok"}

# Core API
curl http://localhost:3000/health
# → {"status":"ok",...}

# Swagger UI (all API docs)
# Open browser: http://localhost:3000/docs

# Dashboard
# Open browser: http://localhost:8080
```

---

## 20. Run Your First Scan

With the vulnerable test site running on `:9090`:

```bash
# Start a scan
curl -X POST http://localhost:3000/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "http://localhost:9090"}'
```

Response:

```json
{"id": "some-uuid-here", "status": "QUEUED", ...}
```

```bash
# Poll for progress
curl http://localhost:3000/scan/<SCAN_ID>

# When status is DONE, download the report
curl "http://localhost:3000/reports/<SCAN_ID>/download?format=html" -o report.html
curl "http://localhost:3000/reports/<SCAN_ID>/download?format=json" -o report.json
curl "http://localhost:3000/reports/<SCAN_ID>/download?format=pdf"  -o report.pdf

# Or view reports in the dashboard
# Open browser: http://localhost:8080
```

---

## 21. Port Reference

| Service | Port | URL |
| --------- | ------ | ----- |
| PostgreSQL | 5432 | — |
| Redis | 6379 | — |
| Context Analyzer | 5001 | <http://localhost:5001/health> |
| Payload Generator | 5002 | <http://localhost:5002/health> |
| Fuzzer | 5003 | <http://localhost:5003/health> |
| Core API | 3000 | <http://localhost:3000/docs> |
| Dashboard | 8080 | <http://localhost:8080> |
| Vulnerable Test Site | 9090 | <http://localhost:9090> |

---

## 22. Troubleshooting

### "Address already in use" on a port

```bash
# Find and kill the process using the port (e.g. 3000)
kill $(lsof -t -i:3000)
```

### PostgreSQL auth failure (`role "rs" does not exist`)

```bash
sudo -u postgres psql -c "CREATE ROLE rs WITH LOGIN PASSWORD 'rs';"
sudo -u postgres psql -c "CREATE DATABASE redsentinel OWNER rs;"
```

### Playwright / Chromium not found

```bash
source venv/bin/activate
python -m playwright install chromium
python -m playwright install-deps chromium
```

### Context module says "AI model not loaded"

The model checkpoint is missing. Either:

- Train it: `cd ai/training && python train.py` (see Section 16)
- OR ignore it — the module falls back to rule-based classification automatically

### PyTorch `CUDA out of memory` during training

Reduce batch size:

```bash
cd ai/training
python train.py --batch_size 16
```

### `npm install` fails in `core/` or `dashboard/`

Make sure Node.js ≥ 20 is active:

```bash
node -v      # must be v20+
npm cache clean --force
npm install
```

### NestJS migrations fail

Make sure PostgreSQL is running and the `rs` role exists (see Section 9), then:

```bash
cd core
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel npm run migration:run
```

### Redis "version too old" warning from BullMQ

```sh
It is highly recommended to use a minimum Redis version of 6.2.0
```

This is a warning, not an error. Everything still works. To upgrade:

```bash
sudo apt install -y redis-server   # installs the latest available
```

### `venv` not activating (`command not found`)

```bash
sudo apt install -y python3-venv
python3 -m venv venv
source venv/bin/activate
```

---

## Quick Reference — Full Setup in Order

```bash
# 1. System packages
sudo apt update && sudo apt install -y git curl tmux build-essential \
  redis-server postgresql postgresql-contrib \
  python3 python3-pip python3-venv python3-dev libpq-dev

# 2. Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# 3. Clone
git clone <your-repo-url> red-sentinel && cd red-sentinel

# 4. Python venv
python3 -m venv venv && source venv/bin/activate
pip install --upgrade pip && pip install -r requirements.txt
python -m playwright install chromium && python -m playwright install-deps chromium
deactivate

# 5. PostgreSQL
sudo systemctl start postgresql
sudo -u postgres psql -c "CREATE ROLE rs WITH LOGIN PASSWORD 'rs';"
sudo -u postgres psql -c "CREATE DATABASE redsentinel OWNER rs;"

# 6. Redis
sudo systemctl start redis-server

# 7. Node deps
cd core && npm install && cd ..
cd dashboard && npm install && cd ..

# 8. Puppeteer
cd core && npx puppeteer browsers install chrome && cd ..

# 9. Environment
cp .env.example .env
# Edit .env: change all Docker hostnames to localhost

# 10. Build & migrate
cd core && npx nest build
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel npm run migration:run
cd ..

# 11. (Optional) Train AI model — skip if model/checkpoints/best.pt exists
source venv/bin/activate
cd ai/training && python train.py && cd ../..
deactivate

# 12. Start
./start.sh
```

---

> *RedSentinel — AI-powered XSS vulnerability scanner*
