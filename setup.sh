#!/usr/bin/env bash
# ── Red Sentinel — First-time setup ─────────────────────────
# Installs all system packages, runtimes, and project dependencies.
# Run once after cloning the repo.
#
# Usage:  ./setup.sh
# ──────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
LOG="$ROOT/.setup.log"

ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$1"; }
info() { printf '  \033[1;34m…\033[0m %s\n' "$1"; }
warn() { printf '  \033[1;33m!\033[0m %s\n' "$1"; }
fail() { printf '  \033[1;31m✗\033[0m %s\n' "$1" >&2; exit 1; }

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║        Red Sentinel — Setup              ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# ══════════════════════════════════════════════════════════════
#  1. System packages
# ══════════════════════════════════════════════════════════════
info "Checking system packages..."

PKGS_NEEDED=()

command -v redis-server &>/dev/null || PKGS_NEEDED+=(redis-server)
command -v psql         &>/dev/null || PKGS_NEEDED+=(postgresql postgresql-contrib)
command -v tmux         &>/dev/null || PKGS_NEEDED+=(tmux)
command -v curl         &>/dev/null || PKGS_NEEDED+=(curl)
command -v lsof         &>/dev/null || PKGS_NEEDED+=(lsof)
command -v git          &>/dev/null || PKGS_NEEDED+=(git)

# python3-venv is needed for virtual environments
python3 -m venv --help &>/dev/null 2>&1 || PKGS_NEEDED+=(python3-venv)

if [[ ${#PKGS_NEEDED[@]} -gt 0 ]]; then
  info "Installing: ${PKGS_NEEDED[*]}"
  sudo apt-get update -qq >> "$LOG" 2>&1
  sudo apt-get install -y -qq "${PKGS_NEEDED[@]}" >> "$LOG" 2>&1
  ok "System packages installed"
else
  ok "System packages already present"
fi

# ══════════════════════════════════════════════════════════════
#  2. Node.js (v20+)
# ══════════════════════════════════════════════════════════════
info "Checking Node.js..."

if command -v node &>/dev/null; then
  NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
  if (( NODE_VER >= 20 )); then
    ok "Node.js $(node -v) found"
  else
    warn "Node.js $(node -v) is too old — need v20+"
    info "Install Node 20: https://nodejs.org or use nvm"
    fail "Node.js >= 20 required"
  fi
else
  fail "Node.js not found — install v20+ from https://nodejs.org"
fi

# ══════════════════════════════════════════════════════════════
#  3. Python 3.10+
# ══════════════════════════════════════════════════════════════
info "Checking Python..."

if command -v python3 &>/dev/null; then
  PY_VER=$(python3 -c 'import sys; print(sys.version_info.minor)')
  if (( PY_VER >= 10 )); then
    ok "Python $(python3 --version) found"
  else
    fail "Python 3.10+ required (found 3.$PY_VER)"
  fi
else
  fail "python3 not found"
fi

# Ensure pip
if ! python3 -m pip --version &>/dev/null; then
  info "Installing pip..."
  sudo apt-get install -y -qq python3-pip >> "$LOG" 2>&1
fi
ok "pip available"

# ══════════════════════════════════════════════════════════════
#  4. PostgreSQL — create role & database
# ══════════════════════════════════════════════════════════════
info "Setting up PostgreSQL..."

# Start postgres if not running
if ! pg_isready -h localhost -q 2>/dev/null; then
  sudo pg_ctlcluster 14 main start 2>/dev/null \
    || sudo systemctl start postgresql 2>/dev/null \
    || warn "Could not start PostgreSQL — start it manually"
fi

# Create role + database (idempotent)
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='rs'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE ROLE rs WITH LOGIN PASSWORD 'rs';" >> "$LOG" 2>&1

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='redsentinel'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE DATABASE redsentinel OWNER rs;" >> "$LOG" 2>&1

ok "PostgreSQL: role=rs, db=redsentinel"

# ══════════════════════════════════════════════════════════════
#  5. Redis — just verify
# ══════════════════════════════════════════════════════════════
info "Checking Redis..."
if command -v redis-server &>/dev/null; then
  ok "Redis $(redis-server --version | grep -oP 'v=\K[^ ]+')"
else
  fail "redis-server not found"
fi

# ══════════════════════════════════════════════════════════════
#  6. Python virtual environment (single venv for whole project)
# ══════════════════════════════════════════════════════════════
VENV="$ROOT/venv"

info "Creating project venv..."
if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install -q --upgrade pip >> "$LOG" 2>&1
ok "venv created at $VENV"

info "Installing Python deps from requirements.txt..."
"$VENV/bin/pip" install -q --no-cache-dir -r "$ROOT/requirements.txt" >> "$LOG" 2>&1
ok "All Python deps installed"

# ══════════════════════════════════════════════════════════════
#  7. Playwright browsers (for fuzzer)
# ══════════════════════════════════════════════════════════════
info "Installing Playwright browsers (Chromium)..."
"$VENV/bin/python" -m playwright install chromium >> "$LOG" 2>&1
"$VENV/bin/python" -m playwright install-deps chromium >> "$LOG" 2>&1 || true
ok "Playwright Chromium installed"

# Also install for Puppeteer (used by report PDF generation)
info "Installing Puppeteer browser..."
cd "$ROOT/core"
npx puppeteer browsers install chrome >> "$LOG" 2>&1 || true
cd "$ROOT"
ok "Puppeteer Chrome installed"

# ══════════════════════════════════════════════════════════════
#  8. Node dependencies — core
# ══════════════════════════════════════════════════════════════
info "Installing Node packages for core (NestJS)..."
cd "$ROOT/core" && npm install --silent >> "$LOG" 2>&1
ok "core/node_modules"

# ══════════════════════════════════════════════════════════════
#  9. Node dependencies — dashboard
# ══════════════════════════════════════════════════════════════
info "Installing Node packages for dashboard (Next.js)..."
cd "$ROOT/dashboard" && npm install --silent >> "$LOG" 2>&1
ok "dashboard/node_modules"

# ══════════════════════════════════════════════════════════════
#  10. Environment file
# ══════════════════════════════════════════════════════════════
cd "$ROOT"
if [[ ! -f .env ]]; then
  info "Creating .env from .env.example..."
  cp .env.example .env
  # Patch for native (non-Docker) mode
  sed -i 's|http://context:|http://localhost:|'       .env
  sed -i 's|http://payload-gen:|http://localhost:|'    .env
  sed -i 's|http://fuzzer:|http://localhost:|'         .env
  sed -i 's|redis|localhost|'                          .env
  sed -i 's|@postgres:|@localhost:|'                   .env
  sed -i 's|REDIS_HOST=.*|REDIS_HOST=localhost|'       .env
  ok ".env created (patched for localhost)"
else
  ok ".env already exists"
fi

# ══════════════════════════════════════════════════════════════
#  11. Build NestJS core
# ══════════════════════════════════════════════════════════════
info "Building NestJS core..."
cd "$ROOT/core" && npx nest build >> "$LOG" 2>&1
ok "core built (dist/)"

# ══════════════════════════════════════════════════════════════
#  12. Run database migrations
# ══════════════════════════════════════════════════════════════
info "Running database migrations..."

# Ensure Postgres is ready before running migrations
for i in $(seq 1 10); do
  pg_isready -h localhost -q 2>/dev/null && break
  sleep 1
done

if pg_isready -h localhost -q 2>/dev/null; then
  cd "$ROOT/core"
  DATABASE_URL="postgresql://rs:rs@localhost:5432/redsentinel" \
    npm run migration:run >> "$LOG" 2>&1
  ok "Migrations applied"
else
  warn "PostgreSQL not reachable — migrations will run on first app start (migrationsRun: true)"
fi

# ══════════════════════════════════════════════════════════════
#  Done
# ══════════════════════════════════════════════════════════════
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║          Setup complete!                 ║"
echo "  ╠══════════════════════════════════════════╣"
echo "  ║  Run all:     ./start.sh                 ║"
echo "  ║  Stop all:    ./stop.sh                  ║"
echo "  ║  Manual run:  see RUN.md                 ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  Full install log: $LOG"
echo ""
