#!/usr/bin/env bash
# ── Red Sentinel — tmux launcher ─────────────────────────────
# Starts all dev servers in a single tmux session with labeled windows.
#
#   Window 0 "python"    : context :5001 | payload-gen :5002 | fuzzer :5003
#   Window 1 "core"      : NestJS API :3000
#   Window 2 "dashboard" : Next.js   :8080
#   Window 3 "exploit"   : Vulnerable test site :9090
#   Window 4 "shell"     : Free terminal
#
# Usage:  ./start.sh          (starts & attaches)
#         ./start.sh --detach (starts in background)
# ──────────────────────────────────────────────────────────────
set -euo pipefail

SESSION="rs"
ROOT="$(cd "$(dirname "$0")" && pwd)"
DETACH=false
[[ "${1:-}" == "--detach" || "${1:-}" == "-d" ]] && DETACH=true

# ── Pre-flight checks ────────────────────────────────────────
for cmd in tmux node python3; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "✗ Required command '$cmd' not found. Install it first." >&2
    exit 1
  fi
done

# ── Ensure PostgreSQL & Redis are running ─────────────────────
if ! pg_isready -h localhost -q 2>/dev/null; then
  echo "  … Starting PostgreSQL..."
  sudo pg_ctlcluster 14 main start 2>/dev/null \
    || sudo systemctl start postgresql 2>/dev/null \
    || echo "  ! Could not start PostgreSQL — start it manually"
fi
if ! redis-cli ping &>/dev/null 2>&1; then
  echo "  … Starting Redis..."
  redis-server --daemonize yes 2>/dev/null || true
fi

# ── Kill previous session ────────────────────────────────────
tmux kill-session -t "$SESSION" 2>/dev/null || true
sleep 0.3

# ── Env vars ─────────────────────────────────────────────────
ENV_COMMON=(
  "REDIS_HOST=localhost"
  "REDIS_PORT=6379"
  "DATA_DIR=$ROOT/dataset"
  "CONTEXT_URL=http://localhost:5001"
  "PAYLOAD_GEN_URL=http://localhost:5002"
  "FUZZER_URL=http://localhost:5003"
  "DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel"
  "NODE_ENV=development"
)

EXPORT_LINE=""
for ev in "${ENV_COMMON[@]}"; do
  EXPORT_LINE+="export $ev; "
done

# ══════════════════════════════════════════════════════════════
#  Window 0 — python  (3 vertical panes)
# ══════════════════════════════════════════════════════════════
tmux new-session -d -s "$SESSION" -n "python" -c "$ROOT/modules/context-module" -x 220 -y 50

# Pane 0 — Context module :5001
tmux send-keys -t "$SESSION:python.0" \
  "printf '\\033[1;33m── Context Module :5001 ──\\033[0m\\n'; \
   $EXPORT_LINE \
   source $ROOT/venv/bin/activate && cd $ROOT/modules/context-module && python app.py" C-m

# Pane 1 — Payload-gen :5002
tmux split-window -v -t "$SESSION:python" -c "$ROOT/modules/payload-gen-module"
tmux send-keys -t "$SESSION:python.1" \
  "printf '\\033[1;33m── Payload-Gen :5002 ──\\033[0m\\n'; \
   $EXPORT_LINE \
   source $ROOT/venv/bin/activate && cd $ROOT/modules/payload-gen-module && python app.py" C-m

# Pane 2 — Fuzzer :5003
tmux split-window -v -t "$SESSION:python" -c "$ROOT/modules/fuzzer-module"
tmux send-keys -t "$SESSION:python.2" \
  "printf '\\033[1;33m── Fuzzer Module :5003 ──\\033[0m\\n'; \
   $EXPORT_LINE \
   source $ROOT/venv/bin/activate && cd $ROOT/modules/fuzzer-module && python app.py" C-m

tmux select-layout -t "$SESSION:python" even-vertical

# ══════════════════════════════════════════════════════════════
#  Window 1 — core  (NestJS :3000)
# ══════════════════════════════════════════════════════════════
tmux new-window -t "$SESSION" -n "core" -c "$ROOT/core"
tmux send-keys -t "$SESSION:core" \
  "printf '\\033[1;32m── NestJS Core API :3000 ──\\033[0m\\n'; \
   $EXPORT_LINE \
   export PORT=3000; \
   npm run start:dev" C-m

# ══════════════════════════════════════════════════════════════
#  Window 2 — dashboard  (Next.js :8080)
# ══════════════════════════════════════════════════════════════
tmux new-window -t "$SESSION" -n "dashboard" -c "$ROOT/dashboard"
tmux send-keys -t "$SESSION:dashboard" \
  "printf '\\033[1;35m── Dashboard (Next.js) :8080 ──\\033[0m\\n'; \
   export NEXT_PUBLIC_API_URL=http://localhost:3000; \
   npx next dev -p 8080" C-m

# ══════════════════════════════════════════════════════════════
#  Window 3 — exploit  (Vulnerable test site :9090)
# ══════════════════════════════════════════════════════════════
tmux new-window -t "$SESSION" -n "exploit" -c "$ROOT/exploitable"
tmux send-keys -t "$SESSION:exploit" \
  "printf '\\033[1;31m── Exploitable Test Site :9090 ──\\033[0m\\n'; \
   source $ROOT/venv/bin/activate && python app.py" C-m

# ══════════════════════════════════════════════════════════════
#  Window 4 — shell  (free terminal)
# ══════════════════════════════════════════════════════════════
tmux new-window -t "$SESSION" -n "shell" -c "$ROOT"
tmux send-keys -t "$SESSION:shell" "$EXPORT_LINE" C-m
tmux send-keys -t "$SESSION:shell" "clear" C-m
tmux send-keys -t "$SESSION:shell" "cat <<'EOF'

  ╔══════════════════════════════════════════════════════╗
  ║              Red Sentinel — Running                  ║
  ╠══════════════════════════════════════════════════════╣
  ║  Context API     http://localhost:5001               ║
  ║  Payload-Gen     http://localhost:5002               ║
  ║  Fuzzer          http://localhost:5003               ║
  ║  Core API        http://localhost:3000               ║
  ║  Dashboard       http://localhost:8080               ║
  ║  Vuln Test Site  http://localhost:9090               ║
  ╠══════════════════════════════════════════════════════╣
  ║  Swagger Docs    http://localhost:3000/docs          ║
  ╠══════════════════════════════════════════════════════╣
  ║  tmux shortcuts:                                     ║
  ║    Ctrl+B n/p   → next / prev window                 ║
  ║    Ctrl+B 0-4   → jump to window                     ║
  ║    Ctrl+B d     → detach (services keep running)     ║
  ║    Ctrl+B o     → switch pane (in python window)     ║
  ╚══════════════════════════════════════════════════════╝

  Quick scan:
    curl -X POST http://localhost:3000/scan \\
      -H 'Content-Type: application/json' \\
      -d '{\"url\":\"http://localhost:9090\"}'

EOF" C-m

# ── Focus on shell window and attach ─────────────────────────
tmux select-window -t "$SESSION:shell"

if $DETACH; then
  echo "Red Sentinel started in tmux session '$SESSION' (detached)."
  echo "Attach with:  tmux attach -t $SESSION"
else
  exec tmux attach -t "$SESSION"
fi
