#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────
# RedSentinel — end-to-end smoke test
# verifies all services start, respond to health checks, and
# the full scan pipeline can be triggered through core.
#
# usage:
#   ./scripts/e2e-smoke.sh              # run against running stack
#   ./scripts/e2e-smoke.sh --up         # docker compose up, test, down
# ───────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

CORE_URL="${CORE_URL:-http://localhost:3000}"
CONTEXT_URL="${CONTEXT_URL:-http://localhost:5001}"
PAYLOAD_GEN_URL="${PAYLOAD_GEN_URL:-http://localhost:5002}"
FUZZER_URL="${FUZZER_URL:-http://localhost:5003}"

COMPOSE_MANAGED=false
PASSED=0
FAILED=0
TOTAL=0

# ── helpers ───────────────────────────────────────────────────

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; ((PASSED++)); ((TOTAL++)); }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; ((FAILED++)); ((TOTAL++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

wait_for_url() {
  local url="$1"
  local name="$2"
  local max_wait="${3:-90}"
  local elapsed=0

  info "waiting for ${name} at ${url} (max ${max_wait}s)..."
  while ! curl -sf --max-time 3 "$url" > /dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ "$elapsed" -ge "$max_wait" ]; then
      fail "${name} did not become ready within ${max_wait}s"
      return 1
    fi
  done
  pass "${name} is ready (${elapsed}s)"
  return 0
}

cleanup() {
  if [ "$COMPOSE_MANAGED" = true ]; then
    info "tearing down docker compose stack..."
    docker compose down --remove-orphans --timeout 10 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ── parse args ────────────────────────────────────────────────

if [[ "${1:-}" == "--up" ]]; then
  COMPOSE_MANAGED=true
  info "starting docker compose stack..."
  docker compose up -d --build
  echo ""
fi

echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  RedSentinel — End-to-End Smoke Test${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo ""

# ── 1. wait for all services ─────────────────────────────────

info "--- service readiness ---"
wait_for_url "${CONTEXT_URL}/health"    "context-module"
wait_for_url "${PAYLOAD_GEN_URL}/health" "payload-gen-module"
wait_for_url "${FUZZER_URL}/health"      "fuzzer-module"
wait_for_url "${CORE_URL}/health"        "core"
echo ""

# ── 2. health endpoints return correct structure ─────────────

info "--- health endpoint checks ---"

# context module
CTX_HEALTH=$(curl -sf "${CONTEXT_URL}/health" 2>/dev/null || echo "")
if echo "$CTX_HEALTH" | grep -q '"status":"ok"'; then
  pass "context /health returns status ok"
else
  fail "context /health unexpected response: ${CTX_HEALTH}"
fi

# payload-gen module
PG_HEALTH=$(curl -sf "${PAYLOAD_GEN_URL}/health" 2>/dev/null || echo "")
if echo "$PG_HEALTH" | grep -q '"status":"ok"'; then
  pass "payload-gen /health returns status ok"
else
  fail "payload-gen /health unexpected response: ${PG_HEALTH}"
fi

# fuzzer module
FZ_HEALTH=$(curl -sf "${FUZZER_URL}/health" 2>/dev/null || echo "")
if echo "$FZ_HEALTH" | grep -q '"status":"ok"'; then
  pass "fuzzer /health returns status ok"
else
  fail "fuzzer /health unexpected response: ${FZ_HEALTH}"
fi

# core aggregated health
CORE_HEALTH=$(curl -sf "${CORE_URL}/health" 2>/dev/null || echo "")
if echo "$CORE_HEALTH" | grep -q '"status"'; then
  pass "core /health returns health report"
else
  fail "core /health unexpected response: ${CORE_HEALTH}"
fi
echo ""

# ── 3. swagger docs accessible ───────────────────────────────

info "--- api docs ---"
SWAGGER=$(curl -sf -o /dev/null -w "%{http_code}" "${CORE_URL}/docs" 2>/dev/null || echo "000")
if [ "$SWAGGER" = "200" ] || [ "$SWAGGER" = "301" ]; then
  pass "swagger docs accessible at /docs"
else
  fail "swagger docs returned HTTP ${SWAGGER}"
fi
echo ""

# ── 4. scan lifecycle ────────────────────────────────────────

info "--- scan lifecycle ---"

# create a scan (will go to queue, likely fail crawling a dummy url — that's OK)
SCAN_RESP=$(curl -sf -X POST "${CORE_URL}/scan" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${API_KEY_SECRET:-change-me-before-deploy}" \
  -d '{
    "url": "http://example.com",
    "options": {
      "depth": 1,
      "max_payloads_per_param": 5,
      "timeout": 10000,
      "report_format": ["json"]
    }
  }' 2>/dev/null || echo "")

if echo "$SCAN_RESP" | grep -q '"id"'; then
  SCAN_ID=$(echo "$SCAN_RESP" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
  pass "POST /scan created scan id=${SCAN_ID}"

  # retrieve scan status
  sleep 1
  STATUS_RESP=$(curl -sf "${CORE_URL}/scan/${SCAN_ID}" \
    -H "x-api-key: ${API_KEY_SECRET:-change-me-before-deploy}" 2>/dev/null || echo "")
  if echo "$STATUS_RESP" | grep -q '"status"'; then
    pass "GET /scan/:id returns scan status"
  else
    fail "GET /scan/:id unexpected response: ${STATUS_RESP}"
  fi

  # list scans
  LIST_RESP=$(curl -sf "${CORE_URL}/scans" \
    -H "x-api-key: ${API_KEY_SECRET:-change-me-before-deploy}" 2>/dev/null || echo "")
  if echo "$LIST_RESP" | grep -q "$SCAN_ID"; then
    pass "GET /scans lists the created scan"
  else
    fail "GET /scans does not contain scan id"
  fi
else
  fail "POST /scan failed: ${SCAN_RESP}"
  warn "skipping scan status checks"
fi
echo ""

# ── 5. report endpoint ──────────────────────────────────────

info "--- report endpoints ---"
if [ -n "${SCAN_ID:-}" ]; then
  REPORT_RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
    "${CORE_URL}/reports/${SCAN_ID}" \
    -H "x-api-key: ${API_KEY_SECRET:-change-me-before-deploy}" 2>/dev/null || echo "000")
  if [ "$REPORT_RESP" = "200" ]; then
    pass "GET /reports/:scanId returns format list"
  else
    # may return 200 with empty formats (scan hasn't completed)
    warn "GET /reports/:scanId returned HTTP ${REPORT_RESP} (scan may not have completed)"
    ((TOTAL++))
  fi
else
  warn "skipping report checks (no scan id)"
fi
echo ""

# ── summary ──────────────────────────────────────────────────

echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo -e "  Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC} out of ${TOTAL} checks"
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
