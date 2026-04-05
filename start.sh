#!/usr/bin/env bash
# ============================================================
#  Virex Security System — Cross-platform startup script
#  Usage: bash start.sh [api|dashboard|all]
# ============================================================

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'

log()  { echo -e "${GREEN}[Virex]${NC} $1"; }
warn() { echo -e "${YELLOW}[Virex]${NC} $1"; }
err()  { echo -e "${RED}[Virex]${NC} $1" >&2; }

# Check .env
if [ ! -f .env ]; then
    err ".env not found. Run:  cp .env.example .env  then fill in the values."
    exit 1
fi

# Check Python
if ! command -v python3 &>/dev/null; then
    err "python3 not found. Install Python 3.10+."
    exit 1
fi

# Check pip deps
if ! python3 -c "import flask" 2>/dev/null; then
    warn "Dependencies not installed. Running: pip install -r requirements.txt"
    pip install -r requirements.txt
fi

MODE="${1:-all}"

case "$MODE" in
    api)
        log "Starting API server..."
        python3 run_api.py
        ;;
    dashboard)
        log "Starting Dashboard server..."
        python3 run_dashboard.py
        ;;
    all)
        log "Starting API + Dashboard..."
        python3 run_api.py &
        API_PID=$!
        sleep 2
        python3 run_dashboard.py &
        DASH_PID=$!
        log "API PID: $API_PID  |  Dashboard PID: $DASH_PID"
        log "API:       http://localhost:5000"
        log "Dashboard: http://localhost:8070"
        wait $API_PID $DASH_PID
        ;;
    *)
        err "Usage: $0 [api|dashboard|all]"
        exit 1
        ;;
esac
