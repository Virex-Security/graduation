#!/usr/bin/env bash
echo "=========================================="
echo "  🛡️ API Security System - Master Launcher"
echo "=========================================="

cd "$(dirname "$0")/.."

if [ -f "./.venv/bin/activate" ]; then
    source ./.venv/bin/activate
fi

echo "[1/3] Starting Security Dashboard on port 8070..."
python3 run_dashboard.py &
DASH_PID=$!
sleep 3

echo "[2/3] Starting API Security System on port 5000..."
python3 run_api.py &
API_PID=$!
sleep 3

echo "[3/3] Starting Attack Simulator..."
python3 attack_simulator.py &
SIM_PID=$!

echo "=========================================="
echo "  ✅ All systems are launching in background."
echo "  Check the Dashboard at http://localhost:8070"
echo "  Press Ctrl+C to stop all."
echo "=========================================="

# Trap ctrl+c and kill all background processes
trap "echo 'Stopping all...'; kill $DASH_PID $API_PID $SIM_PID; exit" SIGINT SIGTERM

wait
