#!/usr/bin/env bash
echo "Starting Security Dashboard..."
echo "================================"
cd "$(dirname "$0")/.."
if [ -f "./.venv/bin/activate" ]; then
    source ./.venv/bin/activate
fi
python3 run_dashboard.py
