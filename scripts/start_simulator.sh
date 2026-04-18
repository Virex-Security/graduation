#!/usr/bin/env bash
echo "Starting Attack Simulator..."
echo "================================"
cd "$(dirname "$0")/.."
if [ -f "./.venv/bin/activate" ]; then
    source ./.venv/bin/activate
fi
python3 attack_simulator.py
