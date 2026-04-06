@echo off
echo ==========================================
echo   🛡️ API Security System - Master Launcher
echo ==========================================

echo [1/3] Starting Security Dashboard on port 8070...
start cmd /k "python run_dashboard.py"

timeout /t 3 /nobreak > nul

echo [2/3] Starting API Security System on port 5000...
start cmd /k "python run_api.py"

timeout /t 3 /nobreak > nul

echo [3/3] Starting Attack Simulator...
start cmd /k "python scripts/attack_simulator.py"

echo ==========================================
echo   ✅ All systems are launching in separate windows.
echo   Check the Dashboard at http://localhost:8070
echo ==========================================
pause
