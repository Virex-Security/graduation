@echo off
echo ==========================================
echo   🛡️ API Security System - Master Launcher
echo ==========================================

echo [1/3] Starting Security Dashboard on port 8070...
<<<<<<< HEAD
start cmd /k "python run_dashboard.py"
=======
start cmd /k "python dashboard.py"
>>>>>>> 967891135f8e00079cef2ba1d9796462c24daaba

timeout /t 3 /nobreak > nul

echo [2/3] Starting API Security System on port 5000...
<<<<<<< HEAD
start cmd /k "python run_api.py"
=======
start cmd /k "python simple_app.py"
>>>>>>> 967891135f8e00079cef2ba1d9796462c24daaba

timeout /t 3 /nobreak > nul

echo [3/3] Starting Attack Simulator...
<<<<<<< HEAD
start cmd /k "python scripts/attack_simulator.py"
=======
start cmd /k "python attack_simulator.py"
>>>>>>> 967891135f8e00079cef2ba1d9796462c24daaba

echo ==========================================
echo   ✅ All systems are launching in separate windows.
echo   Check the Dashboard at http://localhost:8070
echo ==========================================
pause
