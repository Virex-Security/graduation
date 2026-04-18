@echo off
echo Starting Attack Simulator...
echo ================================
cd /d "%~dp0.."
if exist ".\.venv\Scripts\activate.bat" (
    call .\.venv\Scripts\activate.bat
)
python attack_simulator.py
pause
