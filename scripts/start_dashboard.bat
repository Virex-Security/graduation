@echo off
echo Starting Security Dashboard...
echo ================================
cd /d "%~dp0.."
if exist ".\.venv\Scripts\activate.bat" (
    call .\.venv\Scripts\activate.bat
)
python run_dashboard.py
pause
