@echo off
echo Starting API Security System...
echo ================================
cd /d "%~dp0.."
if exist ".\.venv\Scripts\activate.bat" (
    call .\.venv\Scripts\activate.bat
)
python run_api.py
pause
