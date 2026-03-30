@echo off
echo Starting API Security System...
echo ================================
call .\.venv\Scripts\activate.bat
python run_api.py
pause
