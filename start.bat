@echo off
REM ============================================================
REM  Virex Security System — Windows startup script
REM  Usage: start.bat [api|dashboard|all]
REM ============================================================

if not exist .env (
    echo [ERROR] .env not found. Run: copy .env.example .env
    exit /b 1
)

set MODE=%1
if "%MODE%"=="" set MODE=all

if "%MODE%"=="api" (
    echo [Virex] Starting API server...
    python run_api.py
    goto end
)

if "%MODE%"=="dashboard" (
    echo [Virex] Starting Dashboard server...
    python run_dashboard.py
    goto end
)

if "%MODE%"=="all" (
    echo [Virex] Starting API + Dashboard...
    start "Virex API" python run_api.py
    timeout /t 2 /nobreak >nul
    start "Virex Dashboard" python run_dashboard.py
    echo [Virex] API:       http://localhost:5000
    echo [Virex] Dashboard: http://localhost:8070
    goto end
)

echo Usage: start.bat [api^|dashboard^|all]
:end
