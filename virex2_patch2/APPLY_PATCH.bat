@echo off
echo ============================================
echo   VIREX2 Patch v2 - Applying...
echo ============================================

REM ── API files
copy /Y app\api\persistence.py  ..\app\api\persistence.py
copy /Y app\api\routes.py       ..\app\api\routes.py
copy /Y app\api\security.py     ..\app\api\security.py

REM ── ML
copy /Y app\ml\inference.py     ..\app\ml\inference.py

REM ── Auth
copy /Y app\auth\models.py      ..\app\auth\models.py
copy /Y app\auth\decorators.py  ..\app\auth\decorators.py

REM ── Templates
copy /Y app\templates\attack_history.html      ..\app\templates\attack_history.html
copy /Y app\templates\sidebar_component.html   ..\app\templates\sidebar_component.html

REM ── Root files
copy /Y simple_app.py           ..\simple_app.py

REM ── Delete routes_temp if still exists
if exist "..\app\dashboard\routes_temp.py" (
    del /F /Q "..\app\dashboard\routes_temp.py"
    echo Deleted routes_temp.py
)

REM ── Add new env vars to .env if missing
findstr /C:"ML_THRESHOLD_BLOCK" ".\.env" >nul 2>&1 || (
    echo. >> "..\".env"
    echo ML_THRESHOLD_BLOCK=0.90 >> "..\".env"
    echo ML_THRESHOLD_MONITOR=0.70 >> "..\".env"
    echo MAX_CONTENT_LENGTH=1048576 >> "..\".env"
    echo Added ML vars to .env
)

echo ============================================
echo   Done! Run: python verify_virex.py
echo ============================================
pause
