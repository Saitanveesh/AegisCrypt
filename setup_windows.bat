@echo off
setlocal
cd /d "%~dp0"

echo.
echo AegisCrypt v0.9.2 setup
echo ======================
echo.

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 -m venv .venv
) else (
    python -m venv .venv
)

if errorlevel 1 (
    echo Failed to create virtual environment.
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat

python -m pip install --upgrade pip
if errorlevel 1 (
    echo Failed to update pip.
    pause
    exit /b 1
)

pip install -r requirements.txt
if errorlevel 1 (
    echo Failed to install requirements.
    pause
    exit /b 1
)

echo.
echo Setup complete.
echo Run run_desktop.bat to launch AegisCrypt.
echo.
pause
