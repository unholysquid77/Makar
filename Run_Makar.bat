@echo off
setlocal
title MAKAR Launcher

REM Always run from the folder containing this BAT file.
cd /d "%~dp0"

echo.
echo  ========================================
echo           MAKAR - LAUNCHER
echo  ========================================
echo.

REM Check required files before launching either service.
if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Python virtual environment not found:
    echo         .venv\Scripts\python.exe
    echo Run this launcher from the Makar project root and check your venv.
    echo.
    pause
    exit /b 1
)

if not exist "frontend\package.json" (
    echo [ERROR] frontend\package.json was not found.
    echo Make sure this BAT file is in the Makar project root.
    echo.
    pause
    exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm was not found on PATH. Install Node.js or fix PATH.
    echo.
    pause
    exit /b 1
)

echo [1/2] Starting Makar API on port 8000...
start "MAKAR API - port 8000" "%ComSpec%" /k ""%CD%\.venv\Scripts\python.exe" -m backend.main"

REM Give the backend a moment to initialize before starting the UI.
timeout /t 2 /nobreak >nul

echo [2/2] Starting Makar UI on port 5173...
start "MAKAR UI - port 5173" "%ComSpec%" /k "npm --prefix frontend run dev"

echo.
echo Both launch commands have been started.
echo Backend: http://127.0.0.1:8000
echo Frontend: http://localhost:5173
echo.
echo Keep both service windows open while using Makar.
echo Close those windows to stop the services.
echo.
pause
endlocal
