@echo off
setlocal

echo ========================================
echo CyberSec Agent - Stop Services
echo ========================================
echo.

echo Stopping backend (port 8000)...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000 ^| findstr LISTENING') do (
    echo Killing PID %%a
    taskkill /PID %%a /F >nul 2>&1
)

echo Stopping frontend (port 3000)...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :3000 ^| findstr LISTENING') do (
    echo Killing PID %%a
    taskkill /PID %%a /F >nul 2>&1
)

echo.
echo Stopping any remaining CyberSec processes...
taskkill /FI "WindowTitle eq CyberSec*" /F >nul 2>&1

echo.
echo ========================================
echo All services stopped.
echo ========================================
echo.

pause
