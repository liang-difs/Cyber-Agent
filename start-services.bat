@echo off
setlocal

echo ========================================
echo CyberSec Agent - Service Startup
echo ========================================
echo.

REM 检查 PostgreSQL
echo [1/5] Checking PostgreSQL...
sc query postgresql-x64-17 >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: PostgreSQL service not found!
    echo Please install PostgreSQL 17 first.
    echo See docs/INSTALL_SERVICES.md for instructions.
    pause
    exit /b 1
)

sc query postgresql-x64-17 | findstr "RUNNING" >nul
if %errorlevel% neq 0 (
    echo Starting PostgreSQL...
    net start postgresql-x64-17
    timeout /t 3 /nobreak >nul
)
echo PostgreSQL: OK

REM 检查 Redis
echo [2/5] Checking Redis...
sc query Redis >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Redis service not found!
    echo Please install Redis first.
    echo See docs/INSTALL_SERVICES.md for instructions.
    pause
    exit /b 1
)

sc query Redis | findstr "RUNNING" >nul
if %errorlevel% neq 0 (
    echo Starting Redis...
    net start Redis
    timeout /t 2 /nobreak >nul
)
echo Redis: OK

REM 设置环境变量
echo [3/5] Setting environment variables...
set APP_ENV=development
set AUTH_DEV_FALLBACK_ENABLED=true
set DATABASE_URL=postgresql+asyncpg://cybersec:cybersec_pass@localhost:5432/cybersec
set REDIS_URL=redis://localhost:6379/0
set JWT_SECRET=cybersec-local-dev-secret-20260603
set CORS_ORIGINS=http://localhost:3000
echo Environment: OK

REM 初始化数据库表
echo [4/5] Initializing database...
cd /d "%~dp0backend"
python -c "from app.models.base import init_db; import asyncio; asyncio.run(init_db())" 2>nul
if %errorlevel% equ 0 (
    echo Database tables: OK
) else (
    echo Database tables: Already exist or error (continuing...)
)

REM 初始化管理员
python -m app.scripts.init_admin --username admin --password admin123 --role admin 2>nul
echo Admin user: OK

REM 启动应用
echo [5/5] Starting application...
cd /d "%~dp0"
echo.
echo ========================================
echo Starting CyberSec Agent...
echo ========================================
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:3000
echo   Login:    admin / admin123
echo ========================================
echo.

REM 启动后端
echo Starting backend...
start "CyberSec Backend" /D "%~dp0backend" python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

REM 等待后端启动
timeout /t 5 /nobreak >nul

REM 启动前端
echo Starting frontend...
start "CyberSec Frontend" /D "%~dp0frontend" node node_modules\vite\bin\vite.js --host 0.0.0.0 --port 3000

echo.
echo Both services are starting...
echo Check the opened windows for logs.
echo.
echo Press any key to stop all services...
pause >nul

REM 停止服务
echo Stopping services...
taskkill /FI "WindowTitle eq CyberSec Backend*" /F >nul 2>&1
taskkill /FI "WindowTitle eq CyberSec Frontend*" /F >nul 2>&1
echo Services stopped.

pause
