@echo off
setlocal

echo ========================================
echo CyberSec Agent - Database Setup
echo ========================================
echo.

set PSQL="C:\Program Files\PostgreSQL\17\bin\psql.exe"

echo This script will create the database and user for CyberSec Agent.
echo.
echo You will be prompted for the PostgreSQL 'postgres' user password.
echo (This was set during PostgreSQL installation)
echo.

REM 创建用户
echo [1/3] Creating user 'cybersec'...
%PSQL% -U postgres -c "CREATE USER cybersec WITH PASSWORD 'cybersec_pass';" 2>nul
if %errorlevel% equ 0 (
    echo User created successfully.
) else (
    echo User may already exist, continuing...
)

REM 创建数据库
echo [2/3] Creating database 'cybersec'...
%PSQL% -U postgres -c "CREATE DATABASE cybersec OWNER cybersec;" 2>nul
if %errorlevel% equ 0 (
    echo Database created successfully.
) else (
    echo Database may already exist, continuing...
)

REM 授权
echo [3/3] Granting privileges...
%PSQL% -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE cybersec TO cybersec;"
%PSQL% -U postgres -c "GRANT ALL ON SCHEMA public TO cybersec;"

echo.
echo ========================================
echo Database setup complete!
echo ========================================
echo.
echo Connection details:
echo   Host: localhost
echo   Port: 5432
echo   Database: cybersec
echo   User: cybersec
echo   Password: cybersec_pass
echo.
echo Connection string:
echo   postgresql+asyncpg://cybersec:cybersec_pass@localhost:5432/cybersec
echo.

pause
