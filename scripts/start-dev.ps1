param(
    [string]$AdminUsername = $(if ($env:ADMIN_USERNAME) { $env:ADMIN_USERNAME } else { "admin" }),
    [string]$AdminPassword = $(if ($env:ADMIN_PASSWORD) { $env:ADMIN_PASSWORD } else { "admin123" }),
    [string]$AdminRole = $(if ($env:ADMIN_ROLE) { $env:ADMIN_ROLE } else { "admin" }),
    [string]$AdminTenantId = $(if ($env:ADMIN_TENANT_ID) { $env:ADMIN_TENANT_ID } else { "default" })
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message"
}

function Wait-HttpOk {
    param(
        [string]$Url,
        [int]$TimeoutSeconds = 180,
        [System.Diagnostics.Process]$Process = $null
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($Process -and $Process.HasExited) {
            throw "Process $($Process.Id) exited early while waiting for $Url"
        }
        try {
            $response = Invoke-WebRequest -Uri $Url -TimeoutSec 5
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                return
            }
        } catch {
            Start-Sleep -Seconds 2
            continue
        }

        Start-Sleep -Seconds 2
    }

    throw "Timed out waiting for $Url"
}

function Ensure-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found in PATH."
    }
}

function Ensure-PythonImport {
    param(
        [string]$PythonExe,
        [string[]]$PythonArgsPrefix = @(),
        [string[]]$Modules
    )

    $moduleList = $Modules -join ","
    & $PythonExe @PythonArgsPrefix -c "import $moduleList" *> $null
    return ($LASTEXITCODE -eq 0)
}

function Start-BackgroundProcess {
    param(
        [string]$Name,
        [string]$WorkingDirectory,
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$StdOut,
        [string]$StdErr
    )

    if (Test-Path $StdOut) { Remove-Item $StdOut -Force }
    if (Test-Path $StdErr) { Remove-Item $StdErr -Force }

    Write-Step "Starting $Name"
    return Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -WindowStyle Hidden `
        -RedirectStandardOutput $StdOut `
        -RedirectStandardError $StdErr `
        -PassThru
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$backendDir = Join-Path $root "backend"
$frontendDir = Join-Path $root "frontend"
$runtimeDir = Join-Path $backendDir "data/runtime"
$logDir = Join-Path $runtimeDir "logs"
$backendVenv = Join-Path $backendDir ".venv"
$backendVenvPython = Join-Path $backendVenv "Scripts/python.exe"
$backendOut = Join-Path $logDir "backend.out.log"
$backendErr = Join-Path $logDir "backend.err.log"
$frontendOut = Join-Path $logDir "frontend.out.log"
$frontendErr = Join-Path $logDir "frontend.err.log"
$pidFile = Join-Path $runtimeDir "dev-processes.json"

Ensure-Command "py"
Ensure-Command "npm"
Ensure-Command "node"

New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
if (Test-Path $pidFile) { Remove-Item $pidFile -Force }

Write-Step "Preparing backend Python runtime"
$backendPythonExe = "py"
$backendPythonArgsPrefix = @("-3.12")
$backendPipUserArgs = @("--user")

try {
    if (-not (Test-Path $backendVenv)) {
        Write-Step "Creating backend virtual environment with Python 3.12"
        & py -3.12 -m venv $backendVenv
    }

    if (Test-Path $backendVenvPython) {
        & $backendVenvPython -m pip --version *> $null
        if ($LASTEXITCODE -eq 0) {
            $backendPythonExe = $backendVenvPython
            $backendPythonArgsPrefix = @()
            $backendPipUserArgs = @()
            Write-Step "Using backend virtual environment"
        }
    }
} catch {
    Write-Step "Backend virtual environment is unavailable, falling back to system Python 3.12"
}

if ($backendPythonExe -eq "py") {
    $backendPythonExe = (& py -3.12 -c "import sys; print(sys.executable)").Trim()
    $backendPythonArgsPrefix = @()
    Write-Step "Using system Python at $backendPythonExe"
}

if (-not (Ensure-PythonImport -PythonExe $backendPythonExe -PythonArgsPrefix $backendPythonArgsPrefix -Modules @("fastapi", "uvicorn", "sqlalchemy", "aiosqlite"))) {
    Write-Step "Installing backend dependencies"
    & $backendPythonExe @backendPythonArgsPrefix -m pip install @backendPipUserArgs --upgrade pip
    & $backendPythonExe @backendPythonArgsPrefix -m pip install @backendPipUserArgs -r (Join-Path $backendDir "requirements.txt")
}

if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
    Write-Step "Installing frontend dependencies"
    & npm ci --prefix $frontendDir
}
elseif (-not (Test-Path (Join-Path $frontendDir "node_modules/@rollup/rollup-win32-x64-msvc"))) {
    Write-Step "Repairing frontend dependencies"
    & npm install --prefix $frontendDir --no-save @rollup/rollup-win32-x64-msvc
}

$env:APP_ENV = "development"
$env:AUTH_DEV_FALLBACK_ENABLED = "true"
# 使用 PostgreSQL 而不是 SQLite
$env:DATABASE_URL = "postgresql+asyncpg://cybersec:cybersec_pass@localhost:5432/cybersec"
$env:REDIS_URL = "redis://localhost:6379/0"
$env:JWT_SECRET = "cybersec-local-dev-secret-20260603"
$env:CORS_ORIGINS = "http://localhost:3000"

Write-Step "Starting backend"
$backendProcess = $null
$frontendProcess = $null

function Stop-ProcessTree {
    param(
        [System.Diagnostics.Process]$Process
    )

    if (-not $Process) {
        return
    }

    try {
        & taskkill /PID $Process.Id /T /F *> $null
    } catch {
        try {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        } catch {
        }
    }
}

try {
    $backendProcess = Start-BackgroundProcess `
        -Name "backend" `
        -WorkingDirectory $backendDir `
        -FilePath $backendPythonExe `
        -Arguments @($backendPythonArgsPrefix + @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000")) `
        -StdOut $backendOut `
        -StdErr $backendErr

    Write-Step "Waiting for backend health"
    Wait-HttpOk -Url "http://127.0.0.1:8000/health" -TimeoutSeconds 240 -Process $backendProcess

    Write-Step "Initializing default admin user"
    Push-Location $backendDir
    try {
        & $backendPythonExe @backendPythonArgsPrefix -m app.scripts.init_admin `
            --username $AdminUsername `
            --password $AdminPassword `
            --role $AdminRole `
            --tenant-id $AdminTenantId
    }
    finally {
        Pop-Location
    }

    Write-Step "Starting frontend"
    $frontendProcess = Start-BackgroundProcess `
        -Name "frontend" `
        -WorkingDirectory $frontendDir `
        -FilePath "node" `
        -Arguments @((Join-Path $frontendDir "node_modules/vite/bin/vite.js"), "--host", "0.0.0.0", "--port", "3000") `
        -StdOut $frontendOut `
        -StdErr $frontendErr

    Write-Step "Waiting for frontend"
    Wait-HttpOk -Url "http://127.0.0.1:3000" -TimeoutSeconds 240 -Process $frontendProcess

    $processInfo = [ordered]@{
        started_at = (Get-Date).ToString("o")
        backend = @{
            pid = $backendProcess.Id
            port = 8000
            log_out = $backendOut
            log_err = $backendErr
        }
        frontend = @{
            pid = $frontendProcess.Id
            port = 3000
            log_out = $frontendOut
            log_err = $frontendErr
        }
    }
    $processInfo | ConvertTo-Json -Depth 5 | Set-Content -Path $pidFile -Encoding UTF8

    Write-Host ""
    Write-Host "CyberSec Agent is ready."
    Write-Host "  Frontend: http://localhost:3000"
    Write-Host "  Backend:  http://localhost:8000"
    Write-Host "  Login:    $AdminUsername / $AdminPassword"
    Write-Host "  DB:       PostgreSQL (cybersec)"
    Write-Host ""
    Write-Host "Logs:"
    Write-Host "  $backendOut"
    Write-Host "  $backendErr"
    Write-Host "  $frontendOut"
    Write-Host "  $frontendErr"
    Write-Host ""
    Write-Host "Process IDs:"
    Write-Host "  backend:  $($backendProcess.Id)"
    Write-Host "  frontend: $($frontendProcess.Id)"
}
catch {
    Stop-ProcessTree -Process $frontendProcess
    Stop-ProcessTree -Process $backendProcess
    if (Test-Path $pidFile) { Remove-Item $pidFile -Force }
    throw
}
