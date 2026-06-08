param()

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message"
}

function Stop-ProcessTree {
    param(
        [int]$Pid,
        [string]$Label
    )

    if ($Pid -le 0) {
        return
    }

    Write-Step "Stopping $Label (PID $Pid)"
    try {
        & taskkill /PID $Pid /T /F *> $null
        if ($LASTEXITCODE -ne 0) {
            Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
    }
}

function Get-PortOwningPids {
    param([int[]]$Ports)

    $pids = New-Object System.Collections.Generic.HashSet[int]
    foreach ($port in $Ports) {
        try {
            $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction Stop
            foreach ($connection in $connections) {
                if ($connection.OwningProcess -gt 0) {
                    [void]$pids.Add([int]$connection.OwningProcess)
                }
            }
        } catch {
            try {
                $pattern = "[:.]$port\s+.*LISTENING\s+(\d+)$"
                $lines = & netstat -ano -p tcp
                foreach ($line in $lines) {
                    if ($line -match $pattern) {
                        [void]$pids.Add([int]$Matches[1])
                    }
                }
            } catch {
                continue
            }
        }
    }

    return $pids
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$backendDir = Join-Path $root "backend"
$runtimeDir = Join-Path $backendDir "data/runtime"
$pidFile = Join-Path $runtimeDir "dev-processes.json"

$targets = New-Object System.Collections.Generic.List[object]

if (Test-Path $pidFile) {
    try {
        $meta = Get-Content $pidFile -Raw | ConvertFrom-Json
        if ($meta.backend -and $meta.backend.pid) {
            $targets.Add([pscustomobject]@{ pid = [int]$meta.backend.pid; label = "backend" })
        }
        if ($meta.frontend -and $meta.frontend.pid) {
            $targets.Add([pscustomobject]@{ pid = [int]$meta.frontend.pid; label = "frontend" })
        }
    } catch {
        Write-Step "PID file could not be parsed; falling back to port scan."
    }
}

foreach ($pid in (Get-PortOwningPids -Ports @(8000, 3000))) {
    if (-not ($targets | Where-Object { $_.pid -eq $pid })) {
        $label = if ($pid) { "service" } else { "service" }
        $targets.Add([pscustomobject]@{ pid = [int]$pid; label = $label })
    }
}

if ($targets.Count -eq 0) {
    Write-Step "No running frontend/backend processes were found."
} else {
    foreach ($target in ($targets | Sort-Object pid -Unique)) {
        Stop-ProcessTree -Pid $target.pid -Label $target.label
    }
}

if (Test-Path $pidFile) {
    Remove-Item $pidFile -Force
}

Write-Host ""
Write-Host "Development services stopped."
Write-Host "If a window still looks open, it should be safe to close it now."
