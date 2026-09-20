<# 
.SYNOPSIS
    Starts SecureVault (PostgreSQL + Rust backend + Next.js frontend) in one script.
.DESCRIPTION
    Launches all three components in separate background jobs. Press Ctrl+C to stop everything.
#>

param(
    [string]$ProjectRoot = "C:\Users\doesn\OneDrive\Documents\personal password manager\secure-vault",
    [string]$WinLibsPath = "C:\Users\doesn\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.MSVCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin",
    [string]$CargoTargetDir = "C:\Users\doesn\AppData\Local\Temp\opencode\sv-target",
    [string]$DatabaseUrl = "postgres://postgres:postgres@localhost:5432/secure_vault",
    [int]$BackendPort = 8080,
    [int]$FrontendPort = 3000
)

$ErrorActionPreference = "Stop"

# ─── Setup environment ───
$env:Path = "$WinLibsPath;$env:USERPROFILE\.cargo\bin;$env:Path"
$env:CARGO_TARGET_DIR = $CargoTargetDir
$env:DATABASE_URL = $DatabaseUrl
$env:PORT = $BackendPort.ToString()

Set-Location $ProjectRoot

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  SecureVault — One-Command Startup                          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# ─── Track background jobs for cleanup ───
$jobs = @()
$cleanup = {
    Write-Host "`nShutting down..." -ForegroundColor Yellow
    foreach ($job in $jobs) {
        if ($job.State -eq 'Running') {
            Stop-Job $job -Force
        }
    }
    # Also stop docker compose
    docker compose down --remove-orphans 2>$null
    Write-Host "All stopped." -ForegroundColor Green
}
Register-ObjectEvent -InputObject (Get-Process -Id $PID) -EventName Exited -Action $cleanup -SupportEvent | Out-Null

# ─── 1. Start PostgreSQL ───
Write-Host "`n[1/3] Checking Docker..." -ForegroundColor Yellow
$dockerOk = $false
try {
  docker info 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) { $dockerOk = $true }
} catch { $dockerOk = $false }
if (-not $dockerOk) {
  Write-Host ""
  Write-Host "  Docker Desktop is not responding." -ForegroundColor Red
  Write-Host "  Fix it with these steps, then re-run .\start-all.ps1 :" -ForegroundColor Yellow
  Write-Host "    1. Open Docker Desktop from the Start menu"
  Write-Host "    2. Wait until the bottom-left shows green 'Engine running'"
  Write-Host "    3. If it is stuck/erroring: right-click the tray whale icon > Restart"
  Write-Host "    4. Still broken? Run:  wsl --shutdown   then reopen Docker Desktop and wait 1-2 min"
  Write-Host ""
  Write-Host "  Tip: you can still preview the UI without Docker:" -ForegroundColor Cyan
  Write-Host "    cd apps\web; npm run dev   ->  http://localhost:3000  (landing page works, login needs the backend)"
  exit 1
}
Write-Host "      Docker is up." -ForegroundColor Green
Write-Host "`n[1/3] Starting PostgreSQL..." -ForegroundColor Yellow
docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Error "docker compose failed. Is Docker running?"
    exit 1
}

# Wait for DB to accept connections
Write-Host "      Waiting for database..." -NoNewline
for ($i = 0; $i -lt 30; $i++) {
    try {
        $conn = New-Object Npgsql.NpgsqlConnection($DatabaseUrl)
        $conn.Open()
        $conn.Close()
        Write-Host " ready!" -ForegroundColor Green
        break
    } catch {
        Write-Host "." -NoNewline
        Start-Sleep 1
    }
    if ($i -eq 29) { Write-Error "`nDatabase never became ready"; exit 1 }
}

# ─── 2. Start Rust Backend ───
Write-Host "`n[2/3] Starting Rust backend (port ${BackendPort})..." -ForegroundColor Yellow
$backendJob = Start-Job -ScriptBlock {
    param($root, $envPath, $cargoTarget, $dbUrl, $port)
    $env:Path = $envPath
    $env:CARGO_TARGET_DIR = $cargoTarget
    $env:DATABASE_URL = $dbUrl
    $env:PORT = $port.ToString()
    Set-Location $root
    cargo run -p secure-vault-api
} -ArgumentList $ProjectRoot, $env:Path, $CargoTargetDir, $DatabaseUrl, $BackendPort
$jobs += $backendJob

# Give backend a moment to start migration + listen
Start-Sleep 3

# ─── 3. Start Next.js Frontend ───
Write-Host "`n[3/3] Starting Next.js frontend (port ${FrontendPort})..." -ForegroundColor Yellow
$frontendJob = Start-Job -ScriptBlock {
    param($root, $port)
    $env:PORT = $port.ToString()
    Set-Location "$root\apps\web"
    if (-not (Test-Path "node_modules")) {
        Write-Host "      Installing npm dependencies..."
        npm install
    }
    npm run dev
} -ArgumentList $ProjectRoot, $FrontendPort
$jobs += $frontendJob

# ─── Summary ───
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  All services started!                                      ║" -ForegroundColor Cyan
Write-Host "║  • Frontend:  http://localhost:$FrontendPort                       ║" -ForegroundColor Cyan
Write-Host "║  • Backend:   http://localhost:$BackendPort                        ║" -ForegroundColor Cyan
Write-Host "║  • Health:    http://localhost:$BackendPort/health                  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "`nPress Ctrl+C to stop everything." -ForegroundColor Gray

# ─── Keep script alive, show job output ───
try {
    while ($true) {
        foreach ($job in $jobs) {
            $out = Receive-Job $job -ErrorAction SilentlyContinue
            if ($out) { Write-Host $out }
        }
        Start-Sleep 1
    }
} catch {
    & $cleanup
}