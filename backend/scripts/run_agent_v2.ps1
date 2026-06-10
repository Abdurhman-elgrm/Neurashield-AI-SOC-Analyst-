<#
.SYNOPSIS
    Installs and starts NEURASHIELD SOC Agent v2.0
.DESCRIPTION
    Copies soc_agent_v2.py to C:\ProgramData\SOCAnalyst\
    then launches it with pythonw.exe (no console window).
    Requires credentials.json to already exist (run bootstrap.ps1 first).
#>

$AgentDir    = "C:\ProgramData\SOCAnalyst"
$AgentTarget = Join-Path $AgentDir "soc_agent_v2.py"
$LogFile     = Join-Path $AgentDir "agent_v2.log"
$CredsFile   = Join-Path $AgentDir "credentials.json"
$LockPort    = 47333

# ── Check credentials exist ───────────────────────────────────────────────────
if (-not (Test-Path $CredsFile)) {
    Write-Host "ERROR: $CredsFile not found." -ForegroundColor Red
    Write-Host "Run bootstrap.ps1 first to enroll this device." -ForegroundColor Yellow
    exit 1
}

# ── Copy agent script ─────────────────────────────────────────────────────────
$SourceScript = Join-Path $PSScriptRoot "soc_agent_v2.py"
if (Test-Path $SourceScript) {
    Copy-Item $SourceScript $AgentTarget -Force
    Write-Host "Agent script installed to $AgentTarget" -ForegroundColor Green
} elseif (-not (Test-Path $AgentTarget)) {
    Write-Host "ERROR: soc_agent_v2.py not found at $SourceScript or $AgentTarget" -ForegroundColor Red
    exit 1
}

# ── Check if already running ──────────────────────────────────────────────────
$existing = Get-Process -Name "pythonw" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*soc_agent_v2*" }
if ($existing) {
    Write-Host "Agent already running (PID $($existing.Id))" -ForegroundColor Yellow
    exit 0
}

# ── Find Python ───────────────────────────────────────────────────────────────
$pythonw = $null
foreach ($candidate in @("pythonw.exe", "python.exe")) {
    try {
        $p = (Get-Command $candidate -ErrorAction Stop).Source
        if ($p) { $pythonw = $p; break }
    } catch {}
}
if (-not $pythonw) {
    Write-Host "ERROR: Python not found. Install Python 3.9+ and ensure it is in PATH." -ForegroundColor Red
    exit 1
}

Write-Host "Python: $pythonw" -ForegroundColor DarkGray

# ── Install requests if needed ────────────────────────────────────────────────
& $pythonw -c "import requests" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing requests..." -ForegroundColor Cyan
    & $pythonw -m pip install requests --quiet
}

# ── Launch agent ──────────────────────────────────────────────────────────────
Write-Host "Starting NEURASHIELD Agent v2.0..." -ForegroundColor Cyan

$proc = Start-Process `
    -FilePath    $pythonw `
    -ArgumentList $AgentTarget `
    -WindowStyle Hidden `
    -PassThru

if ($proc) {
    Write-Host "Agent started (PID $($proc.Id))" -ForegroundColor Green
    Write-Host "Log file: $LogFile" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "To verify it's running:" -ForegroundColor DarkGray
    Write-Host "  Get-Content '$LogFile' -Wait" -ForegroundColor DarkGray
} else {
    Write-Host "Failed to start agent." -ForegroundColor Red
    exit 1
}
