<#
.SYNOPSIS
    SOC Platform Agent Bootstrap Installer
.DESCRIPTION
    Enrolls this machine as a SOC agent, downloads the agent script,
    writes credentials without UTF-8 BOM, and creates a scheduled task.
.PARAMETER Token
    One-time installer token from the SOC Platform dashboard.
.PARAMETER TenantId
    Tenant UUID from the SOC Platform dashboard.
.PARAMETER ApiUrl
    Base URL of the SOC Platform backend API.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File bootstrap.ps1 `
        -Token inst_xxx -TenantId xxxxxxxx-xxxx-... -ApiUrl https://backend.up.railway.app
#>
param(
    [Parameter(Mandatory=$true)]  [string]$Token,
    [Parameter(Mandatory=$true)]  [string]$TenantId,
    [Parameter(Mandatory=$false)] [string]$ApiUrl = "https://backend-production-a9cb4.up.railway.app"
)

#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

# ── OS guard ─────────────────────────────────────────────────────────────────
if ($env:OS -ne "Windows_NT") {
    Write-Host "[bootstrap] ERR This installer is for Windows only." -ForegroundColor Red
    Write-Host "[bootstrap]     Linux/macOS support coming soon." -ForegroundColor Red
    exit 1
}

# ── Constants ─────────────────────────────────────────────────────────────────
$INSTALL_DIR  = "C:\ProgramData\SOCAnalyst"
$CREDS_FILE   = Join-Path $INSTALL_DIR "credentials.json"
$AGENT_FILE   = Join-Path $INSTALL_DIR "soc_agent_v2.py"
$TASK_NAME    = "SOCAnalystAgent"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step { param($msg) Write-Host "[bootstrap] $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "[bootstrap] OK  $msg" -ForegroundColor Green }
function Write-Fail { param($msg) Write-Host "[bootstrap] ERR $msg" -ForegroundColor Red; exit 1 }

function Write-JsonNoBom {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

# ── Step 0: Stop any running V1 agent ────────────────────────────────────────
$existingV1Task = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
if ($existingV1Task) {
    $v1Args = $existingV1Task.Actions[0].Arguments
    if ($v1Args -like '*soc_agent.py*') {
        Write-Host '[bootstrap] V1 agent detected - upgrading to V2...' -ForegroundColor Yellow
    }
    Stop-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
}

# Kill lingering python processes running the V1 script
$v1Procs = Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue
if ($v1Procs) {
    foreach ($proc in $v1Procs) {
        if ($proc.CommandLine -like '*soc_agent.py*') {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host "[bootstrap] Stopped V1 agent process (PID $($proc.ProcessId))" -ForegroundColor Yellow
        }
    }
}

# ── Step 1: Gather machine information ────────────────────────────────────────
Write-Step "Gathering machine information..."

$hostname  = $env:COMPUTERNAME
$ipAddress = $null
try {
    $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
                  Select-Object -First 1).IPAddress
} catch {}

Write-OK "Hostname: $hostname  IP: $ipAddress"

# ── Step 2: Enroll agent ──────────────────────────────────────────────────────
Write-Step "Enrolling agent with SOC Platform..."

$enrollBody = @{
    token       = $Token
    tenant_id   = $TenantId
    machine_info = @{
        hostname      = $hostname
        os_type       = "windows"
        ip_address    = $ipAddress
        agent_version = "2.0.0"
    }
} | ConvertTo-Json -Depth 5 -Compress

try {
    $resp = Invoke-RestMethod `
        -Uri         "$ApiUrl/api/v1/installer/bootstrap-enroll" `
        -Method      POST `
        -ContentType "application/json; charset=utf-8" `
        -Body        $enrollBody `
        -UseBasicParsing
} catch {
    Write-Fail "Enrollment failed: $($_.Exception.Message)"
}

$agentId         = $resp.data.agent_id
$enrollmentToken = $resp.data.enrollment_token

if (-not $agentId) { Write-Fail "Enrollment response missing agent_id." }

Write-OK "Enrolled — Agent ID: $agentId"

# ── Step 3: Prepare install directory ────────────────────────────────────────
Write-Step "Preparing install directory..."

if (-not (Test-Path $INSTALL_DIR)) {
    New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
}

# Grant Users read/write so the agent (running as SYSTEM) can access all files.
# Single quotes prevent PowerShell from parsing (OI)(CI) as sub-expressions.
icacls "$INSTALL_DIR" /grant 'Everyone:(OI)(CI)F' /T 2>$null | Out-Null

Write-OK "Directory ready: $INSTALL_DIR"

# ── Step 4: Write credentials.json WITHOUT BOM ───────────────────────────────
Write-Step "Storing credentials..."

$credsJson = [ordered]@{
    agent_id         = $agentId
    enrollment_token = $enrollmentToken
    tenant_id        = $TenantId
    api_url          = $ApiUrl
    enrolled_at      = (Get-Date -Format "o")
    hostname         = $hostname
} | ConvertTo-Json -Depth 3

Write-JsonNoBom -Path $CREDS_FILE -Content $credsJson

Write-OK "Credentials saved to $CREDS_FILE"

# ── Step 5: Download agent script ─────────────────────────────────────────────
Write-Step "Downloading agent script..."

try {
    Invoke-WebRequest `
        -Uri     "$ApiUrl/api/v1/installer/soc_agent_v2.py" `
        -OutFile $AGENT_FILE `
        -UseBasicParsing
} catch {
    Write-Fail "Failed to download agent script: $($_.Exception.Message)"
}

Write-OK "Agent script saved to $AGENT_FILE"

# ── Step 6: Find Python ───────────────────────────────────────────────────────
Write-Step "Locating Python runtime..."

$pythonCandidates = @(
    "C:\Python314\pythonw.exe",
    "C:\Python313\pythonw.exe",
    "C:\Python312\pythonw.exe",
    "C:\Python311\pythonw.exe",
    "C:\Python310\pythonw.exe",
    "C:\Python39\pythonw.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python314\pythonw.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python313\pythonw.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python312\pythonw.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\pythonw.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python310\pythonw.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python39\pythonw.exe",
    "C:\Python314\python.exe",
    "C:\Python313\python.exe",
    "C:\Python312\python.exe",
    "C:\Python311\python.exe",
    "C:\Python310\python.exe",
    "C:\Python39\python.exe"
)

$pythonExe = $null
foreach ($candidate in $pythonCandidates) {
    if (Test-Path $candidate) {
        $pythonExe = $candidate
        break
    }
}

if (-not $pythonExe) {
    # Fallback: try PATH
    try {
        $found = (Get-Command "pythonw.exe" -ErrorAction SilentlyContinue).Source
        if (-not $found) {
            $found = (Get-Command "python.exe" -ErrorAction SilentlyContinue).Source
        }
        if ($found -and $found -notlike "*WindowsApps*") {
            $pythonExe = $found
        }
    } catch {}
}

if (-not $pythonExe) {
    Write-Fail "Python 3.9+ not found.`n  Install from https://www.python.org/downloads/ (enable 'Add to PATH')`n  then re-run this installer."
}

Write-OK "Python found: $pythonExe"

# ── Step 7: Create scheduled task ────────────────────────────────────────────
Write-Step "Installing scheduled task..."

# Remove existing task if present
$existingTask = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
if ($existingTask) {
    Stop-ScheduledTask  -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
}

$action  = New-ScheduledTaskAction -Execute $pythonExe -Argument "-u `"$AGENT_FILE`""
$trigger = New-ScheduledTaskTrigger -AtStartup

# Also add an AtLogon trigger so it starts when any user logs in
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit     (New-TimeSpan -Hours 0) `
    -RestartCount           10 `
    -RestartInterval        (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable     `
    -RunOnlyIfNetworkAvailable:$false

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask `
    -TaskName  $TASK_NAME `
    -Action    $action `
    -Trigger   @($trigger, $logonTrigger) `
    -Settings  $settings `
    -Principal $principal `
    -Force | Out-Null

Write-OK "Scheduled task '$TASK_NAME' installed (runs as SYSTEM at startup)"

# ── Step 8: Start agent now ───────────────────────────────────────────────────
Write-Step "Starting agent..."

Start-ScheduledTask -TaskName $TASK_NAME
Start-Sleep -Seconds 3

$state = (Get-ScheduledTask -TaskName $TASK_NAME).State
Write-OK "Agent task state: $state"

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Agent enrolled successfully." -ForegroundColor Green
Write-Host "  The agent will appear in your SOC Platform dashboard." -ForegroundColor Green
Write-Host "  Credentials stored at: $CREDS_FILE" -ForegroundColor DarkGray
Write-Host "  Agent script at:       $AGENT_FILE" -ForegroundColor DarkGray
Write-Host "  Scheduled task:        $TASK_NAME (SYSTEM, runs at startup)" -ForegroundColor DarkGray
Write-Host ""
