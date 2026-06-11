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
    [Parameter(Mandatory=$true)]  [string]$ApiUrl
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

# Kill ALL lingering agent-related processes (python + cmd wrappers)
$allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
if ($allProcs) {
    foreach ($proc in $allProcs) {
        $cmdLine = $proc.CommandLine
        if ($cmdLine -like '*soc_agent.py*' -or
            $cmdLine -like '*soc_agent_v2.py*' -or
            $cmdLine -like '*run_agent.bat*') {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host "[bootstrap] Stopped agent process (PID $($proc.ProcessId))" -ForegroundColor Yellow
        }
    }
}
# Brief pause so killed processes fully release Task Scheduler tracking
Start-Sleep -Seconds 2

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

Write-OK "Enrolled - Agent ID: $agentId"

# ── Step 3: Prepare install directory ────────────────────────────────────────
Write-Step "Preparing install directory..."

# Use .NET directly -- avoids New-Item quirks across PS versions
[System.IO.Directory]::CreateDirectory($INSTALL_DIR) | Out-Null

# Grant full access to Everyone so SYSTEM scheduled task can read/write
# Use cmd.exe to avoid PowerShell parsing (OI)(CI) as sub-expressions
cmd.exe /c "icacls `"$INSTALL_DIR`" /grant Everyone:(OI)(CI)F /T >nul 2>&1"

Write-OK "Directory ready: $INSTALL_DIR"

# ── Step 4: Write credentials.json WITHOUT BOM ───────────────────────────────
Write-Step "Storing credentials..."

# Ensure directory exists immediately before writing (safety net)
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($CREDS_FILE)) | Out-Null

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

# ── Step 6: Find Python (same logic as V1) ───────────────────────────────────
Write-Step "Locating Python runtime..."

$pythonCandidates = @(
    "C:\Python314\python.exe",
    "C:\Python313\python.exe",
    "C:\Python312\python.exe",
    "C:\Python311\python.exe",
    "C:\Python310\python.exe",
    "C:\Python39\python.exe",
    "C:\Program Files\Python314\python.exe",
    "C:\Program Files\Python313\python.exe",
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe"
)

$pythonExe = $null
foreach ($candidate in $pythonCandidates) {
    if (Test-Path $candidate) { $pythonExe = $candidate; break }
}

if (-not $pythonExe) {
    try {
        $found = (Get-Command "python.exe" -ErrorAction SilentlyContinue).Source
        if ($found -and $found -notlike "*WindowsApps*") { $pythonExe = $found }
    } catch {}
}

if (-not $pythonExe) {
    Write-Fail "Python 3.9+ not found.`n  Install from https://www.python.org/downloads/ (enable 'Add to PATH')`n  then re-run this installer."
}

Write-OK "Python found: $pythonExe"

# ── Step 7: Create scheduled task ────────────────────────────────────────────
Write-Step "Installing scheduled task..."

$LOG_FILE = Join-Path $INSTALL_DIR "agent_v2.log"

# Remove existing task if present
$existingTask = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
if ($existingTask) {
    Stop-ScheduledTask  -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
}

# Run Python directly — no cmd.exe wrapper needed.
# The agent opens its own log file as the very first operation, so all
# startup errors (including import failures) are captured there.
$action  = New-ScheduledTaskAction -Execute $pythonExe -Argument "-u `"$AGENT_FILE`""
$trigger = New-ScheduledTaskTrigger -AtStartup

# Also add an AtLogon trigger so it starts when any user logs in
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit       (New-TimeSpan -Hours 0) `
    -RestartCount             10 `
    -RestartInterval          (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable       `
    -RunOnlyIfNetworkAvailable:$false `
    -MultipleInstances        Queue

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask `
    -TaskName  $TASK_NAME `
    -Action    $action `
    -Trigger   @($trigger, $logonTrigger) `
    -Settings  $settings `
    -Principal $principal `
    -Force | Out-Null

Write-OK "Scheduled task '$TASK_NAME' installed (runs as SYSTEM at startup)"

# ── Step 8: Start agent and verify it is running ─────────────────────────────
Write-Step "Starting agent..."

Start-ScheduledTask -TaskName $TASK_NAME

# Wait up to 20 seconds for Python to create its log file — that is the
# definitive proof the agent process actually started and is running.
$deadline = (Get-Date).AddSeconds(20)
while (-not (Test-Path $LOG_FILE) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
}

$state = (Get-ScheduledTask -TaskName $TASK_NAME).State

if (Test-Path $LOG_FILE) {
    Write-OK "Agent is running (log file created)"
    Get-Content $LOG_FILE -Tail 3 | ForEach-Object { Write-Host "  > $_" -ForegroundColor DarkGray }
} else {
    Write-Host "[bootstrap] WARN  Agent log not created after 20s (task state: $state)" -ForegroundColor Yellow
    Write-Host "            The agent will start automatically on next login/reboot." -ForegroundColor Yellow
    Write-Host "            To diagnose: Get-Content $LOG_FILE" -ForegroundColor DarkGray
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Agent enrolled successfully." -ForegroundColor Green
Write-Host "  The agent will appear in your SOC Platform dashboard." -ForegroundColor Green
Write-Host "  Credentials stored at: $CREDS_FILE" -ForegroundColor DarkGray
Write-Host "  Agent script at:       $AGENT_FILE" -ForegroundColor DarkGray
Write-Host "  Scheduled task:        $TASK_NAME (SYSTEM, runs at startup)" -ForegroundColor DarkGray
Write-Host ""
