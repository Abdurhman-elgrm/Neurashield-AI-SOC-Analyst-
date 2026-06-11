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

# Kill lingering python processes running V1 or V2 agent scripts
$allPyProcs = Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue
if ($allPyProcs) {
    foreach ($proc in $allPyProcs) {
        if ($proc.CommandLine -like '*soc_agent.py*' -or $proc.CommandLine -like '*soc_agent_v2.py*') {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host "[bootstrap] Stopped agent process (PID $($proc.ProcessId))" -ForegroundColor Yellow
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

# ── Step 6: Find / provision Python ──────────────────────────────────────────
Write-Step "Locating Python runtime..."

# Prefer system-wide installs; user-profile paths (AppData) may be blocked
# by AppLocker or inaccessible to SYSTEM in Task Scheduler Session-0.
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
    "C:\Program Files\Python310\python.exe",
    # user-profile fallbacks (checked but may not work as SYSTEM)
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

# If Python is missing or lives inside a user profile (AppData / Users),
# download the official embeddable package to a SYSTEM-accessible path.
$pyEmbedDir = Join-Path $INSTALL_DIR "python"
$pyEmbedExe = Join-Path $pyEmbedDir "python.exe"

$needsEmbed = (-not $pythonExe) -or
              ($pythonExe -like "*\Users\*") -or
              ($pythonExe -like "*AppData*")

if ($needsEmbed) {
    if (Test-Path $pyEmbedExe) {
        Write-OK "Embedded Python already present at $pyEmbedExe"
        $pythonExe = $pyEmbedExe
    } else {
        Write-Step "Python not in system path - downloading embeddable runtime (~8 MB)..."
        $pyVersion  = "3.11.9"
        $pyZipUrl   = "https://www.python.org/ftp/python/$pyVersion/python-$pyVersion-embed-amd64.zip"
        $pyZipPath  = Join-Path $env:TEMP "soc_python_embed.zip"
        try {
            Invoke-WebRequest -Uri $pyZipUrl -OutFile $pyZipPath -UseBasicParsing
            [System.IO.Directory]::CreateDirectory($pyEmbedDir) | Out-Null
            Expand-Archive -Path $pyZipPath -DestinationPath $pyEmbedDir -Force
            Remove-Item $pyZipPath -Force -ErrorAction SilentlyContinue

            # Enable site-packages (embeddable layout disables them by default)
            $pthFile = Get-ChildItem $pyEmbedDir -Filter "python*._pth" | Select-Object -First 1
            if ($pthFile) {
                (Get-Content $pthFile.FullName -Raw) -replace '#import site', 'import site' |
                    Set-Content $pthFile.FullName -Encoding ASCII
            }

            # Bootstrap pip then install requests
            # Use 2>$null so pip warnings to stderr don't trigger $ErrorActionPreference=Stop
            $getPipPath = Join-Path $env:TEMP "get-pip.py"
            Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $getPipPath -UseBasicParsing
            & $pyEmbedExe $getPipPath --quiet 2>$null
            Remove-Item $getPipPath -Force -ErrorAction SilentlyContinue
            & $pyEmbedExe -m pip install requests --quiet 2>$null

            # Verify requests is importable
            & $pyEmbedExe -c "import requests" 2>$null
            if ($LASTEXITCODE -ne 0) { throw "requests not importable after pip install" }

            $pythonExe = $pyEmbedExe
            Write-OK "Embedded Python ready: $pyEmbedExe"
        } catch {
            if ($pythonExe) {
                Write-Host "[bootstrap] WARN  Embed download failed ($($_.Exception.Message)); falling back to $pythonExe" -ForegroundColor Yellow
                Write-Host "            NOTE: Agent may fail if SYSTEM cannot execute user-profile Python." -ForegroundColor Yellow
            } else {
                Write-Fail "Python not found and embeddable download failed.`n  Install Python from https://www.python.org/downloads/ (select 'Install for all users')`n  then re-run this installer."
            }
        }
    }
} else {
    Write-OK "Python found (system-wide): $pythonExe"
}

# ── Step 7: Create scheduled task ────────────────────────────────────────────
Write-Step "Installing scheduled task..."

# Write a .bat launcher so cmd.exe quoting is trivial and all output goes to
# the log file. Inline cmd /c "..." with nested quotes breaks on Windows.
$LOG_FILE  = Join-Path $INSTALL_DIR "agent_v2.log"
$RUN_BAT   = Join-Path $INSTALL_DIR "run_agent.bat"
$batLines  = "@echo off`r`n`"$pythonExe`" -u `"$AGENT_FILE`" >> `"$LOG_FILE`" 2>&1`r`n"
[System.IO.File]::WriteAllText($RUN_BAT, $batLines, [System.Text.Encoding]::ASCII)

# Remove existing task if present
$existingTask = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
if ($existingTask) {
    Stop-ScheduledTask  -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
}

$action  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$RUN_BAT`""
$trigger = New-ScheduledTaskTrigger -AtStartup

# Also add an AtLogon trigger so it starts when any user logs in
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit       (New-TimeSpan -Hours 0) `
    -RestartCount             10 `
    -RestartInterval          (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable       `
    -RunOnlyIfNetworkAvailable:$false `
    -MultipleInstances        IgnoreNew

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

# Wait up to 15 seconds for the task to transition from Queued → Running
$deadline = (Get-Date).AddSeconds(15)
$state = "Queued"
while ($state -eq "Queued" -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    $state = (Get-ScheduledTask -TaskName $TASK_NAME).State
}

if ($state -eq "Running") {
    Write-OK "Agent task state: Running"
} elseif ($state -eq "Queued") {
    Write-Host "[bootstrap] WARN  Task still Queued after 15s - may start on next login/reboot" -ForegroundColor Yellow
    Write-Host "            Check log: $INSTALL_DIR\agent_v2.log" -ForegroundColor Yellow
} else {
    Write-Host "[bootstrap] INFO  Agent task state: $state" -ForegroundColor Cyan
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Agent enrolled successfully." -ForegroundColor Green
Write-Host "  The agent will appear in your SOC Platform dashboard." -ForegroundColor Green
Write-Host "  Credentials stored at: $CREDS_FILE" -ForegroundColor DarkGray
Write-Host "  Agent script at:       $AGENT_FILE" -ForegroundColor DarkGray
Write-Host "  Scheduled task:        $TASK_NAME (SYSTEM, runs at startup)" -ForegroundColor DarkGray
Write-Host ""
