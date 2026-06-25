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
$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"

# Enable TLS 1.2 + system proxy (enterprise networks need this)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    $sysProxy = [System.Net.WebRequest]::GetSystemWebProxy()
    $sysProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    [System.Net.WebRequest]::DefaultWebProxy = $sysProxy
} catch {}

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

# ── Step 6: Find / provision Python ──────────────────────────────────────────
Write-Step "Locating Python runtime..."

$pythonExe = $null

# 1. Try PATH (python / py / python3)
foreach ($cmd in @("python", "py", "python3")) {
    try {
        $p = (Get-Command $cmd -ErrorAction Stop).Source
        if ($p -and $p -notlike "*WindowsApps*") { $pythonExe = $p; break }
    } catch {}
}

# 2. Glob search - finds any Python 3.x without hardcoding version numbers
if (-not $pythonExe) {
    foreach ($glob in @(
        "$env:LocalAppData\Programs\Python\Python3*\python.exe",
        "$env:ProgramFiles\Python3*\python.exe",
        "C:\Python3*\python.exe",
        "$env:ProgramW6432\Python3*\python.exe"
    )) {
        $found = Resolve-Path $glob -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($found) { $pythonExe = $found.Path; break }
    }
}

# Validate: reject stubs and incompatible runtimes
if ($pythonExe -like "*WindowsApps*") {
    Write-Host "[bootstrap] WARN  Microsoft Store Python stub ignored (cannot install packages)" -ForegroundColor Yellow
    $pythonExe = $null
}
if ($pythonExe -match "msys|mingw|cygwin") {
    Write-Host "[bootstrap] WARN  MSYS2/MinGW Python ignored (DLLs unavailable under SYSTEM)" -ForegroundColor Yellow
    $pythonExe = $null
}
if ($pythonExe) {
    $pyVer = & $pythonExe -c "import sys; print(sys.version_info.major)" 2>$null
    if ($LASTEXITCODE -ne 0 -or "$pyVer" -ne "3") {
        Write-Host "[bootstrap] WARN  $pythonExe is not Python 3 - ignoring" -ForegroundColor Yellow
        $pythonExe = $null
    }
}

# 3. Portable Python fallback - uses WebClient with system proxy like V1
if (-not $pythonExe) {
    Write-Step "No Python found - downloading portable Python 3.12..."
    $pyDir = Join-Path $INSTALL_DIR "py312"
    $pyZip = Join-Path $env:TEMP "neurashield_py312.zip"
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        $wc.DownloadFile("https://www.python.org/ftp/python/3.12.9/python-3.12.9-embed-amd64.zip", $pyZip)

        [System.IO.Directory]::CreateDirectory($pyDir) | Out-Null
        Expand-Archive -Path $pyZip -DestinationPath $pyDir -Force
        Remove-Item $pyZip -Force -ErrorAction SilentlyContinue

        $pthFile = Get-Item "$pyDir\python312._pth" -ErrorAction SilentlyContinue
        if ($pthFile) {
            (Get-Content $pthFile.FullName) -replace '#import site', 'import site' |
                Set-Content $pthFile.FullName
        }

        $wc.DownloadFile("https://bootstrap.pypa.io/get-pip.py", "$pyDir\get-pip.py")
        & "$pyDir\python.exe" "$pyDir\get-pip.py" --quiet 2>&1 | Out-Null
        Remove-Item "$pyDir\get-pip.py" -Force -ErrorAction SilentlyContinue

        $pythonExe = "$pyDir\python.exe"
        Write-OK "Portable Python 3.12 ready at $pythonExe"
    } catch {
        Write-Fail "No Python found and portable download failed.`n  Install Python from https://www.python.org/downloads/ then re-run."
    }
}

Write-OK "Python: $pythonExe"

# ── Step 6b: Install dependencies (requests + pywin32) ───────────────────────
Write-Step "Installing Python dependencies..."

& $pythonExe -m pip install requests pywin32 --quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    & $pythonExe -m pip install requests pywin32 --quiet 2>&1 | Out-Null
}

# Verify requests
$reqCheck = & $pythonExe -c "import requests; print('ok')" 2>$null
if ($reqCheck -ne "ok") {
    Write-Fail "'requests' not importable after pip install. Try: $pythonExe -m pip install requests"
}

# pywin32 post-install (registers DLLs under SYSTEM context)
$siteScripts = & $pythonExe -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null
if ($siteScripts) {
    $postInstall = Join-Path $siteScripts "pywin32_postinstall.py"
    if (Test-Path $postInstall) { & $pythonExe $postInstall -install 2>$null | Out-Null }
}
$win32Check = & $pythonExe -c "import win32evtlog; print('ok')" 2>$null
if ($win32Check -ne "ok") {
    & $pythonExe -m pip install pywin32 --force-reinstall --quiet 2>&1 | Out-Null
    if ($siteScripts -and (Test-Path (Join-Path $siteScripts "pywin32_postinstall.py"))) {
        & $pythonExe (Join-Path $siteScripts "pywin32_postinstall.py") -install 2>$null | Out-Null
    }
}

Write-OK "Dependencies OK (requests + pywin32)"

# Use pythonw.exe (windowless) for the scheduled task if available
$pythonwExe = $pythonExe -replace 'python\.exe$', 'pythonw.exe'
if (-not (Test-Path $pythonwExe)) { $pythonwExe = $pythonExe }

# ── Step 7: Create scheduled task (requires admin) or fall back ───────────────
Write-Step "Installing scheduled task..."

$LOG_FILE = Join-Path $INSTALL_DIR "agent_v2.log"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$taskInstalled = $false

if ($isAdmin) {
    # Remove existing task if present
    $existingTask = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    if ($existingTask) {
        Stop-ScheduledTask  -TaskName $TASK_NAME -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    }

    $action  = New-ScheduledTaskAction -Execute $pythonwExe -Argument "-u `"$AGENT_FILE`"" -WorkingDirectory $INSTALL_DIR
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $logonTrigger    = New-ScheduledTaskTrigger -AtLogOn
    $watchdogTrigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 30) `
        -Once -At ([datetime]::Today)

    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit       (New-TimeSpan -Hours 0) `
        -RestartCount             10 `
        -RestartInterval          (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable       `
        -RunOnlyIfNetworkAvailable:$false `
        -MultipleInstances        Queue

    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Register-ScheduledTask `
            -TaskName  $TASK_NAME `
            -Action    $action `
            -Trigger   @($trigger, $logonTrigger, $watchdogTrigger) `
            -Settings  $settings `
            -Principal $principal `
            -Force -ErrorAction Stop | Out-Null
        $taskInstalled = $true
        Write-OK "Scheduled task '$TASK_NAME' installed (runs as SYSTEM at startup)"
    } catch {
        Write-Host "[bootstrap] WARN  Scheduled task registration failed: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[bootstrap] WARN  Not running as Administrator -- scheduled task skipped." -ForegroundColor Yellow
    Write-Host "            Re-run as admin to install persistent service." -ForegroundColor Yellow
    Write-Host "            Re-run: Start-Process PowerShell -Verb RunAs" -ForegroundColor DarkGray
}

# ── Step 8: Start agent and verify it is running ─────────────────────────────
Write-Step "Starting agent..."

# Snapshot log modification time before starting -- we verify against this
$logBefore = if (Test-Path $LOG_FILE) { (Get-Item $LOG_FILE).LastWriteTime } else { [datetime]::MinValue }

if ($taskInstalled) {
    Start-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
} else {
    # Fallback: run agent directly as current user (no admin required)
    Write-Host "[bootstrap] INFO  Starting agent as current user (no SYSTEM task)..." -ForegroundColor Cyan
    Start-Process -FilePath $pythonwExe -ArgumentList "-u `"$AGENT_FILE`"" -WorkingDirectory $INSTALL_DIR
}

# Wait up to 25 seconds for the log to show NEW activity (not just existence)
$deadline = (Get-Date).AddSeconds(25)
$agentStarted = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    if (Test-Path $LOG_FILE) {
        $logAfter = (Get-Item $LOG_FILE).LastWriteTime
        if ($logAfter -gt $logBefore) { $agentStarted = $true; break }
    }
}

if ($agentStarted) {
    Write-OK "Agent is running (log activity confirmed)"
    Get-Content $LOG_FILE -Tail 3 | ForEach-Object { Write-Host "  > $_" -ForegroundColor DarkGray }
} else {
    # Check for startup errors
    $stderrFile = Join-Path $INSTALL_DIR "agent_stderr.txt"
    Write-Host "[bootstrap] WARN  Agent log did not update in 25s -- checking for errors..." -ForegroundColor Yellow
    if (Test-Path $stderrFile) {
        $errLines = Get-Content $stderrFile -ErrorAction SilentlyContinue
        if ($errLines) {
            Write-Host "[bootstrap] ERR   Agent startup error:" -ForegroundColor Red
            $errLines | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        }
    }
    if ($taskInstalled) {
        $state = (Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue).State
        Write-Host "[bootstrap] INFO  Task state: $state" -ForegroundColor DarkGray
    }
    Write-Host "[bootstrap]       The agent will retry on next login/reboot." -ForegroundColor Yellow
    Write-Host "            To diagnose: Get-Content '$LOG_FILE'" -ForegroundColor DarkGray
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Agent enrolled successfully." -ForegroundColor Green
Write-Host "  Credentials stored at: $CREDS_FILE" -ForegroundColor DarkGray
Write-Host "  Agent script at:       $AGENT_FILE" -ForegroundColor DarkGray
if ($taskInstalled) {
    Write-Host "  Scheduled task:        $TASK_NAME (SYSTEM, runs at startup)" -ForegroundColor DarkGray
} else {
    Write-Host "  NOTE: Run as Administrator to install as a persistent SYSTEM service." -ForegroundColor Yellow
}
Write-Host ""
