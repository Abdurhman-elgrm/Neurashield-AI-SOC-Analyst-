<#
.SYNOPSIS
    SOC Analyst Agent — Secure Bootstrap Installer

.DESCRIPTION
    Downloads, verifies, and installs the SOC Analyst Agent on this machine.
    Exchanges the one-time installer token for permanent runtime credentials,
    installs a Windows service, and starts monitoring.

    Security properties:
    - Never executes code from a pipe (iwr | iex)
    - Verifies SHA-256 checksum before executing any downloaded content
    - One-time token is invalidated immediately after successful enrollment
    - Runtime credentials stored via Windows DPAPI (not in plaintext)
    - Requires Administrator elevation

.PARAMETER Token
    One-time installer token generated in the SOC Platform dashboard.
    Format: inst_<random>

.PARAMETER ApiUrl
    SOC Platform API base URL. Pre-configured in your organisation's bootstrap.ps1.

.PARAMETER TenantId
    Tenant UUID from the SOC Platform. Pre-configured in your organisation's bootstrap.ps1.

.PARAMETER ExpectedSha256
    Optional SHA-256 checksum of the installer package for offline verification.

.PARAMETER Force
    Allow reinstall over an existing installation without prompting.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File bootstrap.ps1 -Token inst_AbC123...

.NOTES
    Must be run as Administrator.
    Requires Python 3.11 or newer.
    DO NOT pipe this script from the internet (iwr | iex is insecure).
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'One-time installer token from the SOC Platform dashboard')]
    [ValidatePattern('^inst_[A-Za-z0-9_-]{20,}$')]
    [string]$Token,

    # ── These two values are pre-configured in your org's distributed bootstrap.ps1 ──
    [string]$ApiUrl   = 'https://REPLACE_WITH_YOUR_SOC_PLATFORM_URL',
    [string]$TenantId = 'REPLACE_WITH_YOUR_TENANT_ID',

    [string]$ExpectedSha256 = '',

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Constants ────────────────────────────────────────────────────────────────

$INSTALL_DIR          = 'C:\ProgramData\SOCAnalyst'
$SERVICE_NAME         = 'SOCAnalystAgent'
$SERVICE_DISPLAY      = 'SOC Analyst Agent'
$SERVICE_DESC         = 'Security event collection and forwarding for SOC Platform v2'
$AGENT_VERSION        = '2.0.0'
$LOG_FILE             = Join-Path $INSTALL_DIR 'logs\bootstrap.log'
$PACKAGE_URL          = "$ApiUrl/agent/package/soc-agent-windows.zip"
$MANIFEST_URL         = "$ApiUrl/agent/package/manifest.json"
$MIN_PYTHON_VER       = [Version]'3.11'
$MIN_DISK_MB          = 200      # minimum free space on target drive
$DOWNLOAD_TIMEOUT_SEC = 120
$MAX_DOWNLOAD_RETRIES = 3
$CONNECTIVITY_TIMEOUT = 10

# ─── Logging ──────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Level, [string]$Message, [hashtable]$Fields = @{})
    $ts     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $fields = ($Fields.GetEnumerator() | ForEach-Object {
        '"' + ($_.Key -replace '"', '') + '":"' + ($_.Value -replace '"', '') + '"'
    }) -join ','
    $entry  = '{"ts":"' + $ts + '","level":"' + $Level + '","msg":"' + ($Message -replace '"', '') + '"' +
              $(if ($fields) { ',' + $fields }) + '}'

    $logDir = Split-Path $LOG_FILE -Parent
    if (-not (Test-Path $logDir)) {
        [void](New-Item -ItemType Directory -Path $logDir -Force)
    }

    Add-Content -Path $LOG_FILE -Value $entry -Encoding UTF8
    $colour = switch ($Level) { 'ERROR' { 'Red' } 'WARN' { 'Yellow' } 'INFO' { 'Cyan' } default { 'White' } }
    Write-Host "[$ts][$Level] $Message" -ForegroundColor $colour
}

function Write-Info   { param([string]$m, [hashtable]$f = @{}) Write-Log 'INFO'  $m $f }
function Write-Warn   { param([string]$m, [hashtable]$f = @{}) Write-Log 'WARN'  $m $f }
function Write-Error2 { param([string]$m, [hashtable]$f = @{}) Write-Log 'ERROR' $m $f }

# ─── Cleanup and rollback ─────────────────────────────────────────────────────

$TempDir          = $null
$RollbackRequired = $false
$ServiceWasPresent = $false

function Invoke-Cleanup {
    if ($TempDir -and (Test-Path $TempDir)) {
        Write-Info 'Removing temporary directory' @{ path = $TempDir }
        try { Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue } catch {}
    }
}

function Invoke-Rollback {
    if (-not $RollbackRequired) { return }
    Write-Warn 'Rolling back partial installation'

    # Stop and remove the service if we registered it during this run
    $svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($svc -and (-not $ServiceWasPresent)) {
        if ($svc.Status -eq 'Running') {
            Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        & sc.exe delete $SERVICE_NAME 2>$null | Out-Null
        Write-Info 'Service removed during rollback'
    }

    # Remove credential file to prevent half-enrolled state
    $credFile = Join-Path $INSTALL_DIR 'credentials\runtime.dat'
    if (Test-Path $credFile) {
        Remove-Item -Force $credFile -ErrorAction SilentlyContinue
        Write-Info 'Credential file removed during rollback'
    }

    Invoke-Cleanup
}

# Register cleanup to run on any exit path
trap {
    Invoke-Rollback
    break
}

# ─── Elevation check ──────────────────────────────────────────────────────────

function Assert-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must be run as Administrator. Right-click PowerShell and select "Run as Administrator".'
    }
}

# ─── Pre-flight checks ────────────────────────────────────────────────────────

function Test-DiskSpace {
    param([string]$Drive, [int]$RequiredMB)
    try {
        $disk = Get-PSDrive -Name ($Drive.TrimEnd(':\')) -ErrorAction SilentlyContinue
        if ($null -eq $disk) {
            # Fallback via WMI
            $wmiDisk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='${Drive}:'" -ErrorAction SilentlyContinue
            if ($wmiDisk) {
                $freeMB = [math]::Round($wmiDisk.FreeSpace / 1MB, 0)
            } else {
                Write-Warn 'Could not determine disk space — skipping check'
                return
            }
        } else {
            $freeMB = [math]::Round($disk.Free / 1MB, 0)
        }

        Write-Info 'Disk space check' @{ drive = $Drive; free_mb = $freeMB; required_mb = $RequiredMB }
        if ($freeMB -lt $RequiredMB) {
            throw "Insufficient disk space on ${Drive}: — ${freeMB}MB free, ${RequiredMB}MB required."
        }
    } catch [System.Management.ManagementException] {
        Write-Warn 'WMI unavailable for disk check — skipping'
    }
}

function Test-ApiConnectivity {
    param([string]$Url)
    Write-Info 'Testing API connectivity' @{ url = $Url }
    try {
        $uri  = [System.Uri]$Url
        $host = $uri.Host
        $port = if ($uri.Port -gt 0) { $uri.Port } else { if ($uri.Scheme -eq 'https') { 443 } else { 80 } }

        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect   = $tcpClient.BeginConnect($host, $port, $null, $null)
        $success   = $connect.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($CONNECTIVITY_TIMEOUT))
        if ($success) {
            $tcpClient.EndConnect($connect) | Out-Null
            Write-Info 'API connectivity confirmed'
        } else {
            Write-Warn "Could not reach $host`:$port within ${CONNECTIVITY_TIMEOUT}s — install may fail"
        }
        $tcpClient.Close()
    } catch {
        Write-Warn "Connectivity check failed: $($_.Exception.Message) — proceeding anyway"
    }
}

# ─── SHA-256 verification ─────────────────────────────────────────────────────

function Get-FileSha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $hashBytes = $sha.ComputeHash($stream)
            return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLower()
        } finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
}

function Assert-Checksum {
    param([string]$Path, [string]$Expected)
    if ([string]::IsNullOrEmpty($Expected)) {
        Write-Warn 'No expected checksum provided — skipping offline verification'
        return
    }
    Write-Info 'Verifying SHA-256 checksum' @{ file = (Split-Path $Path -Leaf) }
    $actual = Get-FileSha256 -Path $Path
    if ($actual -ne $Expected.ToLower().Trim()) {
        throw "Checksum mismatch. Expected: $Expected  Got: $actual"
    }
    Write-Info 'Checksum verified' @{ sha256 = $actual.Substring(0, 16) + '...' }
}

# ─── Secure download with retry ───────────────────────────────────────────────

function Invoke-SecureDownload {
    param([string]$Url, [string]$Destination)

    [Net.ServicePointManager]::SecurityProtocol = (
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    )

    $attempt = 0
    $lastError = $null
    while ($attempt -lt $MAX_DOWNLOAD_RETRIES) {
        $attempt++
        Write-Info "Downloading (attempt $attempt/$MAX_DOWNLOAD_RETRIES)" @{ url = $Url }

        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add('User-Agent', "SOCBootstrap/$AGENT_VERSION")
            # Enforce download timeout via proxy with timeout
            $wc.Headers.Add('Cache-Control', 'no-cache')

            # Use asynchronous download so we can impose a timeout
            $task = $wc.DownloadFileTaskAsync([System.Uri]$Url, $Destination)
            if (-not $task.Wait([TimeSpan]::FromSeconds($DOWNLOAD_TIMEOUT_SEC))) {
                $wc.CancelAsync()
                throw "Download timed out after ${DOWNLOAD_TIMEOUT_SEC}s"
            }
            $wc.Dispose()

            if (-not (Test-Path $Destination)) {
                throw "Download reported success but file not found: $Destination"
            }
            $fileSize = (Get-Item $Destination).Length
            if ($fileSize -eq 0) {
                throw "Downloaded file is empty: $Destination"
            }
            Write-Info 'Download complete' @{ bytes = $fileSize }
            return   # success
        } catch {
            $lastError = $_.Exception.Message
            Write-Warn "Download attempt $attempt failed: $lastError"
            if ($attempt -lt $MAX_DOWNLOAD_RETRIES) {
                $delay = $attempt * 5
                Write-Info "Retrying in ${delay}s..."
                Start-Sleep -Seconds $delay
                if (Test-Path $Destination) { Remove-Item $Destination -Force }
            }
        }
    }
    throw "Download failed after $MAX_DOWNLOAD_RETRIES attempts. Last error: $lastError"
}

# ─── Python discovery ─────────────────────────────────────────────────────────

function Find-Python {
    # Check for Microsoft Store Python stub first (it's not a real interpreter)
    $candidates = @(
        'python',
        'python3',
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        'C:\Python313\python.exe',
        'C:\Python312\python.exe',
        'C:\Python311\python.exe',
        "$INSTALL_DIR\python\python.exe"   # embedded distribution
    )

    foreach ($candidate in $candidates) {
        try {
            $verOutput = & $candidate --version 2>&1
            if ($verOutput -match 'Python (\d+\.\d+)') {
                $found = [Version]$Matches[1]

                # Reject Microsoft Store stub (returns app installer, not Python)
                $resolvedPath = (Get-Command $candidate -ErrorAction SilentlyContinue)?.Source
                if ($resolvedPath -and $resolvedPath -like '*WindowsApps*') {
                    Write-Warn "Skipping Microsoft Store Python stub: $resolvedPath"
                    continue
                }

                if ($found -lt $MIN_PYTHON_VER) {
                    Write-Warn "Python $found found at '$candidate' is below minimum $MIN_PYTHON_VER — skipping"
                    continue
                }

                Write-Info 'Python runtime found' @{ path = $candidate; version = $verOutput.ToString().Trim() }
                return $candidate
            }
        } catch { }
    }
    return $null
}

# ─── pip install with retry ───────────────────────────────────────────────────

function Install-PythonDependencies {
    param([string]$PythonExe, [string]$RequirementsFile)

    if (-not (Test-Path $RequirementsFile)) {
        Write-Warn 'requirements.txt not found — skipping dependency install'
        return
    }

    Write-Info 'Installing Python dependencies'
    $attempt = 0
    while ($attempt -lt $MAX_DOWNLOAD_RETRIES) {
        $attempt++
        Write-Info "pip install (attempt $attempt/$MAX_DOWNLOAD_RETRIES)"
        & $PythonExe -m pip install -r $RequirementsFile `
            --quiet --no-warn-script-location --timeout 60
        if ($LASTEXITCODE -eq 0) {
            Write-Info 'Dependencies installed'
            return
        }
        $lastCode = $LASTEXITCODE
        Write-Warn "pip install attempt $attempt failed (exit $lastCode)"
        if ($attempt -lt $MAX_DOWNLOAD_RETRIES) { Start-Sleep -Seconds ($attempt * 10) }
    }
    throw "pip install failed after $MAX_DOWNLOAD_RETRIES attempts"
}

# ─── Directory structure + ACLs ───────────────────────────────────────────────

function Initialize-InstallDirectory {
    $subdirs = @('bin', 'config', 'credentials', 'logs', 'state', 'tmp')
    foreach ($sub in $subdirs) {
        $path = Join-Path $INSTALL_DIR $sub
        if (-not (Test-Path $path)) {
            [void](New-Item -ItemType Directory -Path $path -Force)
        }
    }

    # Credentials directory: restrict to SYSTEM + Administrators only
    $credDir = Join-Path $INSTALL_DIR 'credentials'
    $acl     = Get-Acl $credDir
    $acl.SetAccessRuleProtection($true, $false)  # disable inheritance
    $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

    $rights  = [System.Security.AccessControl.FileSystemRights]::FullControl
    $type    = [System.Security.AccessControl.AccessControlType]::Allow
    $inherit = (
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $prop = [System.Security.AccessControl.PropagationFlags]::None

    foreach ($identity in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, $rights, $inherit, $prop, $type
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $credDir -AclObject $acl

    Write-Info 'Install directory initialised' @{ path = $INSTALL_DIR }
}

# ─── Service installation ─────────────────────────────────────────────────────

function Install-AgentService {
    param([string]$PythonExe, [string]$ServiceScript)

    if (-not (Test-Path $ServiceScript)) {
        throw "Service script not found at: $ServiceScript"
    }

    $script:ServiceWasPresent = $false
    $existing = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($existing) {
        $script:ServiceWasPresent = $true
        Write-Info 'Stopping existing service for reinstall' @{ status = $existing.Status.ToString() }
        if ($existing.Status -eq 'Running') {
            Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
            # Wait up to 10s for stop
            $waited = 0
            while ($waited -lt 10) {
                Start-Sleep -Seconds 1
                $waited++
                $svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
                if ($svc.Status -ne 'Running') { break }
            }
        }
        & sc.exe delete $SERVICE_NAME 2>$null | Out-Null
        Start-Sleep -Seconds 2
    }

    # Register service via pywin32
    Write-Info 'Installing Windows service' @{ name = $SERVICE_NAME; script = $ServiceScript }
    $result = & $PythonExe $ServiceScript install 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Service installation failed (exit $LASTEXITCODE): $result"
    }

    # Configure service recovery: restart on any failure (3 attempts, increasing delays)
    & sc.exe failure $SERVICE_NAME reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>$null | Out-Null

    # Set auto-start
    & sc.exe config $SERVICE_NAME start= auto 2>$null | Out-Null

    # Set service description
    & sc.exe description $SERVICE_NAME $SERVICE_DESC 2>$null | Out-Null

    Write-Info 'Service installed and configured' @{ service = $SERVICE_NAME }
}

function Test-ServiceHealthy {
    param([string]$Name, [int]$TimeoutSecs = 15)
    $elapsed = 0
    while ($elapsed -lt $TimeoutSecs) {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') { return $true }
        Start-Sleep -Seconds 2
        $elapsed += 2
    }
    return $false
}

# ─── Main bootstrap flow ──────────────────────────────────────────────────────

function Invoke-Bootstrap {
    Write-Info '===== SOC Analyst Agent Bootstrap =====' @{ version = $AGENT_VERSION }
    Write-Info 'Starting bootstrap' @{ api_url = $ApiUrl; tenant_id = $TenantId }

    Assert-Administrator

    # Validate parameters
    if ($ApiUrl -like '*REPLACE*' -or $TenantId -like '*REPLACE*') {
        throw 'bootstrap.ps1 has not been configured. ApiUrl and TenantId must be set by your administrator.'
    }
    if (-not ($ApiUrl -match '^https?://')) {
        throw "ApiUrl must be an http/https URL. Got: $ApiUrl"
    }
    if (-not ($TenantId -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')) {
        throw "TenantId '$TenantId' is not a valid UUID."
    }

    # Check for existing install
    $credFile = Join-Path $INSTALL_DIR 'credentials\runtime.dat'
    if ((Test-Path $credFile) -and (-not $Force)) {
        Write-Warn 'Existing installation detected'
        Write-Info 'Re-enrolling with new token (use -Force to suppress this message)'
    }

    # Create temp working directory
    $script:TempDir = Join-Path $env:TEMP ('SOCInstall-' + [System.Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $TempDir -Force)
    Write-Info 'Temp directory created' @{ path = $TempDir }

    $script:RollbackRequired = $true  # enable rollback from this point forward

    # ── Pre-flight ────────────────────────────────────────────────────────────
    $installDrive = (Split-Path $INSTALL_DIR -Qualifier).TrimEnd(':')
    Test-DiskSpace -Drive $installDrive -RequiredMB $MIN_DISK_MB
    Test-ApiConnectivity -Url $ApiUrl

    # ── Step 1: Discover Python ───────────────────────────────────────────────
    Write-Info 'Step 1/7: Locating Python runtime'
    $pythonExe = Find-Python
    if (-not $pythonExe) {
        throw "Python $MIN_PYTHON_VER+ not found. Install from https://www.python.org/downloads/ and ensure it is added to PATH."
    }

    # ── Step 2: Download installer package ───────────────────────────────────
    Write-Info 'Step 2/7: Downloading agent package'
    $packagePath  = Join-Path $TempDir 'soc-agent.zip'
    $manifestPath = Join-Path $TempDir 'manifest.json'

    Invoke-SecureDownload -Url $MANIFEST_URL -Destination $manifestPath
    Invoke-SecureDownload -Url $PACKAGE_URL  -Destination $packagePath

    # ── Step 3: Verify SHA-256 checksum ──────────────────────────────────────
    Write-Info 'Step 3/7: Verifying package integrity'
    $manifestExpected = $ExpectedSha256
    if (-not $manifestExpected -and (Test-Path $manifestPath)) {
        try {
            $manifest         = Get-Content $manifestPath -Raw | ConvertFrom-Json
            $manifestExpected = $manifest.sha256
        } catch {
            Write-Warn 'Could not parse manifest — using provided ExpectedSha256 only'
        }
    }
    Assert-Checksum -Path $packagePath -Expected $manifestExpected

    # ── Step 4: Extract installer ─────────────────────────────────────────────
    Write-Info 'Step 4/7: Extracting installer package'
    $extractDir = Join-Path $TempDir 'extracted'
    Expand-Archive -Path $packagePath -DestinationPath $extractDir -Force
    Write-Info 'Package extracted' @{ dest = $extractDir }

    # ── Step 5: Initialise install directory with restricted ACLs ─────────────
    Write-Info 'Step 5/7: Initialising installation directory'
    Initialize-InstallDirectory

    # ── Step 6: Run Python installer (enrolls agent, stores DPAPI creds) ─────
    Write-Info 'Step 6/7: Running agent installer'
    $installerScript = Join-Path $extractDir 'install.py'
    if (-not (Test-Path $installerScript)) {
        throw "Installer script not found at: $installerScript"
    }

    # Install Python dependencies with retry
    $requirementsFile = Join-Path $extractDir 'requirements.txt'
    Install-PythonDependencies -PythonExe $pythonExe -RequirementsFile $requirementsFile

    $installerArgs = @(
        $installerScript,
        '--token',      $Token,
        '--tenant-id',  $TenantId,
        '--api-url',    $ApiUrl,
        '--install-dir', $INSTALL_DIR,
        '--hostname',   $env:COMPUTERNAME,
        '--os-type',    'windows'
    )

    Write-Info 'Running install.py'
    & $pythonExe @installerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Installer exited with code $LASTEXITCODE. Check $LOG_FILE for details."
    }

    # ── Step 7: Install and start Windows service ─────────────────────────────
    Write-Info 'Step 7/7: Installing Windows service'
    # Service script is installed at bin\soc_agent\service.py by install.py
    $serviceScript = Join-Path $INSTALL_DIR 'bin\soc_agent\service.py'
    Install-AgentService -PythonExe $pythonExe -ServiceScript $serviceScript

    Write-Info 'Starting service'
    Start-Service -Name $SERVICE_NAME

    if (-not (Test-ServiceHealthy -Name $SERVICE_NAME -TimeoutSecs 15)) {
        $svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
        $status = if ($svc) { $svc.Status.ToString() } else { 'not found' }
        throw "Service failed to start within 15s. Status: $status. Check $LOG_FILE."
    }

    $script:RollbackRequired = $false  # install succeeded — disable rollback

    Write-Info '===== Bootstrap complete =====' @{
        service = $SERVICE_NAME
        status  = (Get-Service -Name $SERVICE_NAME).Status.ToString()
        log     = $LOG_FILE
    }
    Write-Host ''
    Write-Host '  Installation complete.' -ForegroundColor Green
    Write-Host "  Service '$SERVICE_NAME' is running." -ForegroundColor Green
    Write-Host "  Agent will appear in the SOC Platform within 60 seconds." -ForegroundColor Green
    Write-Host ''
}

# ─── Entry point ──────────────────────────────────────────────────────────────

try {
    Invoke-Bootstrap
} catch {
    Write-Error2 'Bootstrap failed' @{ error = ($_.Exception.Message -replace '"', "'") }
    Write-Host "`n  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  See log: $LOG_FILE" -ForegroundColor Red
    Invoke-Rollback
    exit 1
} finally {
    Invoke-Cleanup
}
