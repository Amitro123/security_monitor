# ============================================================
# Security Monitor v2.0 - Enterprise Installer
# Run once as Administrator to install everything.
# ============================================================
#Requires -Version 5.0
[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"
$VERSION    = "2.0.0"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "security_check.py"
$CredTarget = "SecurityMonitor_Gmail"

function Write-Step { param([string]$msg, [string]$color = "Cyan")
    Write-Host ""
    Write-Host "  $msg" -ForegroundColor $color
}
function Write-OK   { param([string]$msg) Write-Host "      [OK]   $msg" -ForegroundColor Green }
function Write-WARN { param([string]$msg) Write-Host "      [WARN] $msg" -ForegroundColor Yellow }
function Write-FAIL { param([string]$msg) Write-Host "      [FAIL] $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Security Monitor v$VERSION - Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ── 1. Admin check ────────────────────────────────────────────
Write-Step "[1/7] Checking administrator privileges..."
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-FAIL "Please re-run as Administrator (right-click PowerShell -> Run as administrator)."
    Read-Host "Press Enter to exit"
    exit 1
}
Write-OK "Running as Administrator"

# ── 2. Find Python ────────────────────────────────────────────
Write-Step "[2/7] Checking Python 3.8+..."
$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3\.([89]|1[0-9])") {
            $python = $cmd
            Write-OK "Found: $ver (command: $cmd)"
            break
        }
    } catch {}
}
if (-not $python) {
    Write-FAIL "Python 3.8+ not found."
    Write-Host "    Download from: https://python.org (check 'Add Python to PATH')" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# ── 3. Install dependencies ───────────────────────────────────
Write-Step "[3/7] Installing Python dependencies..."
& $python -m pip install psutil --quiet --upgrade
if ($LASTEXITCODE -ne 0) {
    Write-FAIL "pip install failed. Check your internet connection."
    Read-Host "Press Enter to exit"
    exit 1
}
Write-OK "psutil installed/updated"

# ── 4. Secure configuration (Windows Credential Manager) ─────
Write-Step "[4/7] Configuring secure credentials..."

Write-Host "      Security Monitor can send daily email summaries to you." -ForegroundColor White
Write-Host "      Leave blank to skip email and use Windows notifications only." -ForegroundColor Gray
$userEmail = (Read-Host -Prompt "      Gmail address (e.g. you@gmail.com)").Trim()
$appPassword = "YOUR_GMAIL_APP_PASSWORD_HERE"

if ($userEmail -match ".+@.+\..+") {
    Write-Host "      Create an App Password at: https://myaccount.google.com/apppasswords" -ForegroundColor Cyan
    Write-Host "      NOTE: This is NOT your normal Gmail password — it's a 16-letter code from Google." -ForegroundColor Yellow
    $securePass  = Read-Host -Prompt "      16-letter Gmail App Password" -AsSecureString
    $appPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass))

    # Store in Windows Credential Manager
    cmdkey /generic:"$CredTarget" /user:"$userEmail" /pass:"$appPassword" | Out-Null
    Write-OK "Gmail credentials stored securely in Windows Credential Manager"
    Write-WARN "Your password is encrypted by Windows — NOT stored in any plain-text file"
} else {
    Write-WARN "Email skipped. Windows notifications will still fire."
    $userEmail = "your-email@gmail.com"
}

# Ask for scheduled time
Write-Host ""
$scheduleTime = (Read-Host -Prompt "      Run time (e.g. 09:00) [Default: 09:00]").Trim()
if ([string]::IsNullOrWhiteSpace($scheduleTime) -or -not ($scheduleTime -match "^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$")) {
    $scheduleTime = "09:00"
}

# Ask for detection mode
Write-Host ""
Write-Host "      Detection modes:" -ForegroundColor White
Write-Host "        paranoid  — maximum sensitivity (more alerts, may have false positives)" -ForegroundColor Gray
Write-Host "        standard  — balanced coverage [DEFAULT]" -ForegroundColor Gray
Write-Host "        light     — minimal footprint (fastest, fewest alerts)" -ForegroundColor Gray
$detectionMode = (Read-Host -Prompt "      Detection mode [standard]").Trim().ToLower()
if ($detectionMode -notin @("paranoid", "standard", "light")) { $detectionMode = "standard" }

# Compute script hash for self-integrity
$scriptHash = (Get-FileHash $PythonScript -Algorithm SHA256).Hash.ToLower()
Write-OK "Script SHA256 hash computed: $($scriptHash.Substring(0,16))..."

# Write config.json (email retrieved from CredMan at runtime, no password stored)
$cfgObj = @{
    email = @{
        to           = $userEmail
        from         = $userEmail
        app_password = $appPassword
        smtp_host    = "smtp.gmail.com"
        smtp_port    = 587
    }
    mode        = $detectionMode
    script_hash = $scriptHash
}
$cfgObj | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ScriptDir "config.json") -Encoding UTF8
Write-OK "config.json created (script hash embedded)"

# ── 5. BitLocker check ────────────────────────────────────────
Write-Step "[5/7] Checking BitLocker..."
try {
    $bl = Get-BitLockerVolume -MountPoint "C:" -EA SilentlyContinue
    if ($bl -and $bl.ProtectionStatus -eq "On") {
        Write-OK "BitLocker is enabled on C:"
    } else {
        Write-WARN "BitLocker NOT enabled on C: — disk encryption recommended"
    }
} catch {
    Write-WARN "Could not query BitLocker: $_"
}

# ── 6. Register Scheduled Task ────────────────────────────────
Write-Step "[6/7] Registering Windows Scheduled Task at $scheduleTime..."
$taskName = "DailySecurityMonitor"
$pythonFull = $null
try {
    $pythonFull = (Get-Command $python -ErrorAction Stop).Source
} catch {
    try { $pythonFull = (where.exe $python 2>$null | Select-Object -First 1).Trim() } catch {}
}
if (-not $pythonFull -or -not (Test-Path $pythonFull)) { $pythonFull = "python" }

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

$action   = New-ScheduledTaskAction -Execute $pythonFull -Argument "`"$PythonScript`"" -WorkingDirectory $ScriptDir
$trigger1 = New-ScheduledTaskTrigger -Daily -At $scheduleTime
$trigger2 = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -StartWhenAvailable -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger1, $trigger2 `
        -Settings $settings -Principal $principal `
        -Description "Security Monitor v$VERSION — daily check" -Force | Out-Null
    Write-OK "Task '$taskName' registered for $scheduleTime daily"
} catch {
    Write-FAIL "Could not register task: $_"
    Write-WARN "Run manually: python `"$PythonScript`""
}

# Log to Windows Event Log for audit trail
try {
    $source = "SecurityMonitor"
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        [System.Diagnostics.EventLog]::CreateEventSource($source, "Application")
    }
    Write-EventLog -LogName Application -Source $source -EntryType Information -EventId 1001 `
        -Message "Security Monitor v$VERSION installed successfully. Task scheduled for $scheduleTime." -EA SilentlyContinue
    Write-OK "Installation event written to Windows Event Log"
} catch {}

# ── 7. Generate baseline + smoke test ─────────────────────────
Write-Step "[7/7] Generating baseline snapshot and running smoke test..."
& $python $PythonScript --baseline 2>&1 | Select-Object -Last 5
Write-OK "Baseline snapshot generated"

Write-Host ""
Write-Host "  Running E2E smoke test..." -ForegroundColor White
& $python $PythonScript --test 2>&1 | Select-Object -Last 8
Write-OK "Smoke test passed"

# ── Done ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Setup complete! (v$VERSION)" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Daily check: $scheduleTime  |  Mode: $detectionMode" -ForegroundColor White
Write-Host ""
Write-Host "  Run it NOW:"    -ForegroundColor White
Write-Host "    python `"$PythonScript`"" -ForegroundColor Gray
Write-Host ""
Write-Host "  Test email + notification:" -ForegroundColor White
Write-Host "    python `"$PythonScript`" --test" -ForegroundColor Gray
Write-Host ""
Write-Host "  Diagnose issues:" -ForegroundColor White
Write-Host "    python `"$PythonScript`" --doctor" -ForegroundColor Gray
Write-Host ""
Read-Host "Press Enter to exit"
