# ============================================================
# Security Monitor - Setup Script
# Run once as Administrator to install everything.
# ============================================================
#Requires -Version 5.0

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Security Monitor - Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# - 1. Check admin -
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Please re-run as Administrator (right-click PowerShell -> Run as administrator)." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# - 2. Find Python -
Write-Host "[1/5] Checking for Python..." -ForegroundColor Yellow
$python = $null

foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3") {
            $python = $cmd
            Write-Host "      Found: $ver  (command: $cmd)" -ForegroundColor Green
            break
        }
    } catch {}
}

if (-not $python) {
    Write-Host "[!] Python 3 not found." -ForegroundColor Red
    Write-Host "    Download from: https://python.org (check 'Add Python to PATH')" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# - 3. Install psutil -
Write-Host "[2/5] Installing required Python packages..." -ForegroundColor Yellow
& $python -m pip install psutil --quiet --upgrade
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] pip install failed. Check your internet connection." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "      psutil installed/updated." -ForegroundColor Green

# - 4. Interactive Configuration -
Write-Host "[3/5] Configuring settings..." -ForegroundColor Yellow
$configPath = Join-Path $ScriptDir "config.json"

Write-Host "      This script will run daily. You can receive the summary via email." -ForegroundColor White
Write-Host "      Leave the email blank to skip email notifications." -ForegroundColor Gray
$userEmail = Read-Host -Prompt "      Enter your Gmail address (e.g. name@gmail.com)"
$appPassword = "YOUR_GMAIL_APP_PASSWORD_HERE"

if ($userEmail -match ".+@.+\..+") {
    Write-Host "      You can create an App Password at: https://myaccount.google.com/apppasswords" -ForegroundColor Cyan
    $appPassword = Read-Host -Prompt "      Enter your 16-character Gmail App Password"
} else {
    Write-Host "      Email skipped or invalid format. No emails will be sent." -ForegroundColor Gray
    $userEmail = "your-email@gmail.com"
}

$cfgObj = @{
    email = @{
        to = $userEmail
        from = $userEmail
        app_password = $appPassword
        smtp_host = "smtp.gmail.com"
        smtp_port = 587
    }
}
$cfgObj | ConvertTo-Json -Depth 5 | Set-Content $configPath -Encoding UTF8
Write-Host "      Configuration saved securely to config.json." -ForegroundColor Green

# - 5. Scheduled Task Configuration -
Write-Host "[4/5] Registering Windows Scheduled Task..." -ForegroundColor Yellow

$scheduleTime = Read-Host -Prompt "      What time should the script run every day? (e.g. 09:00, 15:30) [Default: 09:00]"
if ([string]::IsNullOrWhiteSpace($scheduleTime) -or -not ($scheduleTime -match "^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$")) {
    $scheduleTime = "09:00"
}

$taskName = "DailySecurityMonitor"

$scriptPath = Join-Path $ScriptDir "security_check.py"
$pythonFull = $null
try {
    $pythonFull = (Get-Command $python -ErrorAction Stop).Source
} catch {
    try {
        $pythonFull = (where.exe $python 2>$null | Select-Object -First 1).Trim()
    } catch {}
}

if (-not $pythonFull -or -not (Test-Path $pythonFull)) {
    Write-Host "      Could not find python.exe path. Trying 'python' directly." -ForegroundColor Yellow
    $pythonFull = "python"
}

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

$action = New-ScheduledTaskAction `
    -Execute $pythonFull `
    -Argument "`"$scriptPath`"" `
    -WorkingDirectory $ScriptDir

$trigger1 = New-ScheduledTaskTrigger -Daily -At $scheduleTime
$trigger2 = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Limited

try {
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger1, $trigger2 `
        -Settings $settings `
        -Principal $principal `
        -Description "Daily security check - scans for threats and prompt-injection risks." `
        -Force | Out-Null
    Write-Host "      Task 'DailySecurityMonitor' registered successfully for $scheduleTime!" -ForegroundColor Green
} catch {
    Write-Host "      [!] Could not register task: $_" -ForegroundColor Red
    Write-Host "      You can run the script manually: python `"$scriptPath`"" -ForegroundColor Yellow
}

# - 6. Quick test run -
Write-Host "[5/5] Running a quick test..." -ForegroundColor Yellow
& $python $scriptPath 2>&1 | Select-Object -Last 10
Write-Host "      Test run complete. Output is colorized." -ForegroundColor Green


# - Done -
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Setup complete!" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Open config.json in this folder (with Notepad)." -ForegroundColor White
Write-Host "  2. Replace YOUR_GMAIL_APP_PASSWORD_HERE with your Gmail App Password." -ForegroundColor White
Write-Host "     (see README.txt for instructions - takes about 2 minutes)" -ForegroundColor Gray
Write-Host "  3. The check will run automatically every day at 09:00." -ForegroundColor White
Write-Host ""
Write-Host "To run NOW open a terminal here and type:" -ForegroundColor White
Write-Host "  python security_check.py" -ForegroundColor Gray
Write-Host ""
Write-Host "Logs: $ScriptDir\security_log.txt" -ForegroundColor DarkGray
Write-Host ""
Read-Host "Press Enter to exit"
