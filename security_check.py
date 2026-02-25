#!/usr/bin/env python3
"""
Security Monitor - Daily Security Check Script
===============================================
Checks for security vulnerabilities, prompt injection risks,
browser threats, and suspicious system activity.

Built for Amit | February 2026
"""

import os
import sys

# Enable ANSI escape sequences on Windows
if os.name == 'nt':
    os.system("")
import json
import datetime
import subprocess
import smtplib
import re
from pathlib import Path
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Auto-install psutil if missing ──────────────────────────────────────────
try:
    import psutil
except ImportError:
    print("Installing required package: psutil...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "-q"])
    import psutil

# ── Windows registry (Windows only) ─────────────────────────────────────────
try:
    import winreg
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False

# ============================================================
# CONFIGURATION
# ============================================================
BASE_DIR    = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"
LOG_FILE    = BASE_DIR / "security_log.txt"

DEFAULT_CONFIG = {
    "email": {
        "to":           "your-email@gmail.com",
        "from":         "your-email@gmail.com",
        "app_password": "YOUR_GMAIL_APP_PASSWORD_HERE",
        "smtp_host":    "smtp.gmail.com",
        "smtp_port":    587
    }
}

# ── Threat signatures ────────────────────────────────────────────────────────
SUSPICIOUS_PROCESS_PATTERNS = [
    r'miner', r'xmrig', r'nicehash', r'ngrok', r'frp',
    r'netcat', r'\bnc\b', r'psexec', r'mimikatz',
    r'meterpreter', r'payload', r'inject', r'hook',
    r'keylog', r'spyware', r'rat\.exe', r'trojan',
]

KNOWN_MALICIOUS_EXTENSIONS = {
    "bcjindcccaagfpapjjmafapmmgkkhgoa",
    "hmgpakheknlgcbjnllfmhbpcomggkdop",
    "oocalimimngaihdkbihfgmpkcpnmlaoa",
}

DANGEROUS_CHROME_PERMISSIONS = {
    "nativeMessaging", "debugger", "proxy",
    "webRequest", "webRequestBlocking",
    "clipboardRead", "clipboardWrite",
    "cookies", "history", "bookmarks",
    "management", "downloads",
}

SUSPICIOUS_PORTS = {
    4444, 4445, 4446,   # Metasploit
    1080,               # SOCKS proxy
    31337,              # Common backdoor
    6667, 6668, 6669,   # IRC / botnets
    9001, 9030,         # Tor
}

INJECTION_PATTERNS = [
    r'ignore\s+previous\s+instructions',
    r'disregard\s+.*instructions',
    r'you\s+are\s+now\s+',
    r'act\s+as\s+',
    r'jailbreak',
    r'bypass\s+.*safety',
    r'override\s+.*system',
    r'<script[\s>]',
    r'javascript\s*:',
    r'eval\s*\(',
    r'exec\s*\(',
    r'__import__\s*\(',
    r'system\s*\(',
]

# ============================================================
# UTILITIES
# ============================================================
def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, encoding="utf-8-sig") as f:
            cfg = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            if k not in cfg:
                cfg[k] = v
        return cfg
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    return DEFAULT_CONFIG.copy()


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    WHITE = '\033[97m'

def log(msg: str):
    ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    color = Colors.RESET
    msg_upper = msg.upper()
    if "ISSUE" in msg_upper or "CRITICAL" in msg_upper or "WARNING" in msg_upper or "FAILED" in msg_upper or "EXCEPTION" in msg_upper:
        color = Colors.RED
    elif "SUSPICIOUS" in msg_upper or "POTENTIAL" in msg_upper or "RISKY" in msg_upper or "ALERT" in msg_upper:
        color = Colors.YELLOW
    elif "OK" in msg_upper or "PASSED" in msg_upper or "SUCCESS" in msg_upper or "ACTIVE" in msg_upper or "CLEAN" in msg_upper:
        color = Colors.GREEN

    colored_line = f"[{ts}] {color}{msg}{Colors.RESET}"
    plain_line = f"[{ts}] {msg}"
    
    print(colored_line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(plain_line + "\n")


def send_windows_notification(title: str, body: str):
    """Send a Windows 10/11 Toast Notification via PowerShell."""
    if not IS_WINDOWS:
        return
    title = title.replace('"', '""').replace("'", "''")
    body  = body.replace('"',  '""').replace("'", "''")
    log_path = str(LOG_FILE).replace('\\', '/')
    
    ps = f"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$appId = '{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\WindowsPowerShell\\v1.0\\powershell.exe'

$template = @"
<toast activationType="protocol" launch="file:///{log_path}">
    <visual>
        <binding template="ToastGeneric">
            <text>{title}</text>
            <text>{body}</text>
        </binding>
    </visual>
</toast>
"@

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
"""
    try:
        subprocess.Popen(
            ["powershell", "-WindowStyle", "Hidden", "-Command", ps],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except Exception as e:
        log(f"[Notification] Could not send: {e}")


# ============================================================
# SECURITY CHECKS
# ============================================================

# ── 1. Chrome Extensions ─────────────────────────────────────────────────────
def check_chrome_extensions():
    findings = []
    username = os.environ.get("USERNAME", os.environ.get("USER", ""))
    ext_root = Path(f"C:/Users/{username}/AppData/Local/Google/Chrome/User Data")

    if not ext_root.exists():
        return findings, "Chrome not found on this machine"

    profiles   = [ext_root / "Default"] + list(ext_root.glob("Profile *"))
    total_exts = 0
    suspicious = 0

    for profile in profiles:
        ext_dir = profile / "Extensions"
        if not ext_dir.exists():
            continue
        for ext_folder in ext_dir.iterdir():
            if not ext_folder.is_dir():
                continue
            ext_id       = ext_folder.name
            version_dirs = sorted(ext_folder.iterdir(), reverse=True)
            for vdir in version_dirs:
                manifest_path = vdir / "manifest.json"
                if not manifest_path.exists():
                    continue
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    break

                total_exts += 1
                name       = manifest.get("name", ext_id)
                perms      = set(manifest.get("permissions", []))
                host_perms = manifest.get("host_permissions", []) + manifest.get("permissions", [])

                if ext_id in KNOWN_MALICIOUS_EXTENSIONS:
                    suspicious += 1
                    findings.append(f"CRITICAL – Known malicious extension: {name} ({ext_id})")
                    break

                danger_found = perms & DANGEROUS_CHROME_PERMISSIONS
                all_urls = any(h in ("<all_urls>", "*://*/*", "http://*/*") for h in host_perms)
                if len(danger_found) >= 3 and all_urls:
                    suspicious += 1
                    findings.append(
                        f"High-risk extension: '{name}' "
                        f"[{', '.join(sorted(danger_found))}] + all-URL access"
                    )
                break

    summary = f"{total_exts} extensions found" + (f", {suspicious} suspicious" if suspicious else " – OK")
    return findings, summary


# ── 2. Windows Startup Registry ──────────────────────────────────────────────
def check_startup_items():
    findings = []
    if not IS_WINDOWS:
        return findings, "Skipped (not Windows)"

    paths = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    SUSPECT_DIRS = (r'\temp\\', r'\appdata\roaming\\', r'\appdata\local\temp\\', r'\downloads\\')
    total = 0

    for hive, path in paths:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    total    += 1
                    val_lower = value.lower()
                    for pat in SUSPICIOUS_PROCESS_PATTERNS:
                        if re.search(pat, name, re.I) or re.search(pat, value, re.I):
                            findings.append(f"Suspicious startup entry: '{name}' -> {value}")
                            break
                    else:
                        for d in SUSPECT_DIRS:
                            if d in val_lower:
                                findings.append(f"Startup from risky location: '{name}' -> {value}")
                                break
                    i += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)

    summary = f"{total} startup entries" + (" – OK" if not findings else "")
    return findings, summary


# ── 3. Running Processes ─────────────────────────────────────────────────────
def check_running_processes():
    findings  = []
    RISKY_DIRS = (r'\temp\\', r'\downloads\\', r'\appdata\local\temp\\')
    count     = 0

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info  = proc.info
            pname = (info.get("name") or "").lower()
            pexe  = (info.get("exe")  or "").lower()
            count += 1
            for pat in SUSPICIOUS_PROCESS_PATTERNS:
                if re.search(pat, pname, re.I) or re.search(pat, pexe, re.I):
                    findings.append(f"Suspicious process: {info['name']} (PID {info['pid']}) — {info['exe']}")
                    break
            else:
                for d in RISKY_DIRS:
                    if d in pexe:
                        findings.append(f"Process from risky path: {info['name']} (PID {info['pid']}) — {info['exe']}")
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    summary = f"{count} processes checked" + (" – OK" if not findings else "")
    return findings, summary


# ── 4. Network Connections ───────────────────────────────────────────────────
def check_network_connections():
    findings = []
    PRIVATE  = ("127.", "::1", "0.0.0.0", "192.168.", "10.", "172.16.",
                 "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                 "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                 "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
    per_pid   = defaultdict(int)
    total_ext = 0

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        return findings, f"Could not enumerate connections: {e}"

    for c in conns:
        if not c.raddr or c.status != "ESTABLISHED":
            continue
        rip = c.raddr.ip
        if any(rip.startswith(p) for p in PRIVATE):
            continue
        total_ext += 1
        if c.pid:
            per_pid[c.pid] += 1
        if c.raddr.port in SUSPICIOUS_PORTS:
            try:
                pname = psutil.Process(c.pid).name() if c.pid else "?"
            except Exception:
                pname = "?"
            findings.append(f"Suspicious connection: {pname} (PID {c.pid}) -> {rip}:{c.raddr.port}")

    for pid, cnt in per_pid.items():
        if cnt > 20:
            try:
                pname = psutil.Process(pid).name()
            except Exception:
                pname = "?"
            findings.append(f"Process with many external connections: {pname} (PID {pid}) — {cnt} connections")

    summary = f"{total_ext} external connections" + (" – OK" if not findings else "")
    return findings, summary


# ── 5. Hosts File ────────────────────────────────────────────────────────────
def check_hosts_file():
    findings       = []
    SENTINEL_DOMAINS = (
        "google.com", "microsoft.com", "windows.com", "windowsupdate.com",
        "github.com", "anthropic.com", "openai.com", "update.microsoft.com",
        "apple.com", "paypal.com", "amazon.com",
    )
    hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
    if not hosts_path.exists():
        return findings, "hosts file not found"

    custom = 0
    for line in hosts_path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        ip, host = parts[0], parts[1].lower()
        custom += 1
        for domain in SENTINEL_DOMAINS:
            if domain in host:
                findings.append(f"Hosts file hijack: {host} -> {ip}")
                break

    summary = f"{custom} custom entries" + (" – OK" if not findings else "")
    return findings, summary


# ── 6. AI Tool Configs (Claude / MCP) ────────────────────────────────────────
def check_ai_tool_configs():
    findings = []
    username = os.environ.get("USERNAME", os.environ.get("USER", ""))
    home     = Path(f"C:/Users/{username}")

    candidate_dirs = [
        home / "AppData" / "Roaming" / "Claude",
        home / ".claude",
        home / "AppData" / "Local" / "Claude",
        home / "AppData" / "Roaming" / "Code" / "User",
        home / ".config" / "claude",
    ]

    scanned = 0
    for d in candidate_dirs:
        if not d.exists():
            continue
        for jf in d.rglob("*.json"):
            scanned += 1
            try:
                text = jf.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for pat in INJECTION_PATTERNS:
                if re.search(pat, text, re.IGNORECASE):
                    findings.append(f"Potential prompt-injection pattern in: {jf}  [{pat}]")
                    break

    for key in os.environ:
        if any(kw in key.upper() for kw in ("ANTHROPIC", "OPENAI", "API_KEY", "LLM_SECRET")):
            findings.append(f"AI API credential in environment variable: {key} (value hidden)")

    summary = f"{scanned} config files scanned" + (" – OK" if not findings else "")
    return findings, summary


# ── 7. Windows Defender ──────────────────────────────────────────────────────
def check_windows_defender():
    findings = []
    if not IS_WINDOWS:
        return findings, "Skipped (not Windows)"

    ps_cmd = (
        "Get-MpComputerStatus | "
        "Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled "
        "| ConvertTo-Json"
    )
    try:
        r = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0 and r.stdout.strip():
            s = json.loads(r.stdout)
            if not s.get("AMServiceEnabled"):
                findings.append("Windows Defender Antimalware Service is DISABLED!")
            if not s.get("RealTimeProtectionEnabled"):
                findings.append("Real-Time Protection is DISABLED!")
            if not s.get("AntivirusEnabled"):
                findings.append("Antivirus is DISABLED!")
    except Exception as e:
        return findings, f"Could not query Defender: {e}"

    summary = "Windows Defender active" if not findings else "Defender ISSUES detected"
    return findings, summary


# ── 8. Suspicious Scheduled Tasks ────────────────────────────────────────────
def check_scheduled_tasks():
    findings = []
    if not IS_WINDOWS:
        return findings, "Skipped (not Windows)"

    ps_cmd = (
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
        "Select-Object TaskName,TaskPath | ConvertTo-Json -Compress"
    )
    try:
        r = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=20
        )
        if r.returncode != 0 or not r.stdout.strip():
            return findings, "Could not retrieve scheduled tasks"

        tasks = json.loads(r.stdout)
        if isinstance(tasks, dict):
            tasks = [tasks]

        for t in tasks:
            tname = t.get("TaskName", "")
            for pat in SUSPICIOUS_PROCESS_PATTERNS:
                if re.search(pat, tname, re.I):
                    findings.append(f"Suspicious scheduled task: {t.get('TaskPath','')}{tname}")
                    break

        summary = f"{len(tasks)} active tasks checked" + (" – OK" if not findings else "")
    except Exception as e:
        summary = f"Error: {e}"

    return findings, summary


# ============================================================
# EMAIL REPORT
# ============================================================
def send_email_report(config: dict, all_findings: dict, summaries: dict) -> bool:
    ec = config.get("email", {})
    if ec.get("app_password") == "YOUR_GMAIL_APP_PASSWORD_HERE":
        log("[Email] Not configured — skipping. Edit config.json to enable.")
        return False

    total  = sum(len(v) for v in all_findings.values())
    ts     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    status = "CLEAN – no issues" if total == 0 else f"{total} ISSUE(S) FOUND"

    rows = []
    for check, findings in all_findings.items():
        icon = "OK" if not findings else "ALERT"
        rows.append(f"<tr><td><b>[{icon}] {check}</b></td><td>{summaries.get(check,'')}</td></tr>")
        for f in findings:
            rows.append(f"<tr><td colspan='2' style='color:#cc0000;padding-left:20px'>• {f}</td></tr>")

    color  = "green" if total == 0 else "red"
    html   = f"""
<html><body style="font-family:Arial,sans-serif">
<h2>Daily Security Report — {ts}</h2>
<h3 style="color:{color}">{status}</h3>
<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%">
  <tr style="background:#f0f0f0"><th>Check</th><th>Result</th></tr>
  {''.join(rows)}
</table>
<p style="color:#888;font-size:12px">Security Monitor — automated daily report.</p>
</body></html>"""

    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = f"[Security Monitor] {status} — {ts}"
        msg["From"]    = ec["from"]
        msg["To"]      = ec["to"]
        msg.attach(MIMEText(html, "html", "utf-8"))

        with smtplib.SMTP(ec["smtp_host"], int(ec["smtp_port"])) as srv:
            srv.starttls()
            srv.login(ec["from"], ec["app_password"])
            srv.send_message(msg)

        log("[Email] Report sent successfully.")
        return True
    except Exception as e:
        log(f"[Email] Failed to send: {e}")
        return False


# ============================================================
# MAIN
# ============================================================
import argparse

def main():
    parser = argparse.ArgumentParser(description="Security Monitor")
    parser.add_argument("--test", action="store_true", help="Run a test to verify Windows notifications and email delivery")
    args = parser.parse_args()

    log("=" * 60)
    log("Security Monitor — daily check starting")
    log("=" * 60)

    config = load_config()

    if args.test:
        log("  > RUNNING IN TEST MODE ...")
        all_findings = {
            "Simulated Test Alert": [
                "CRITICAL – This is a simulated high-risk finding for testing purposes.",
                "Process: fake_miner.exe (PID 9999) — C:\\temp\\fake_miner.exe"
            ]
        }
        summaries = {
            "Simulated Test Alert": "TEST ALERT"
        }
        log("    -> TEST ALERT")
        log("    CRITICAL – This is a simulated high-risk finding for testing purposes.")
        
        log("=" * 60)
        log("WARNING: 2 potential issue(s) detected — review the log.")
        send_windows_notification(
            "Security Alert — 2 issue(s) found",
            "Open security_log.txt for details. Review immediately!"
        )
        send_email_report(config, all_findings, summaries)
        log("=" * 60)
        log("Security Monitor Test — done.")
        log("")
        return 1

    checks = [
        ("Chrome Extensions",     check_chrome_extensions),
        ("Startup Items",         check_startup_items),
        ("Running Processes",     check_running_processes),
        ("Network Connections",   check_network_connections),
        ("Hosts File",            check_hosts_file),
        ("AI Tool Configs / MCP", check_ai_tool_configs),
        ("Windows Defender",      check_windows_defender),
        ("Scheduled Tasks",       check_scheduled_tasks),
    ]

    all_findings: dict = {}
    summaries:    dict = {}

    for check_name, check_fn in checks:
        log(f"  > {check_name} ...")
        try:
            findings, summary = check_fn()
        except Exception as ex:
            findings, summary = [f"Exception: {ex}"], "Check failed"

        all_findings[check_name] = findings
        summaries[check_name]    = summary
        log(f"    -> {summary}")
        for f in findings:
            log(f"    {f}")

    total = sum(len(v) for v in all_findings.values())

    log("=" * 60)
    if total == 0:
        log("ALL CHECKS PASSED — no issues found.")
        send_windows_notification(
            "Security Check Passed",
            f"Daily check complete — no issues found. ({datetime.datetime.now().strftime('%H:%M')})"
        )
    else:
        log(f"WARNING: {total} potential issue(s) detected — review the log.")
        send_windows_notification(
            f"Security Alert — {total} issue(s) found",
            "Open security_log.txt for details. Review immediately!"
        )

    send_email_report(config, all_findings, summaries)
    log("=" * 60)
    log("Security Monitor — done.")
    log("")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
