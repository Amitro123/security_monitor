#!/usr/bin/env python3
"""
Security Monitor v2.0 — Production EDR Engine
===============================================
Enterprise-grade daily security check with 15+ detection vectors,
baseline drift detection, MITRE ATT&CK coverage, and structured logging.

Author: Security Monitor Project | MIT License
"""

import os
import sys
import json
import datetime
import subprocess
import smtplib
import re
import hashlib
import argparse
from pathlib import Path
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Enable ANSI escape sequences on Windows
if os.name == 'nt':
    os.system("")

# ── Auto-install psutil if missing ──────────────────────────────────────────
try:
    import psutil
except ImportError:
    print("Installing required package: psutil...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "-q"])
    import psutil

# ── Auto-install keyring if missing (for secure credential storage) ──────────
try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    print("Installing required package: keyring...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "keyring", "-q"])
    try:
        import keyring
        KEYRING_AVAILABLE = True
    except Exception:
        KEYRING_AVAILABLE = False

# ── Windows registry (Windows only) ─────────────────────────────────────────
try:
    import winreg
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

# ============================================================
# CONFIGURATION
# ============================================================
VERSION     = "2.3.0"
BASE_DIR    = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"
LOG_FILE    = BASE_DIR / "security_log.txt"
JSON_LOG    = BASE_DIR / "security_log.json"
BASELINE    = BASE_DIR / "baseline.json"

DEFAULT_CONFIG = {
    "email": {
        "to":           "your-email@gmail.com",
        "from":         "your-email@gmail.com",
        "app_password": "YOUR_GMAIL_APP_PASSWORD_HERE",
        "smtp_host":    "smtp.gmail.com",
        "smtp_port":    587
    },
    "mode": "standard",   # paranoid | standard | light
    "script_hash": "",
    # trusted_items: list of substrings — any finding whose message contains
    # one of these strings is silently suppressed (treated as whitelisted).
    "trusted_items": [
        "SCM Event",                    # Windows Service Control Manager WMI filter
        "Copilot",                       # GitHub Copilot Chat config
        "copilot",
        "ANTHROPIC_API_KEY",            # Your own API keys in env
        "CONTEXT7_API_KEY",
        "GOOGLE_API_KEY"
    ]
}

# ── Severity Levels ──────────────────────────────────────────────────────────
P0        = "CRITICAL"
P1        = "HIGH"
P2        = "MEDIUM"
P3        = "LOW"
AUTOMATION = "AUTOMATION"
INFO      = "INFO"

# Automation tool name keywords — these extensions get the AUTOMATION category
AUTOMATION_KEYWORDS = ("claude", "automation", "ai assistant", "copilot", "openai", "chatgpt")
# Automation tool permission fingerprint (must have all three)
AUTOMATION_PERMS    = {"debugger", "nativeMessaging", "downloads"}

class Colors:
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    WHITE  = '\033[97m'
    RESET  = '\033[0m'

# ── Permission explanations (human-readable) ────────────────────────────────
PERM_EXPLANATIONS = {
    "nativeMessaging":       "can run programs on your PC outside the browser",
    "debugger":              "can inspect and modify any website you visit",
    "proxy":                 "can redirect all your web traffic through another server",
    "webRequest":            "can intercept and read every network request your browser makes",
    "webRequestBlocking":    "can block or modify network requests in real-time",
    "clipboardRead":         "can silently read everything you copy to clipboard",
    "clipboardWrite":        "can inject text into your clipboard",
    "cookies":               "can read your login cookies for all websites",
    "history":               "can read your full browsing history",
    "bookmarks":             "can read and modify your saved bookmarks",
    "management":            "can install/remove other Chrome extensions",
    "downloads":             "can read and manage your downloads",
}

# ── CTA templates per check ──────────────────────────────────────────────────
CTA_MAP = {
    "Chrome Extensions":     "👉 Fix: Open chrome://extensions → Find the extension → Toggle OFF or click Remove",
    "Startup Items":         "👉 Fix: Open Task Manager (Ctrl+Shift+Esc) → Startup tab → Right-click → Disable",
    "Startup Folders":       "👉 Fix: Open Run (Win+R) → shell:startup → Delete the suspicious file",
    "Running Processes":     "👉 Fix: Open Task Manager → find the process → End Task, then check its file location",
    "Network Connections":   "👉 Fix: Identify the process via Task Manager, terminate it, then run a full AV scan",
    "Hosts File":            "👉 Fix: Open Notepad as Admin → Open C:\\Windows\\System32\\drivers\\etc\\hosts → Remove suspicious lines",
    "Windows Defender":      "👉 Fix: Start → Windows Security → Virus & threat protection → Turn on Real-time protection",
    "Scheduled Tasks":       "👉 Fix: Open Task Scheduler (taskschd.msc) → find the task → right-click → Delete",
    "Windows Services":      "👉 Fix: Open services.msc → find the service → right-click → Stop, then set to Disabled",
    "WMI Persistence":       "👉 Fix: Open PowerShell as Admin → Get-WMIObject -Namespace root\\subscription -Class __EventFilter | Remove-WmiObject",
    "PowerShell Profiles":   "👉 Fix: Open the profile file shown above in Notepad → remove the suspicious line",
    "BITS Jobs":             "👉 Fix: Open PowerShell → Get-BitsTransfer -AllUsers | Remove-BitsTransfer",
    "AI Tool Configs / MCP": "👉 Fix: Review the file listed above and remove any suspicious prompt overrides",
    "Self-Integrity":        "👉 Fix: Re-run setup.ps1 as Administrator to restore the scheduled task and rehash the script",
    "Event Log Audit":       "👉 Fix: Review the Windows Security Event Log via eventvwr.msc for full context",
}

# ── Threat signatures ────────────────────────────────────────────────────────
SUSPICIOUS_PROCESS_PATTERNS = [
    r'miner', r'xmrig', r'nicehash', r'ngrok', r'frp',
    r'netcat', r'\bnc\b', r'psexec', r'mimikatz',
    r'meterpreter', r'payload', r'inject', r'hook',
    r'keylog', r'spyware', r'rat\.exe', r'trojan',
    r'cobalt', r'empire', r'beacon', r'havoc',
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
    8443, 8080, 2222,   # Common C2 proxies
}

# Known TOR exit node IPs prefix sets (lightweight version)
TOR_PREFIXES = ("176.10.", "195.176.3.", "185.220.", "45.142.")

# ── WMI known-safe subscription objects (system defaults, not threats) ─────────
WMI_KNOWN_SAFE = {
    "BVTFilter",
    "SCM Event Log Consumer",
    "NTEventLogEventConsumer",
    "MSFT_SCMEventLogConsumer",
    "TSlogonEvents.filter",
    "TSlogonEvents.consumer",
    "RmShellEventConsumer",
}

# ── VS Code subdirectories that should never be scanned for injection patterns ──────
VSCODE_SKIP_DIRS = {
    "workspaceStorage", "chatEditingSessions", "History",
    "backupWorkspaces", "logs",
}

# ── Browser processes legitimately open many connections — whitelist them ─────────
HIGH_CONN_WHITELIST = {"chrome.exe", "firefox.exe", "msedge.exe", "brave.exe"}

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


SUSPICIOUS_SERVICE_PATHS = (
    r'\temp\\', r'\downloads\\',
    r'\appdata\local\temp\\', r'\users\public\\',
)

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
        # Auto-migrate plaintext app_password to keyring on first run
        ec = cfg.get("email", {})
        pw = ec.get("app_password", "")
        if KEYRING_AVAILABLE and pw not in ("", "YOUR_GMAIL_APP_PASSWORD_HERE", "__KEYRING__", None):
            try:
                keyring.set_password("SecurityMonitor", ec.get("from", ""), pw)
                cfg["email"]["app_password"] = "__KEYRING__"
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2)
            except Exception:
                pass  # Migration failed silently — plaintext still works
        return cfg
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    return DEFAULT_CONFIG.copy()


def save_credential(service: str, username: str, password: str) -> bool:
    """Save a credential to Windows Credential Manager via keyring."""
    if not KEYRING_AVAILABLE:
        return False
    try:
        keyring.set_password(service, username, password)
        return True
    except Exception:
        return False


def get_credential(service: str, username: str, fallback: str = "") -> str:
    """Retrieve a credential from keyring; fall back to the provided value."""
    if KEYRING_AVAILABLE:
        try:
            val = keyring.get_password(service, username)
            if val:
                return val
        except Exception:
            pass
    return fallback


def load_baseline() -> dict:
    if BASELINE.exists():
        with open(BASELINE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_baseline(data: dict):
    with open(BASELINE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def compute_script_hash() -> str:
    """SHA256 hash of this script for self-integrity validation."""
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def severity_color(sev: str) -> str:
    return {
        P0: Colors.RED,
        P1: Colors.RED,
        P2: Colors.YELLOW,
        P3: Colors.CYAN,
        INFO: Colors.RESET,
    }.get(sev, Colors.RESET)


def log(msg: str, sev: str = INFO):
    ts    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color = severity_color(sev)
    print(f"[{ts}] {color}{msg}{Colors.RESET}")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")


def json_log(check: str, sev: str, finding: str, details: dict = None):
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "version":   VERSION,
        "check":     check,
        "severity":  sev,
        "finding":   finding,
        "details":   details or {},
    }
    with open(JSON_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def run_ps(command: str, timeout: int = 20) -> str:
    """Run a PowerShell command and return stdout."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def send_windows_notification(title: str, body: str):
    """Send a Windows 10/11 Toast Notification via PowerShell."""
    if not IS_WINDOWS:
        return
    title    = title.replace('"', '""').replace("'", "''")
    body     = body.replace('"', '""').replace("'", "''")
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
        log(f"[Notification] Could not send: {e}", P2)


# ============================================================
# SECURITY CHECKS
# ============================================================

# ── 1. Chrome Extensions ─────────────────────────────────────────────────────
def _resolve_msg_name(name: str, vdir: Path) -> str:
    """Resolve a Chrome i18n message key (__MSG_key__) to a real name.

    Looks for the localized string in _locales/en/messages.json or
    _locales/en_US/messages.json relative to the extension version directory.
    Returns the resolved name, or the original string if resolution fails.
    """
    if not name.startswith("__MSG_") or not name.endswith("__"):
        return name
    key = name[6:-2]  # strip '__MSG_' prefix and '__' suffix
    for locale in ("en", "en_US", "en_GB"):
        messages_path = vdir / "_locales" / locale / "messages.json"
        if messages_path.exists():
            try:
                msgs = json.loads(messages_path.read_text(encoding="utf-8", errors="ignore"))
                # Messages.json: {"key": {"message": "Real Name"}}
                # Keys are case-insensitive in Chrome
                for k, v in msgs.items():
                    if k.lower() == key.lower():
                        resolved = v.get("message", "").strip()
                        if resolved:
                            return resolved
            except Exception:
                pass
    return name  # resolution failed — caller keeps 'Unknown' source behavior


def _ext_source(manifest: dict, name: str = "") -> str:
    """Detect whether the extension was installed from the Chrome Web Store.
    If the name contains __MSG_ it's an unresolved message key -> Unknown.
    """
    if "__MSG_" in name:
        return "Unknown (unresolved name)"
    update_url = manifest.get("update_url", "")
    if "clients2.google.com" in update_url or "chrome.google.com" in update_url:
        return "Chrome Web Store"
    if update_url:
        return f"Unknown ({update_url[:50]})"
    return "Unknown (no update URL)"


def check_chrome_extensions(baseline: dict, config: dict, _ext_root=None):
    """Scan Chrome extensions for high-risk permissions, automation tools, and baseline drift.

    Args:
        baseline: Baseline dict (may contain 'chrome_extensions' list of known IDs).
        config:   Config dict (for 'mode' selection).
        _ext_root: Optional Path override for the Chrome User Data directory.
                   Used in tests to inject a temporary directory.
    """
    findings   = []
    mode       = config.get("mode", "standard")
    username   = os.environ.get("USERNAME", os.environ.get("USER", ""))
    ext_root   = _ext_root if _ext_root is not None else Path(f"C:/Users/{username}/AppData/Local/Google/Chrome/User Data")


    if not ext_root.exists():
        return findings, "Chrome not found on this machine"

    profiles   = [ext_root / "Default"] + list(ext_root.glob("Profile *"))
    total_exts = 0
    suspicious = 0
    seen_ids   = set()   # ← dedup: skip if we already processed this extension ID

    for profile in profiles:
        ext_dir = profile / "Extensions"
        if not ext_dir.exists():
            continue
        for ext_folder in ext_dir.iterdir():
            if not ext_folder.is_dir():
                continue
            ext_id = ext_folder.name

            # Rule 1 — Deduplicate across profiles
            if ext_id in seen_ids:
                continue

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
                seen_ids.add(ext_id)
                raw_name  = manifest.get("name", ext_id)
                # Fix 1: attempt to resolve Chrome i18n message keys
                name       = _resolve_msg_name(raw_name, vdir)
                perms      = set(manifest.get("permissions", []))
                host_perms = manifest.get("host_permissions", []) + manifest.get("permissions", [])
                source     = _ext_source(manifest, name)

                # Known malicious — always P0 regardless of other rules
                if ext_id in KNOWN_MALICIOUS_EXTENSIONS:
                    suspicious += 1
                    msg = f"Known malicious extension: {name} ({ext_id}) [Source: {source}]"
                    findings.append((P0, msg))
                    json_log("Chrome Extensions", P0, msg, {"ext_id": ext_id})
                    break

                danger_found = perms & DANGEROUS_CHROME_PERMISSIONS
                all_urls     = any(h in ("<all_urls>", "*://*/*", "http://*/*") for h in host_perms)
                threshold    = 2 if mode == "paranoid" else 3

                if len(danger_found) >= threshold and all_urls:
                    # Rule 2 — Automation tools: do NOT flag as HIGH
                    name_lower = name.lower()
                    is_automation = (
                        any(kw in name_lower for kw in AUTOMATION_KEYWORDS)
                        and AUTOMATION_PERMS.issubset(perms)
                    )
                    if is_automation:
                        msg = (f"Automation tool: '{name}' [{', '.join(sorted(danger_found))}]"
                               f" [Source: {source}]")
                        findings.append((AUTOMATION, msg))
                        json_log("Chrome Extensions", AUTOMATION, msg, {"ext_id": ext_id})

                    else:
                        suspicious += 1
                        # Rule 3 — PDF/web-capture: keep HIGH, custom CTA handled
                        # by _finding_cta() in render_dashboard. Do NOT embed the
                        # CTA text in the message to avoid showing it twice.
                        msg = (f"High-risk extension: '{name}' [{', '.join(sorted(danger_found))}]"
                               f" + all-URL access [Source: {source}]")
                        findings.append((P1, msg))
                        json_log("Chrome Extensions", P1, msg, {"ext_id": ext_id})

                # Baseline drift — new extension since last scan
                bl_exts = set(baseline.get("chrome_extensions", []))
                if bl_exts and ext_id not in bl_exts:
                    msg = f"New extension since baseline: '{name}' ({ext_id}) [Source: {source}]"
                    findings.append((P2, msg))
                    json_log("Chrome Extensions", P2, msg, {"ext_id": ext_id})
                break

    summary = f"{total_exts} extensions checked" + (f", {suspicious} suspicious" if suspicious else " – OK")
    return findings, summary


# ── 2. Windows Startup Registry ──────────────────────────────────────────────
def check_startup_items(baseline: dict):
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
    found_entries = {}

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
                    found_entries[name] = value
                    for pat in SUSPICIOUS_PROCESS_PATTERNS:
                        if re.search(pat, name, re.I) or re.search(pat, value, re.I):
                            msg = f"Suspicious startup entry: '{name}' -> {value}"
                            findings.append((P0, msg))
                            json_log("Startup Items", P0, msg)
                            break
                    else:
                        for d in SUSPECT_DIRS:
                            if d in val_lower:
                                msg = f"Startup from risky location: '{name}' -> {value}"
                                findings.append((P1, msg))
                                json_log("Startup Items", P1, msg)
                                break
                    i += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)

    # Baseline drift
    bl_startup = baseline.get("startup_items", {})
    for name, val in found_entries.items():
        if bl_startup and name not in bl_startup:
            msg = f"New startup entry since baseline: '{name}' -> {val}"
            findings.append((P1, msg))
            json_log("Startup Items", P1, msg)

    summary = f"{total} startup entries" + (" – OK" if not findings else "")
    return findings, summary


# ── 3. Running Processes ─────────────────────────────────────────────────────
def check_running_processes():
    findings  = []
    RISKY_DIRS = (r'\temp\\', r'\downloads\\', r'\appdata\local\temp\\', r'\users\public\\')
    count     = 0

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info  = proc.info
            pname = (info.get("name") or "").lower()
            pexe  = (info.get("exe")  or "").lower()
            count += 1
            for pat in SUSPICIOUS_PROCESS_PATTERNS:
                if re.search(pat, pname, re.I) or re.search(pat, pexe, re.I):
                    msg = f"Suspicious process: {info['name']} (PID {info['pid']}) — {info['exe']}"
                    findings.append((P0, msg))
                    json_log("Running Processes", P0, msg, {"pid": info['pid']})
                    break
            else:
                for d in RISKY_DIRS:
                    if d in pexe:
                        msg = f"Process from risky path: {info['name']} (PID {info['pid']}) — {info['exe']}"
                        findings.append((P1, msg))
                        json_log("Running Processes", P1, msg, {"pid": info['pid']})
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

    # Fix 3: wrap in ThreadPoolExecutor with 10s timeout to avoid blocking
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(psutil.net_connections, "inet")
            try:
                conns = future.result(timeout=10)
            except FuturesTimeout:
                return findings, "Network scan timed out (>10s) — skipped"
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
            msg = f"Suspicious connection: {pname} (PID {c.pid}) -> {rip}:{c.raddr.port}"
            findings.append((P0, msg))
            json_log("Network Connections", P0, msg, {"port": c.raddr.port, "ip": rip})

        if any(rip.startswith(p) for p in TOR_PREFIXES):
            try:
                pname = psutil.Process(c.pid).name() if c.pid else "?"
            except Exception:
                pname = "?"
            msg = f"Possible TOR connection: {pname} (PID {c.pid}) -> {rip}"
            findings.append((P0, msg))
            json_log("Network Connections", P0, msg, {"ip": rip})

    for pid, cnt in per_pid.items():
        if cnt > 20:
            try:
                pname = psutil.Process(pid).name()
            except Exception:
                pname = "?"
            # Fix 3: browsers legitimately open many connections — skip them
            if pname.lower() in HIGH_CONN_WHITELIST:
                continue
            msg = f"Process with many external connections: {pname} (PID {pid}) — {cnt} connections"
            findings.append((P2, msg))
            json_log("Network Connections", P2, msg, {"pid": pid, "count": cnt})

    summary = f"{total_ext} external connections" + (" – OK" if not findings else "")
    return findings, summary


# ── 5. Hosts File ────────────────────────────────────────────────────────────
def check_hosts_file():
    findings = []
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
                msg = f"Hosts file hijack: {host} -> {ip}"
                findings.append((P0, msg))
                json_log("Hosts File", P0, msg, {"domain": host, "ip": ip})
                break

    summary = f"{custom} custom entries" + (" – OK" if not findings else "")
    return findings, summary


# ── 6. AI Tool Configs (Claude / MCP / OpenClaw) ─────────────────────────────
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
        # OpenClaw specific paths
        home / "AppData" / "Roaming" / "OpenClaw",
        home / "AppData" / "Local" / "OpenClaw",
        home / ".openclaw",
        home / "AppData" / "Roaming" / "openclaw",
    ]

    scanned = 0
    for d in candidate_dirs:
        if not d.exists():
            continue
        for jf in d.rglob("*.json"):
            # Fix 2: skip VS Code internal state directories
            if any(part in VSCODE_SKIP_DIRS for part in jf.parts):
                continue
            scanned += 1
            try:
                text = jf.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for pat in INJECTION_PATTERNS:
                if re.search(pat, text, re.IGNORECASE):
                    msg = f"Potential prompt-injection pattern in: {jf}  [{pat}]"
                    findings.append((P1, msg))
                    json_log("AI Tool Configs", P1, msg, {"file": str(jf), "pattern": pat})
                    break

    for key in os.environ:
        if any(kw in key.upper() for kw in ("ANTHROPIC", "OPENAI", "API_KEY", "LLM_SECRET", "OPENCLAW")):
            msg = f"AI API credential in environment variable: {key} (value hidden)"
            findings.append((P2, msg))
            json_log("AI Tool Configs", P2, msg, {"env_var": key})

    summary = f"{scanned} config files scanned" + (" – OK" if not findings else "")
    return findings, summary


# ── 7. Windows Defender ──────────────────────────────────────────────────────
def check_windows_defender():
    findings = []
    if not IS_WINDOWS:
        return findings, "Skipped (not Windows)"

    ps_cmd = (
        "Get-MpComputerStatus | "
        "Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureLastUpdated "
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
                msg = "Windows Defender Antimalware Service is DISABLED!"
                findings.append((P0, msg))
                json_log("Windows Defender", P0, msg)
            if not s.get("RealTimeProtectionEnabled"):
                msg = "Real-Time Protection is DISABLED!"
                findings.append((P0, msg))
                json_log("Windows Defender", P0, msg)
            if not s.get("AntivirusEnabled"):
                msg = "Antivirus is DISABLED!"
                findings.append((P0, msg))
                json_log("Windows Defender", P0, msg)
            # Check signature staleness
            last_sig = s.get("AntivirusSignatureLastUpdated", "")
            if last_sig:
                try:
                    # Typically format: /Date(ms)/
                    ms = int(re.search(r'\d+', str(last_sig)).group())
                    sig_dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=ms)
                    age_days = (datetime.datetime.now() - sig_dt).days
                    if age_days > 3:
                        msg = f"Defender signatures are {age_days} days old — update recommended"
                        findings.append((P2, msg))
                        json_log("Windows Defender", P2, msg)
                except Exception:
                    pass

        # Fix 4: Check for Defender exclusions — skip gracefully on permission errors
        excl = run_ps("(Get-MpPreference).ExclusionPath | ConvertTo-Json -Compress")
        if excl and excl not in ("null", "[]", ""):
            # Guard: if PS returned a permission/access error, skip rather than flag
            if (excl.startswith("N/A") or "Must be" in excl or "Access" in excl
                    or "Administrator" in excl or "not recognized" in excl.lower()):
                pass  # insufficient privileges — skip exclusions check silently
            else:
                msg = f"Defender has path exclusions configured: {excl[:200]}"
                findings.append((P2, msg))
                json_log("Windows Defender", P2, msg)

    except Exception as e:
        return findings, f"Could not query Defender: {e}"

    summary = "Windows Defender active" if not findings else "Defender ISSUES detected"
    return findings, summary


# ── 8. Suspicious Scheduled Tasks ────────────────────────────────────────────
def check_scheduled_tasks(baseline: dict):
    findings = []
    if not IS_WINDOWS:
        return findings, "Skipped (not Windows)"

    ps_cmd = (
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
        "Select-Object TaskName,TaskPath,@{Name='Execute';Expression={$_.Actions.Execute}} | ConvertTo-Json -Compress"
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

        bl_tasks = set(baseline.get("scheduled_tasks", []))
        found_names = set()

        for t in tasks:
            tname   = t.get("TaskName", "")
            texe    = (t.get("Execute") or "").lower()
            found_names.add(tname)

            for pat in SUSPICIOUS_PROCESS_PATTERNS:
                if re.search(pat, tname, re.I) or re.search(pat, texe, re.I):
                    msg = f"Suspicious scheduled task: {t.get('TaskPath','')}{tname}"
                    findings.append((P0, msg))
                    json_log("Scheduled Tasks", P0, msg)
                    break

            # Baseline drift — new task
            if bl_tasks and tname not in bl_tasks:
                if not tname.startswith("Microsoft") and not tname.startswith("\\Microsoft"):
                    msg = f"New scheduled task since baseline: {tname}"
                    findings.append((P2, msg))
                    json_log("Scheduled Tasks", P2, msg)

        summary = f"{len(tasks)} active tasks checked" + (" – OK" if not findings else "")
    except Exception as e:
        summary = f"Error: {e}"

    return findings, summary


# ── 9. Windows Services ───────────────────────────────────────────────────────
def check_windows_services(baseline: dict):
    findings = []
    if not IS_WINDOWS:
        return findings, "Skipped (not Windows)"

    ps_cmd = (
        "Get-WmiObject Win32_Service | Where-Object { $_.StartMode -in 'Auto','Delayed Auto' } | "
        "Select-Object Name,PathName,State | ConvertTo-Json -Compress"
    )
    try:
        out = run_ps(ps_cmd, timeout=25)
        if not out:
            return findings, "Could not retrieve services"

        services = json.loads(out)
        if isinstance(services, dict):
            services = [services]

        bl_svcs = set(baseline.get("services", []))
        total = len(services)

        for svc in services:
            name = svc.get("Name", "")
            path = (svc.get("PathName") or "").lower()

            for d in SUSPICIOUS_SERVICE_PATHS:
                if d in path:
                    msg = f"Service running from risky path: {name} -> {path}"
                    findings.append((P0, msg))
                    json_log("Windows Services", P0, msg, {"name": name, "path": path})
                    break

            for pat in SUSPICIOUS_PROCESS_PATTERNS:
                if re.search(pat, name, re.I) or re.search(pat, path, re.I):
                    msg = f"Suspicious service: {name} -> {path}"
                    findings.append((P0, msg))
                    json_log("Windows Services", P0, msg, {"name": name})
                    break

            # Baseline drift
            if bl_svcs and name not in bl_svcs:
                msg = f"New auto-start service since baseline: {name}"
                findings.append((P2, msg))
                json_log("Windows Services", P2, msg, {"name": name})

        summary = f"{total} auto-start services checked" + (" – OK" if not findings else "")
    except Exception as e:
        summary = f"Error: {e}"

    return findings, summary


# ── 10. Startup Folders ───────────────────────────────────────────────────────
def check_startup_folders(baseline: dict):
    findings  = []
    username  = os.environ.get("USERNAME", os.environ.get("USER", ""))

    startup_dirs = [
        Path(f"C:/Users/{username}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"),
        Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"),
    ]

    bl_files = set(baseline.get("startup_folder_files", []))
    total = 0

    for d in startup_dirs:
        if not d.exists():
            continue
        for f in d.iterdir():
            if f.suffix.lower() not in (".lnk", ".exe", ".bat", ".cmd", ".ps1", ".vbs"):
                continue
            total += 1
            fname  = f.name

            for pat in SUSPICIOUS_PROCESS_PATTERNS:
                if re.search(pat, fname, re.I):
                    msg = f"Suspicious startup item: {f}"
                    findings.append((P0, msg))
                    json_log("Startup Folders", P0, msg, {"file": str(f)})
                    break

            if bl_files and fname not in bl_files:
                msg = f"New startup folder item since baseline: {f}"
                findings.append((P1, msg))
                json_log("Startup Folders", P1, msg, {"file": str(f)})

    summary = f"{total} startup folder items scanned" + (" – OK" if not findings else "")
    return findings, summary


# ── 11. WMI Persistence ───────────────────────────────────────────────────────
def check_wmi_persistence():
    findings = []
    if not IS_WINDOWS:
        return findings, "Skipped (not Windows)"

    ps_cmd = """
$filters = Get-WMIObject -Namespace root\\subscription -Class __EventFilter -EA SilentlyContinue | Select-Object Name,Query | ConvertTo-Json -Compress
$consumers = Get-WMIObject -Namespace root\\subscription -Class CommandLineEventConsumer -EA SilentlyContinue | Select-Object Name,CommandLineTemplate | ConvertTo-Json -Compress
Write-Output "FILTERS:$filters"
Write-Output "CONSUMERS:$consumers"
"""
    try:
        out = run_ps(ps_cmd, timeout=25)
        filters_json   = ""
        consumers_json = ""
        for line in out.splitlines():
            if line.startswith("FILTERS:"):
                filters_json = line[8:]
            elif line.startswith("CONSUMERS:"):
                consumers_json = line[10:]

        count = 0
        for raw, label in [(filters_json, "WMI EventFilter"), (consumers_json, "WMI Consumer")]:
            if not raw or raw in ("null", "[]", ""):
                continue
            items = json.loads(raw)
            if isinstance(items, dict):
                items = [items]
            for item in items:
                count += 1
                name = item.get("Name", "")
                # Fix 2: Skip known-safe system WMI subscriptions
                if name in WMI_KNOWN_SAFE:
                    continue
                body = item.get("Query") or item.get("CommandLineTemplate", "")
                for pat in SUSPICIOUS_PROCESS_PATTERNS + INJECTION_PATTERNS:
                    if re.search(pat, body or "", re.I):
                        msg = f"Suspicious {label}: '{name}' — {str(body)[:150]}"
                        findings.append((P0, msg))
                        json_log("WMI Persistence", P0, msg)
                        break
                else:
                    if body:  # any non-safe WMI consumer is worth flagging as Medium
                        msg = f"{label} found (review manually): '{name}'"
                        findings.append((P2, msg))
                        json_log("WMI Persistence", P2, msg)

        summary = f"{count} WMI subscription objects found" + (" – OK" if not findings else "")
    except Exception as e:
        summary = f"Error: {e}"

    return findings, summary


# ── 12. PowerShell Profiles ───────────────────────────────────────────────────
def check_powershell_profiles():
    findings = []
    username = os.environ.get("USERNAME", os.environ.get("USER", ""))

    profile_paths = [
        Path(f"C:/Users/{username}/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1"),
        Path(f"C:/Users/{username}/Documents/PowerShell/Microsoft.PowerShell_profile.ps1"),
        Path("C:/Windows/System32/WindowsPowerShell/v1.0/profile.ps1"),
    ]

    suspicious_patterns = [
        r'Invoke-Expression', r'IEX\s*\(', r'DownloadString',
        r'Net\.WebClient', r'bitsadmin', r'-EncodedCommand',
        r'bypass', r'Hidden', r'FromBase64',
    ]

    found = 0
    for p in profile_paths:
        if not p.exists():
            continue
        found += 1
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pat in suspicious_patterns:
            if re.search(pat, content, re.I):
                msg = f"Suspicious PowerShell profile: {p} — contains [{pat}]"
                findings.append((P1, msg))
                json_log("PowerShell Profiles", P1, msg, {"file": str(p), "pattern": pat})
                break

    summary = f"{found} PS profiles found" + (" – OK" if not findings else "")
    return findings, summary


# ── 13. BITS Jobs ─────────────────────────────────────────────────────────────
def check_bits_jobs():
    findings = []
    if not IS_WINDOWS:
        return findings, "Skipped (not Windows)"

    ps_cmd = "Get-BitsTransfer -AllUsers -EA SilentlyContinue | Select-Object DisplayName,TransferType,FileList | ConvertTo-Json -Compress"
    try:
        out = run_ps(ps_cmd, timeout=15)
        if not out or out in ("null", "[]", ""):
            return findings, "No BITS jobs found – OK"

        jobs = json.loads(out)
        if isinstance(jobs, dict):
            jobs = [jobs]

        for j in jobs:
            name     = j.get("DisplayName", "")
            filelist = j.get("FileList", []) or []
            for entry in (filelist if isinstance(filelist, list) else [filelist]):
                remote = (entry.get("RemoteName") or "") if isinstance(entry, dict) else str(entry)
                if re.search(r'\.exe$|\.dll$|\.ps1$|\.bat$', remote, re.I):
                    msg = f"BITS job downloading executable: '{name}' -> {remote}"
                    findings.append((P1, msg))
                    json_log("BITS Jobs", P1, msg, {"job": name, "url": remote})

        summary = f"{len(jobs)} BITS transfer job(s) found" + (" – OK" if not findings else "")
    except Exception as e:
        summary = f"Error: {e}"

    return findings, summary


# ── 14. Self-Integrity ────────────────────────────────────────────────────────
def check_self_integrity(config: dict):
    findings = []
    stored_hash = config.get("script_hash", "")
    if not stored_hash:
        return findings, "No baseline hash stored — run setup to enable"

    current_hash = compute_script_hash()
    if current_hash != stored_hash:
        msg = f"Script tamper detected! Stored hash: {stored_hash[:16]}... Current: {current_hash[:16]}..."
        findings.append((P0, msg))
        json_log("Self-Integrity", P0, msg)
    else:
        pass  # OK

    # Check that our own scheduled task still exists
    if IS_WINDOWS:
        out = run_ps("(Get-ScheduledTask -TaskName 'DailySecurityMonitor' -EA SilentlyContinue).TaskName")
        if not out.strip():
            msg = "Scheduled task 'DailySecurityMonitor' is MISSING — possible tampering"
            findings.append((P1, msg))
            json_log("Self-Integrity", P1, msg)

    summary = "Script integrity verified – OK" if not findings else "INTEGRITY VIOLATION DETECTED"
    return findings, summary


# ── 15. Windows Event Log Audit ────────────────────────────────────────────────
def check_event_log():
    findings = []
    if not IS_WINDOWS:
        return findings, "Skipped (not Windows)"

    # Look for security events in last 24h: failed logons (4625), privilege use (4672), user creation (4720)
    events_of_interest = {
        4625: (P1, "Failed logon attempt"),
        4720: (P0, "New user account created"),
        4672: (P2, "Special privileges assigned to new logon"),
        4698: (P1, "Scheduled task created"),
        4699: (P1, "Scheduled task deleted"),
        7045: (P1, "New service installed"),
    }

    ps_cmd = """
$start = (Get-Date).AddHours(-24)
$events = @()
foreach ($id in @(4625,4720,4672,4698,4699,7045)) {
    $e = Get-WinEvent -FilterHashtable @{LogName='Security';Id=$id;StartTime=$start} -EA SilentlyContinue -MaxEvents 5
    if ($e) { $events += $e | Select-Object Id,TimeCreated,Message }
}
$events | ConvertTo-Json -Compress
"""
    try:
        out = run_ps(ps_cmd, timeout=30)
        if not out or out in ("null", "[]", ""):
            return findings, "No critical security events in last 24h – OK"

        evts = json.loads(out)
        if isinstance(evts, dict):
            evts = [evts]

        for evt in evts:
            eid    = evt.get("Id", 0)
            ts     = evt.get("TimeCreated", "")
            sev, label = events_of_interest.get(eid, (P3, f"Event {eid}"))
            msg = f"{label} at {ts} (EventID {eid})"
            findings.append((sev, msg))
            json_log("Event Log Audit", sev, msg, {"event_id": eid})

        summary = f"{len(evts)} security event(s) in last 24h" + (" – OK" if not findings else "")
    except Exception as e:
        summary = f"Error reading event log: {e}"

    return findings, summary


# ============================================================
# EMAIL REPORT
# ============================================================
def send_email_report(config: dict, all_findings: dict, summaries: dict) -> bool:
    ec = config.get("email", {})
    if ec.get("app_password") in ("YOUR_GMAIL_APP_PASSWORD_HERE", "", None):
        log("[Email] Not configured — skipping. Edit config.json to enable.", INFO)
        return False

    total  = sum(len(v) for v in all_findings.values())
    ts     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    status = "CLEAN – no issues" if total == 0 else f"{total} ISSUE(S) FOUND"

    sev_colors = {P0: "#cc0000", P1: "#dd4400", P2: "#cc8800", P3: "#888800", INFO: "#666"}

    rows = []
    for check, findings in all_findings.items():
        icon = "✅ OK" if not findings else f"🚨 {len(findings)} ALERT(S)"
        rows.append(f"<tr><td><b>{check}</b></td><td>{icon}</td><td>{summaries.get(check,'')}</td></tr>")
        for sev, f in findings:
            c = sev_colors.get(sev, "#333")
            rows.append(f"<tr><td colspan='3' style='color:{c};padding-left:20px'>• [{sev}] {f}</td></tr>")

    color = "green" if total == 0 else "red"
    html  = f"""
<html><body style="font-family:Arial,sans-serif">
<h2>Security Monitor v{VERSION} — Daily Report — {ts}</h2>
<h3 style="color:{color}">{status}</h3>
<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%">
  <tr style="background:#f0f0f0"><th>Check</th><th>Status</th><th>Summary</th></tr>
  {''.join(rows)}
</table>
<p style="color:#888;font-size:12px">Security Monitor v{VERSION} — automated daily report. Click on the Windows notification to view the full log.</p>
</body></html>"""

    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = f"[Security Monitor v{VERSION}] {status} — {ts}"
        msg["From"]    = ec["from"]
        msg["To"]      = ec["to"]
        msg.attach(MIMEText(html, "html", "utf-8"))

        with smtplib.SMTP(ec["smtp_host"], int(ec["smtp_port"])) as srv:
            srv.starttls()
            # Fix 1: use keyring if available, fall back to config value
            password = get_credential("SecurityMonitor", ec["from"],
                                      fallback=ec.get("app_password", ""))
            srv.login(ec["from"], password)
            srv.send_message(msg)

        log("[Email] Report sent successfully.", INFO)
        return True
    except Exception as e:
        log(f"[Email] Failed to send: {e}", P2)
        return False


# ============================================================
# BASELINE GENERATION
# ============================================================
def generate_baseline() -> dict:
    """Capture current system state as baseline."""
    log("  > Generating system baseline snapshot...", INFO)
    bl: dict = {"generated_at": datetime.datetime.now().isoformat(), "version": VERSION}

    # Chrome extensions
    username = os.environ.get("USERNAME", os.environ.get("USER", ""))
    ext_root = Path(f"C:/Users/{username}/AppData/Local/Google/Chrome/User Data")
    ext_ids = set()
    if ext_root.exists():
        for profile in [ext_root / "Default"] + list(ext_root.glob("Profile *")):
            ext_dir = profile / "Extensions"
            if ext_dir.exists():
                for ef in ext_dir.iterdir():
                    if ef.is_dir():
                        ext_ids.add(ef.name)
    bl["chrome_extensions"] = sorted(ext_ids)

    # Startup items
    startup = {}
    if IS_WINDOWS:
        for hive, path in [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]:
            try:
                key = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        startup[name] = val
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                pass
    bl["startup_items"] = startup

    # Startup folder files
    sfolder_files = []
    for d in [
        Path(f"C:/Users/{username}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"),
        Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"),
    ]:
        if d.exists():
            for f in d.iterdir():
                sfolder_files.append(f.name)
    bl["startup_folder_files"] = sfolder_files

    # Scheduled tasks
    task_names = []
    if IS_WINDOWS:
        out = run_ps("Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object -ExpandProperty TaskName | ConvertTo-Json -Compress")
        if out and out not in ("null", "[]"):
            try:
                names = json.loads(out)
                task_names = names if isinstance(names, list) else [names]
            except Exception:
                pass
    bl["scheduled_tasks"] = task_names

    # Services
    svc_names = []
    if IS_WINDOWS:
        out = run_ps("Get-WmiObject Win32_Service | Where-Object { $_.StartMode -in 'Auto','Delayed Auto' } | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress")
        if out and out not in ("null", "[]"):
            try:
                names = json.loads(out)
                svc_names = names if isinstance(names, list) else [names]
            except Exception:
                pass
    bl["services"] = svc_names

    save_baseline(bl)
    log(f"    -> Baseline snapshot saved to {BASELINE}", INFO)
    return bl


# ============================================================
# DASHBOARD RENDERER
# ============================================================

def _score_findings(all_findings: dict) -> int:
    """Calculate a 0-100 security score. 100 = clean, 0 = critical.
    
    Scoring is capped per-check (max -20 per check) so a single noisy
    check with many findings can't tank the whole score on its own.
    """
    deductions = {P0: 20, P1: 12, P2: 4, P3: 1}
    total_deducted = 0
    for findings in all_findings.values():
        # Cap deduction per check at the worst single finding's value
        if not findings:
            continue
        worst = max(deductions.get(sev, 0) for sev, _ in findings)
        total_deducted += worst
    return max(0, 100 - total_deducted)


def filter_findings(all_findings: dict, config: dict) -> dict:
    """Remove any findings whose message matches a trusted_items pattern.
    Returns a new dict with whitelisted entries removed.
    """
    trusted = [t.lower() for t in config.get("trusted_items", [])]
    if not trusted:
        return all_findings
    filtered = {}
    for check, findings in all_findings.items():
        kept = [(sev, msg) for sev, msg in findings
                if not any(t in msg.lower() for t in trusted)]
        filtered[check] = kept
    return filtered


def _score_bar(score: int) -> str:
    """Render a colored ASCII risk bar."""
    filled = score // 5        # 0-20 blocks
    empty  = 20 - filled
    if score >= 80:
        color = Colors.GREEN
    elif score >= 50:
        color = Colors.YELLOW
    else:
        color = Colors.RED
    bar = "█" * filled + "░" * empty
    return f"{color}{bar}{Colors.RESET}"


def _sev_emoji(sev: str) -> str:
    return {P0: "🔴", P1: "🔴", P2: "🟡", P3: "🔵", INFO: "🟢"}.get(sev, "⚪")


def _explain_finding(check_name: str, sev: str, msg: str) -> str:
    """Return a human-readable 'Why risky?' explanation for a finding."""
    msg_lower = msg.lower()
    # Chrome extension explanations
    if check_name == "Chrome Extensions":
        for perm, expl in PERM_EXPLANATIONS.items():
            if perm.lower() in msg_lower:
                return f"Why risky? This extension {expl}."
        if "malicious" in msg_lower:
            return "Why risky? This extension ID is flagged in known malware databases."
        if "baseline" in msg_lower:
            return "Why risky? An extension was installed since your last security baseline — verify you installed it."
    if check_name == "Startup Items":
        if "risky location" in msg_lower:
            return "Why risky? Legitimate apps don't usually start from Temp or Downloads folders — this is a common malware trick."
        if "baseline" in msg_lower:
            return "Why risky? A new program was added to auto-start since your last check. Verify you authorised it."
    if check_name == "Running Processes":
        return "Why risky? This process name matches known hacking tools (cryptominers, RATs, or C2 frameworks)."
    if check_name == "Network Connections":
        if "tor" in msg_lower:
            return "Why risky? This IP prefix is associated with the TOR anonymity network — often used to hide malicious traffic."
        return "Why risky? This port is commonly used by Metasploit, botnets, or remote-access backdoors."
    if check_name == "Hosts File":
        return "Why risky? Your browser is being redirected away from a trusted domain — attackers use this to steal passwords."
    if check_name == "WMI Persistence":
        return "Why risky? WMI subscriptions run silently in the background and survive reboots — a favourite APT persistence mechanism."
    if check_name == "Windows Defender":
        if "disabled" in msg_lower:
            return "Why risky? Without Real-time Protection your PC has no active malware shield."
        if "exclusion" in msg_lower:
            return "Why risky? Attackers add Defender exclusions to hide their malware from scans."
    if check_name == "Self-Integrity":
        return "Why risky? The security script itself may have been modified to hide threats from you."
    if check_name == "Event Log Audit":
        if "4625" in msg or "failed logon" in msg_lower:
            return "Why risky? Repeated failed logins may indicate a brute-force attack against your account."
        if "4720" in msg or "user account created" in msg_lower:
            return "Why risky? A new Windows user account was created — this is a common backdoor persistence method."
    return ""


def _finding_cta(chk: str, msg: str) -> str:
    """Return the correct call-to-action for a finding.
    PDF/web-capture Chrome extensions get a custom CTA instead of the generic one.
    All other findings use CTA_MAP.
    """
    if (chk == "Chrome Extensions"
            and "nativeMessaging" in msg
            and "webRequest" in msg
            and "all-URL" in msg):
        return "👉 Fix: Verify the installation source on the Chrome Web Store before removing."
    return CTA_MAP.get(chk, "")


def render_dashboard(
    all_findings: dict,
    summaries: dict,
    scan_duration: float,
    is_test: bool = False,
):
    """Print the full Security Dashboard to the console."""
    score  = _score_findings(all_findings)
    ts     = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M")
    W      = 60  # box width

    high_findings   = [(chk, sev, msg) for chk, fs in all_findings.items() for sev, msg in fs if sev in (P0, P1)]
    medium_findings = [(chk, sev, msg) for chk, fs in all_findings.items() for sev, msg in fs if sev == P2]
    low_findings    = [(chk, sev, msg) for chk, fs in all_findings.items() for sev, msg in fs if sev == P3]
    auto_findings   = [(chk, sev, msg) for chk, fs in all_findings.items() for sev, msg in fs if sev == AUTOMATION]
    # Rule 5: ok_checks only counts checks with NO non-automation findings
    ok_checks       = [chk for chk, fs in all_findings.items()
                       if not any(s not in (AUTOMATION,) for s, _ in fs)]

    test_banner = "  ⚠️  TEST MODE — simulated data  ⚠️" if is_test else ""
    total_real  = len(high_findings) + len(medium_findings) + len(low_findings)

    # ── Header ──────────────────────────────────────────────
    print()
    print(f"{Colors.BOLD}{Colors.CYAN}╔{'═' * W}╗{Colors.RESET}")
    title = f"🛡️  Security Monitor v{VERSION} — Daily Report"
    print(f"{Colors.BOLD}{Colors.CYAN}║  {title:<57}║{Colors.RESET}")
    sub   = f"{ts}  |  Scan: {scan_duration:.1f}s"
    print(f"{Colors.BOLD}{Colors.CYAN}║  {sub:<57}║{Colors.RESET}")
    if test_banner:
        print(f"{Colors.BOLD}{Colors.YELLOW}║  {test_banner:<57}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}╚{'═' * W}╝{Colors.RESET}")
    print()

    # ── Risk Score (excludes AUTOMATION findings from score) ────────────
    score_label = f"{score}/100"
    if score == 100:
        score_color, rating = Colors.GREEN, "CLEAN ✅"
    elif score >= 75:
        score_color, rating = Colors.GREEN, "GOOD"
    elif score >= 50:
        score_color, rating = Colors.YELLOW, "REVIEW NEEDED"
    elif score >= 25:
        score_color, rating = Colors.RED, "AT RISK ⚠️"
    else:
        score_color, rating = Colors.RED, "CRITICAL 🚨"

    print(f"  {Colors.BOLD}SECURITY SCORE:{Colors.RESET}  {score_color}{Colors.BOLD}{score_label}{Colors.RESET}  {_score_bar(score)}  {score_color}{rating}{Colors.RESET}")
    print(f"  {Colors.DIM}{len(high_findings)} high · {len(medium_findings)} medium · {len(low_findings)} low · {len(auto_findings)} automation · {len(ok_checks)}/{len(all_findings)} checks clean{Colors.RESET}")
    print()

    # ── HIGH section ────────────────────────────────────────
    if high_findings:
        print(f"  {Colors.RED}{Colors.BOLD}🔴 HIGH  ({len(high_findings)} issue{'s' if len(high_findings) != 1 else ''}){Colors.RESET}")
        for chk, sev, msg in high_findings:
            expl = _explain_finding(chk, sev, msg)
            cta  = _finding_cta(chk, msg)   # rule 3: PDF capture gets custom CTA
            print(f"  {Colors.RED}┌{'─' * (W - 2)}┐{Colors.RESET}")
            # Wrap the message
            for i, chunk in enumerate([msg[j:j+54] for j in range(0, max(len(msg), 1), 54)]):
                prefix = f"  {Colors.RED}│{Colors.RESET} [{chk}]  " if i == 0 else f"  {Colors.RED}│{Colors.RESET}          "
                print(f"{prefix}{Colors.WHITE}{chunk}{Colors.RESET}")
            if expl:
                print(f"  {Colors.RED}│{Colors.RESET}  {Colors.DIM}{expl}{Colors.RESET}")
            if cta:
                print(f"  {Colors.RED}│{Colors.RESET}  {Colors.CYAN}{cta}{Colors.RESET}")
            print(f"  {Colors.RED}└{'─' * (W - 2)}┘{Colors.RESET}")
        print()

    # ── MEDIUM section ──────────────────────────────────────
    if medium_findings:
        print(f"  {Colors.YELLOW}{Colors.BOLD}🟡 MEDIUM  ({len(medium_findings)} item{'s' if len(medium_findings) != 1 else ''}){Colors.RESET}")
        for chk, sev, msg in medium_findings:
            expl = _explain_finding(chk, sev, msg)
            cta  = _finding_cta(chk, msg)
            short_msg = msg if len(msg) <= 55 else msg[:52] + "..."
            print(f"    {Colors.YELLOW}•{Colors.RESET} {Colors.WHITE}{short_msg}{Colors.RESET}")
            if expl:
                print(f"      {Colors.DIM}{expl}{Colors.RESET}")
            if cta:
                print(f"      {Colors.CYAN}{cta}{Colors.RESET}")
        print()

    # ── AUTOMATION section ──────────────────────────────────────
    if auto_findings:
        print(f"  {Colors.CYAN}{Colors.BOLD}⚙️  AUTOMATION TOOLS  ({len(auto_findings)} extension{'s' if len(auto_findings) != 1 else ''}){Colors.RESET}")
        print(f"  {Colors.DIM}  These permissions are required for the tool to function. Not flagged as a threat.{Colors.RESET}")
        for chk, sev, msg in auto_findings:
            short_msg = msg if len(msg) <= 60 else msg[:57] + "..."
            print(f"    {Colors.CYAN}•{Colors.RESET} {Colors.WHITE}{short_msg}{Colors.RESET}")
        print()

    # ── LOW section ─────────────────────────────────────────
    if low_findings:
        print(f"  {Colors.CYAN}{Colors.BOLD}🔵 LOW  ({len(low_findings)} item{'s' if len(low_findings) != 1 else ''}){Colors.RESET}")
        for chk, sev, msg in low_findings:
            short_msg = msg if len(msg) <= 55 else msg[:52] + "..."
            print(f"    {Colors.CYAN}•{Colors.RESET} {Colors.DIM}{short_msg}{Colors.RESET}")
        print()

    # ── OK checks ───────────────────────────────────────────
    if ok_checks:
        print(f"  {Colors.GREEN}{Colors.BOLD}🟢 CLEAN{Colors.RESET}")
        # Print ok checks in lines of max ~56 chars
        line_buf = "    "
        for chk in ok_checks:
            token = f"✅ {chk}  "
            if len(line_buf) + len(token) > 58:
                print(f"{Colors.GREEN}{line_buf}{Colors.RESET}")
                line_buf = "    "
            line_buf += token
        if line_buf.strip():
            print(f"{Colors.GREEN}{line_buf}{Colors.RESET}")
        print()

    # ── Footer ──────────────────────────────────────────────
    print(f"{Colors.DIM}  Log: {LOG_FILE}  |  JSON: {JSON_LOG}{Colors.RESET}")
    print()


# ── Interactive --fix wizard ────────────────────────────────────────────────
def run_fix_wizard(all_findings: dict):
    """Interactively walk the user through each High finding with a fix CTA."""
    high_findings = [
        (chk, sev, msg)
        for chk, fs in all_findings.items()
        for sev, msg in fs
        if sev in (P0, P1)
    ]
    if not high_findings:
        print(f"  {Colors.GREEN}No high-severity findings to fix — you're all clear!{Colors.RESET}")
        return

    print(f"\n{Colors.BOLD}{Colors.RED}  🔧 FIX WIZARD — {len(high_findings)} high-severity issue(s){Colors.RESET}")
    print(f"  {Colors.DIM}Walk through each finding one at a time.{Colors.RESET}\n")

    for i, (chk, sev, msg) in enumerate(high_findings, 1):
        cta  = CTA_MAP.get(chk, "Manual review required")
        expl = _explain_finding(chk, sev, msg)
        print(f"  {Colors.BOLD}[{i}/{len(high_findings)}] {chk}{Colors.RESET}")
        print(f"  {Colors.RED}  Issue:  {msg}{Colors.RESET}")
        if expl:
            print(f"  {Colors.DIM}  Why?    {expl}{Colors.RESET}")
        print(f"  {Colors.CYAN}  Action: {cta}{Colors.RESET}")
        print()
        try:
            ans = input("  Mark as resolved and continue? [Y/n] → ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Fix wizard cancelled.")
            return
        if ans in ("n", "no"):
            print(f"  {Colors.YELLOW}  Skipped — will appear again in next scan.{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}  ✅ Marked for review. Remember to perform the action above!{Colors.RESET}")
        print()

    print(f"  {Colors.GREEN}Fix wizard complete. Re-run the scan after applying fixes.{Colors.RESET}\n")


# -- Interactive --clean wizard (whitelist + fix combined) --------------------
def run_clean_wizard(all_findings: dict, config: dict):
    """Walk through every finding and let the user Trust / Fix / Skip it.
    Trusted items are saved to config.json so they never alert again.
    """
    all_items = [
        (chk, sev, msg)
        for chk, fs in all_findings.items()
        for sev, msg in fs
    ]
    if not all_items:
        print(f"\n  {Colors.GREEN}Nothing to clean — your system is clear!{Colors.RESET}\n")
        return

    trusted = list(config.get("trusted_items", []))
    newly_trusted = []

    print(f"\n{Colors.BOLD}{Colors.CYAN}  🧹 CLEAN WIZARD — {len(all_items)} finding(s){Colors.RESET}")
    print(f"  {Colors.DIM}For each finding choose: [T]rust forever  [F]ix now  [S]kip{Colors.RESET}\n")

    for i, (chk, sev, msg) in enumerate(all_items, 1):
        emoji = "🔴" if sev in (P0, P1) else ("🟡" if sev == P2 else "🔵")
        cta   = CTA_MAP.get(chk, "")
        expl  = _explain_finding(chk, sev, msg)

        print(f"  {Colors.BOLD}[{i}/{len(all_items)}]{Colors.RESET} {emoji} {Colors.BOLD}{chk}{Colors.RESET}")
        short = msg if len(msg) <= 70 else msg[:67] + "..."
        print(f"  {Colors.WHITE}  {short}{Colors.RESET}")
        if expl:
            print(f"  {Colors.DIM}  {expl}{Colors.RESET}")
        if cta:
            print(f"  {Colors.CYAN}  {cta}{Colors.RESET}")
        print()

        try:
            ans = input("  [T]rust / [F]ix / [S]kip → ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Clean wizard cancelled.")
            break

        if ans in ("t", "trust"):
            # Extract a short keyword from the message to use as a pattern
            # Use first 40 chars of the message as the trust pattern
            pattern = msg[:40].rstrip()
            if pattern not in trusted:
                trusted.append(pattern)
                newly_trusted.append(pattern)
            print(f"  {Colors.GREEN}  ✅ Trusted! Won't appear in future scans.{Colors.RESET}")
        elif ans in ("f", "fix"):
            print(f"  {Colors.YELLOW}  Opening fix instructions...{Colors.RESET}")
            if cta:
                print(f"  {Colors.CYAN}  {cta}{Colors.RESET}")
            if "chrome" in chk.lower():
                # Fix 4: use subprocess.run with shell=False (works on Windows 11)
                subprocess.run(["cmd", "/c", "start", "chrome://extensions"],
                               shell=False, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            print(f"  {Colors.DIM}  Skipped.{Colors.RESET}")
        print()

    if newly_trusted:
        config["trusted_items"] = trusted
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        print(f"  {Colors.GREEN}✅ Saved {len(newly_trusted)} trust rule(s) to config.json.{Colors.RESET}")
        print(f"  {Colors.DIM}  These findings will be silently suppressed in all future scans.{Colors.RESET}\n")
    print(f"  {Colors.GREEN}Clean wizard done. Re-run the scan to see your updated score.{Colors.RESET}\n")


# ── Interactive --baseline-update wizard ─────────────────────────────────────
def run_baseline_update(all_findings: dict, baseline_data: dict):
    """Show drift findings and let the user approve new items into the baseline."""
    drift_findings = [
        (chk, msg)
        for chk, fs in all_findings.items()
        for sev, msg in fs
        if "baseline" in msg.lower() or "since baseline" in msg.lower()
    ]
    if not drift_findings:
        print(f"  {Colors.GREEN}  No baseline drift detected — nothing to approve.{Colors.RESET}")
        return

    print(f"\n{Colors.BOLD}{Colors.YELLOW}  📋 BASELINE UPDATE — {len(drift_findings)} new item(s) detected{Colors.RESET}")
    print(f"  {Colors.DIM}Approve items that YOU installed to suppress future alerts.{Colors.RESET}\n")

    approved = []
    for i, (chk, msg) in enumerate(drift_findings, 1):
        print(f"  [{i}/{len(drift_findings)}] {Colors.BOLD}{chk}{Colors.RESET}: {msg}")
        try:
            ans = input("  Did YOU install/create this? Approve it? [Y/n] → ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Baseline update cancelled.")
            return
        if ans not in ("n", "no"):
            approved.append((chk, msg))
            print(f"  {Colors.GREEN}  Approved - baseline will be regenerated.{Colors.RESET}")
        else:
            print(f"  {Colors.RED}  ⚠️  Flagged — keep investigating this item!{Colors.RESET}")
        print()

    if approved:
        print(f"  {Colors.YELLOW}  Regenerating baseline to include {len(approved)} approved item(s)...{Colors.RESET}")
        generate_baseline()
        print(f"  {Colors.GREEN}  ✅ Baseline updated. These items won't trigger alerts next scan.{Colors.RESET}\n")


# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description=f"Security Monitor v{VERSION} — Enterprise EDR Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_check.py               # Normal daily scan
  python security_check.py --test        # Simulate 5 threat types (E2E test)
  python security_check.py --doctor      # Diagnose install issues
  python security_check.py --baseline    # Regenerate system baseline
        """
    )
    parser.add_argument("--test",            action="store_true", help="Run E2E test with 5 simulated threats")
    parser.add_argument("--doctor",           action="store_true", help="Diagnose common installation issues")
    parser.add_argument("--baseline",         action="store_true", help="Regenerate the baseline.json snapshot")
    parser.add_argument("--fix",              action="store_true", help="Interactive wizard to fix high-severity findings")
    parser.add_argument("--baseline-update",  action="store_true", help="Approve new baseline items interactively")
    parser.add_argument("--clean",            action="store_true", help="Interactive clean wizard: Trust/Fix/Skip each finding")
    args = parser.parse_args()

    log("=" * 60)
    log(f"Security Monitor v{VERSION} — starting", INFO)
    log("=" * 60)

    config   = load_config()
    baseline_data = load_baseline()

    # ── Doctor Mode ────────────────────────────────────────────────────────────
    if args.doctor:
        log("  > DOCTOR MODE — diagnosing installation...", INFO)
        issues = 0

        # Python version
        if sys.version_info < (3, 8):
            log(f"    [FAIL] Python 3.8+ required, found {sys.version}", P0)
            issues += 1
        else:
            log(f"    [OK]   Python version: {sys.version.split()[0]}", INFO)

        # psutil
        try:
            import psutil
            log(f"    [OK]   psutil {psutil.__version__} installed", INFO)
        except ImportError:
            log("    [FAIL] psutil not installed — run setup.ps1", P0)
            issues += 1

        # Config
        if not CONFIG_FILE.exists():
            log("    [WARN] config.json missing — run setup.ps1", P2)
        elif config.get("email", {}).get("app_password") == "YOUR_GMAIL_APP_PASSWORD_HERE":
            log("    [WARN] Email not configured — run setup.ps1 to configure", P2)
        else:
            log("    [OK]   Email configured", INFO)

        # Baseline
        if not BASELINE.exists():
            log("    [WARN] baseline.json missing — run setup.ps1 or use --baseline", P2)
        else:
            log(f"    [OK]   Baseline exists (generated: {baseline_data.get('generated_at','?')})", INFO)

        # Scheduled task
        if IS_WINDOWS:
            out = run_ps("(Get-ScheduledTask -TaskName 'DailySecurityMonitor' -EA SilentlyContinue).TaskName")
            if out.strip():
                log("    [OK]   Scheduled task 'DailySecurityMonitor' exists", INFO)
            else:
                log("    [FAIL] Scheduled task missing — run setup.ps1 as Administrator", P1)
                issues += 1

        # Script hash
        if config.get("script_hash"):
            current = compute_script_hash()
            if current == config["script_hash"]:
                log("    [OK]   Script integrity hash matches", INFO)
            else:
                log("    [FAIL] Script hash mismatch — possible tampering!", P0)
                issues += 1
        else:
            log("    [WARN] No script hash stored — run setup.ps1 to enable", P2)

        log("=" * 60)
        log(f"Doctor complete — {issues} issue(s) found", P0 if issues else INFO)
        log("=" * 60)
        return issues

    # ── Baseline Regeneration ───────────────────────────────────────────────────
    if args.baseline:
        generate_baseline()
        log("Baseline regeneration complete.", INFO)
        return 0

    # ── Test Mode ──────────────────────────────────────────────────────────────
    if args.test:
        t0 = datetime.datetime.now()
        all_findings = {
            "Chrome Extensions":   [(P0, "Known malicious extension: FakeSpyware (bcjindcccaagfpapjjmafapmmgkkhgoa)")],
            "Running Processes":   [(P0, "Suspicious process: fake_miner.exe (PID 9999) — C:\\temp\\fake_miner.exe")],
            "WMI Persistence":     [(P0, "Suspicious WMI Consumer: 'EvilPersist' — cmd /c powershell -e <payload>")],
            "Windows Services":    [(P1, "Service running from risky path: evil_svc -> C:\\users\\public\\evil.exe")],
            "Startup Folders":     [(P1, "New startup folder item since baseline: C:\\Users\\Public\\autorun_payload.lnk")],
            "Hosts File":          [],
            "Network Connections": [],
            "Windows Defender":    [],
            "Scheduled Tasks":     [],
            "AI Tool Configs / MCP": [],
        }
        summaries = {k: "TEST" for k in all_findings}
        for check, findings in all_findings.items():
            for sev, msg in findings:
                json_log(check, sev, msg)
        duration = (datetime.datetime.now() - t0).total_seconds()
        render_dashboard(all_findings, summaries, duration, is_test=True)
        send_windows_notification(
            "Security Alert — 5 issue(s) [TEST]",
            "Test mode active. Click to open log!"
        )
        send_email_report(config, all_findings, summaries)
        log("Security Monitor Test — done.", INFO)
        return 1

    # ── Full Scan ──────────────────────────────────────────────────────────────
    checks = [
        ("Chrome Extensions",     lambda: check_chrome_extensions(baseline_data, config)),
        ("Startup Items",         lambda: check_startup_items(baseline_data)),
        ("Running Processes",     check_running_processes),
        ("Network Connections",   check_network_connections),
        ("Hosts File",            check_hosts_file),
        ("AI Tool Configs / MCP", check_ai_tool_configs),
        ("Windows Defender",      check_windows_defender),
        ("Scheduled Tasks",       lambda: check_scheduled_tasks(baseline_data)),
        ("Windows Services",      lambda: check_windows_services(baseline_data)),
        ("Startup Folders",       lambda: check_startup_folders(baseline_data)),
        ("WMI Persistence",       check_wmi_persistence),
        ("PowerShell Profiles",   check_powershell_profiles),
        ("BITS Jobs",             check_bits_jobs),
        ("Self-Integrity",        lambda: check_self_integrity(config)),
        ("Event Log Audit",       check_event_log),
    ]

    all_findings: dict = {}
    summaries:    dict = {}

    t0 = datetime.datetime.now()
    for check_name, check_fn in checks:
        # Write progress to stderr so it doesn't interfere with stdout dashboard
        sys.stderr.write(f"\r  \033[2K  \u25b8 {check_name}...")  # \033[2K = erase current line
        sys.stderr.flush()
        try:
            findings, summary = check_fn()
        except Exception as ex:
            findings, summary = [(P1, f"Exception: {ex}")], "Check failed"

        all_findings[check_name] = findings
        summaries[check_name]    = summary
        # Write to log file silently
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as lf:
            lf.write(f"[{ts}] {check_name}: {summary}\n")
            for sev, f in findings:
                lf.write(f"[{ts}]   [{sev}] {f}\n")
                json_log(check_name, sev, f)

    # Clear the progress line from stderr
    sys.stderr.write("\r\033[2K")
    sys.stderr.flush()

    duration       = (datetime.datetime.now() - t0).total_seconds()
    critical_count = sum(1 for v in all_findings.values() for sev, _ in v if sev in (P0, P1))
    total          = sum(len(v) for v in all_findings.values())

    # Apply whitelist filter before displaying
    all_findings = filter_findings(all_findings, config)
    render_dashboard(all_findings, summaries, duration)

    # ── Notification ───────────────────────────────────────
    total          = sum(len(v) for v in all_findings.values())
    critical_count = sum(1 for v in all_findings.values() for sev, _ in v if sev in (P0, P1))
    if total == 0:
        send_windows_notification(
            "Security Check Passed ✅",
            f"All 15 checks clean. Score: 100/100 ({datetime.datetime.now().strftime('%H:%M')})"
        )
    else:
        score = _score_findings(all_findings)
        send_windows_notification(
            f"🔴 Security Alert — {total} issue(s) — Score: {score}/100",
            f"{critical_count} high/critical severity. Click to open log!"
        )

    send_email_report(config, all_findings, summaries)

    # ── Optional post-scan modes ───────────────────────────
    if args.clean:
        run_clean_wizard(all_findings, config)
    elif args.fix:
        run_fix_wizard(all_findings)
    if args.baseline_update:
        run_baseline_update(all_findings, baseline_data)

    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
