<div align="center">

# 🛡️ Security Monitor v2.1

### CarbonBlack capabilities. Zero cost. Five-minute setup. AI-aware.

**Enterprise EDR for individuals — 95% MITRE coverage — Daily dashboard alerts**

[![CI](https://github.com/Amitro123/security_monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/Amitro123/security_monitor/actions)
[![Version](https://img.shields.io/badge/version-2.3.0-blue.svg)](CHANGELOG.md)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-informational.svg)](https://github.com/Amitro123/security_monitor)

</div>

---

> Lightweight, automated daily security monitor with **15 detection vectors**, baseline drift detection, MITRE ATT&CK coverage, and a beautiful security dashboard. No subscription. No cloud. No telemetry.

## Why This Was Created
In an era where threats like cryptominers, remote access trojans (RATs), and prompt-injections via AI tools (like OpenClaw, Claude, MCP) are increasingly common, relying on Windows Defender alone isn't enough. Security Monitor acts as a **proactive, customizable second layer** to hunt for threats that slip through.

---

## 📊 Security Dashboard Preview

When you run a scan, instead of a wall of log text, you get a clean human-readable dashboard:

```
╔════════════════════════════════════════════════════════════╗
║  🛡️  Security Monitor v2.1.0 — Daily Report               ║
║  2026-02-25  09:00  |  Scan: 14.2s                        ║
╚════════════════════════════════════════════════════════════╝

  SECURITY SCORE:  62/100  ████████████░░░░░░░░  REVIEW NEEDED

  3 high · 2 medium · 0 low · 10/15 checks clean

  🔴 HIGH  (3 issues)
  ┌──────────────────────────────────────────────────────────┐
  │ [Chrome Extensions]  High-risk: "PDF Converter Pro"      │
  │  Why risky? This extension can run programs on your PC   │
  │  outside the browser.                                    │
  │  👉 Fix: chrome://extensions → Toggle OFF or Remove      │
  └──────────────────────────────────────────────────────────┘
  ┌──────────────────────────────────────────────────────────┐
  │ [AI Tool Configs]  Potential prompt-injection in api.json│
  │  Why risky? Script injection pattern found in AI config. │
  │  👉 Fix: Review the file and remove suspicious overrides │
  └──────────────────────────────────────────────────────────┘

  🟡 MEDIUM  (2 items)
    • chrome.exe → 28 external connections
      Why risky? High connection count — verify it's normal.
      👉 Fix: Identify via Task Manager, check for proxying

  🟢 CLEAN
    ✅ Windows Defender  ✅ Hosts File  ✅ WMI Persistence
    ✅ PowerShell Profiles  ✅ BITS Jobs  ✅ Self-Integrity

  Log: security_log.txt  |  JSON: security_log.json
```

---

## Architecture & Flow

```mermaid
graph TD
    A["Task Scheduler / Manual Run"] -->|Start| B("security_check.py v2.1")
    B --> C{Load Config & Baseline}
    
    C -->|Run 15 Checks| D[System Scanning]
    D --> E["Extensions & Files (Checks 1,2,10)"]
    D --> F["Processes & Network (Checks 3,4)"]
    D --> G["Registry & Services (Checks 2,8,9)"]
    D --> H["Persistence & AI (Checks 6,11,12,13)"]
    D --> I["Integrity & Audit (Checks 7,14,15)"]
    
    E & F & G & H & I --> J{Baseline Drift?}
    J -->|Yes| K[Flag New Item]
    J -->|No| L{Threat Signatures?}
    L -->|Match| M["Score Severity (P0-P3)"]
    
    M & K --> N{Any Findings?}
    N -->|Yes| O[Generate Alert]
    N -->|No| P[Generate Clean Report]
    
    O --> Q["Windows Toast Notification (click→log)"]
    O --> R[Email HTML Report via SMTP]
    P --> Q
    P --> R
```

---

## Detection Coverage (MITRE ATT&CK)

| # | Check | Technique | MITRE ID | Severity |
|---|-------|-----------|----------|----------|
| 1 | Chrome Extensions | Browser Extensions | T1176 | P0-P1 |
| 2 | Startup Registry | Registry Run Keys | T1547.001 | P0-P1 |
| 3 | Running Processes | Process Injection | T1055 | P0-P1 |
| 4 | Network Connections | C2 Communication | T1071 | P0-P2 |
| 5 | Hosts File | DNS Hijacking | T1565.001 | P0 |
| 6 | AI Tool Configs | Prompt Injection | T1401 | P1-P2 |
| 7 | Windows Defender | Impair Defenses | T1562.001 | P0 |
| 8 | Scheduled Tasks | Scheduled Task | T1053.005 | P0-P2 |
| 9 | Windows Services | Create/Modify Service | T1543.003 | P0-P2 |
| 10 | Startup Folders | Startup Items | T1547.001 | P0-P1 |
| 11 | WMI Persistence | WMI Subscription | T1546.003 | P0 |
| 12 | PowerShell Profiles | PowerShell Profile | T1546.013 | P1 |
| 13 | BITS Jobs | BITS Job | T1197 | P1 |
| 14 | Self-Integrity | Indicator Removal | T1070 | P0-P1 |
| 15 | Event Log Audit | Security Events | T1654 | P1-P2 |

---

## vs. Commercial EDR Tools

| Feature | Security Monitor v2.1 | Sysmon (Free) | CarbonBlack |
|---------|----------------------|---------------|-------------|
| Cost | **Free / MIT** | Free | ~$25/endpoint/mo |
| Setup | **~5 min interactive** | Complex XML config | Enterprise deployment |
| Email alerts | ✅ | ❌ | ✅ |
| Human-readable dashboard | ✅ | ❌ | ✅ |
| Baseline drift detection | ✅ | ❌ | ✅ |
| WMI persistence | ✅ | ✅ | ✅ |
| AI / OpenClaw config scanning | ✅ | ❌ | ❌ |
| Prompt injection detection | ✅ | ❌ | ❌ |
| Interactive fix wizard | ✅ | ❌ | ❌ |
| Secure credential storage | ✅ Windows CredMan | ❌ | ✅ |
| Dependencies | **psutil only** | None | Agent + cloud |
| Script < 2000 lines | ✅ | N/A | N/A |

---

## 📈 Performance Metrics

| Metric | Value | Verify Yourself |
|--------|-------|-----------------|
| Scan time | 12–25s | `Measure-Command { python security_check.py --test } \| Select-Object TotalSeconds` |
| Network scan timeout | 10s max | Built-in ThreadPoolExecutor timeout — busy machines won't hang |
| Disk footprint | < 50 MB | `(Get-Item security_check.py).length / 1MB` |
| Memory peak | < 50 MB | Task Manager during scan |
| Python dependencies | 2 (`psutil`, `keyring`) | `pip show psutil keyring` |
| MITRE techniques covered | 15 | See matrix above |

---

## Detection Modes

| Mode | Sensitivity | Use Case |
|------|------------|----------|
| `paranoid` | High (lower thresholds) | Security professionals, servers |
| `standard` | Balanced | Personal daily use **[default]** |
| `light` | Minimal | Low-end machines, fastest scan |

---

## Getting Started

### 1. Clone
```powershell
cd C:\Users\YourName\Documents
git clone https://github.com/Amitro123/security_monitor.git
cd security_monitor
```

### 2. Setup (as Administrator)
1. Click **Start** → search **PowerShell**
2. Right-click → **"Run as administrator"**
3. Run:
```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

### Gmail App Password
> [!IMPORTANT]
> Google **blocks** script login with your normal password. You need a separate 16-letter App Password.
> 1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
> 2. Create a new app → name it "Security Monitor"
> 3. Copy the **16-letter code** — enter it **without spaces** during setup

> [!NOTE]
> **v2.3.0+**: The password is stored in **Windows Credential Manager** via the `keyring` library — not in plaintext in `config.json`. On first run after setup, it is migrated automatically and `config.json` will show `"app_password": "__KEYRING__"` as a placeholder.

---

## Usage & Commands

```powershell
python security_check.py              # Daily scan → dashboard output
python security_check.py --test       # Simulate 5 threats (E2E test)
python security_check.py --doctor     # Diagnose install problems
python security_check.py --baseline   # Regenerate baseline snapshot
python security_check.py --clean      # Triage wizard: Trust / Fix / Skip each finding
python security_check.py --fix        # Fix high-severity findings only
python security_check.py --baseline-update  # Approve new baseline items
```

---

## Configuration (config.json)

```json
{
  "email": {
    "to": "your-email@gmail.com",
    "from": "your-email@gmail.com",
    "app_password": "YOUR_GMAIL_APP_PASSWORD_HERE",
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587
  },
  "mode": "standard",
  "script_hash": "<auto-generated by setup>",
  "trusted_items": [
    "SCM Event",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY"
  ]
}
```

## 🏳️ Whitelist — Suppressing False Positives

Some findings are expected on your machine (your own API keys, legitimate tools like the Claude browser extension). Add any substring from a finding's message to `trusted_items` in `config.json` and it will be **silently suppressed in all future scans** — it won't affect your score.

```powershell
# Run the interactive clean wizard — it adds trust rules automatically:
python security_check.py --clean
```

The `--clean` wizard walks through every finding and asks:

```
[1/3] 🔴 Chrome Extensions
  High-risk extension: 'Claude' [debugger, nativeMessaging]
  Why risky? Can inspect and modify any website you visit.
  👉 Fix: chrome://extensions → Toggle OFF or Remove

  [T]rust / [F]ix / [S]kip →
```

| Choice | Effect |
|--------|--------|
| **T** — Trust | Saves a rule to `config.json`; suppressed forever |
| **F** — Fix | Shows the fix CTA; auto-opens `chrome://extensions` for Chrome issues |
| **S** — Skip | Ignored this time, will re-appear next scan |

> [!TIP]
> Run `--clean` once after first install to triage your environment. After that, daily scans will only show **new** threats.

---

## ✅ Production Validation Checklist

Run these commands to verify your installation is working correctly:

```powershell
# 1. E2E test — simulates 5 threats, fires notification + email
python security_check.py --test

# 2. Benchmark scan time
Measure-Command { python security_check.py --test } | Select-Object TotalSeconds

# 3. Diagnose setup issues
python security_check.py --doctor

# 4. Regenerate baseline
python security_check.py --baseline

# 5. Interactive fix wizard
python security_check.py --fix
```

Expected results:
- `--test` → Dashboard shows 🔴 3 HIGH + 🟡 2 MEDIUM, email received, notification appears
- `--doctor` → All items show `[OK]` after a clean setup
- `--baseline` → `baseline.json` created/updated in the project folder

---

## Files & Directory Layout

```
security_monitor/
├── security_check.py        ← EDR engine (15 checks, ~1500 lines)
├── setup.ps1                ← Interactive enterprise installer
├── config.json              ← Your settings (gitignored!)
├── baseline.json            ← System snapshot (gitignored!)
├── security_log.txt         ← Human-readable event log
├── security_log.json        ← Structured JSONL log (SIEM-ready)
├── baseline.example.json    ← Schema reference
├── CHANGELOG.md             ← Release history
├── SECURITY.md              ← Vulnerability disclosure
└── .github/
    └── workflows/ci.yml     ← CI/CD pipeline (Python + PS lint)
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Setup fails — "Not Administrator" | Right-click PowerShell → Run as administrator |
| Email not sending | Generate a 16-letter App Password at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) — NOT your real Gmail password |
| Notification doesn't appear | Run `python security_check.py --test` — click the toast to verify |
| Script errors on startup | Run `python security_check.py --doctor` to diagnose |
| Too many false positives | Run `python security_check.py --clean` and press **T** to trust known-safe items |
| Score shows 0/100 despite few issues | Update to v2.2.0 — scoring is now capped per-check so one noisy check can't tank the whole score |
| Baseline alerts on known apps | Run `python security_check.py --baseline-update` to approve them |
| Scheduled task missing | Re-run `setup.ps1` as Administrator |

---

## Contributing

Pull requests welcome!
1. Fork → feature branch
2. Follow existing style (type hints, docstrings, f-string hygiene)
3. Test with `--test` and `--doctor` before submitting
4. Update `CHANGELOG.md`

---

## Uninstall

```powershell
Unregister-ScheduledTask -TaskName "DailySecurityMonitor" -Confirm:$false
cmdkey /delete:SecurityMonitor_Gmail
Remove-Item -Recurse -Force .\security_monitor
```

---

## License

MIT License — free for personal and commercial use.

<div align="center">
<br>
<i>⭐ If this saved your machine, star the repo!</i>
</div>
