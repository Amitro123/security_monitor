# Changelog

All notable changes to Security Monitor are documented here.

## [2.3.0] — 2026-02-26

### Added
- **Full pytest test suite** — 10 tests in `tests/test_security_check.py` covering WMI whitelist, extension dedup, source detection, automation classification, net timeout, keyring, filter_findings, CTA logic, dashboard counter, and E2E mode
- **`pyproject.toml`** and **`requirements.txt`** for standard Python packaging (`pip install -r requirements.txt`)
- **`CONTRIBUTING.md`** — Windows-only policy, coding style guide, and instructions for adding new detection checks
- **`WMI_KNOWN_SAFE`** whitelist — eliminates BVTFilter / SCM Event Log Consumer false positives
- **net_connections 10-second timeout** using `ThreadPoolExecutor` — prevents scan hang on busy machines
- **Keyring credential storage** — Gmail password migrated from plaintext `config.json` to Windows Credential Manager on first run
- **`chrome://extensions` subprocess fix** — uses `shell=False` for reliable behavior on Windows 11

### Changed
- README: added Windows-only badge, Contributing badge, Requirements section, and Windows-only note in intro
- Version bumped to 2.3.0

---



### 🔒 Security Hardening

#### Fix 1 — Secure Email Password Storage
- Added `keyring` as a dependency (auto-installed on first run)
- Added `save_credential()` and `get_credential()` helpers backed by Windows Credential Manager
- `load_config()` now auto-migrates a plaintext `app_password` to keyring on first run; `config.json` stores `"__KEYRING__"` as a placeholder
- `send_email_report()` now retrieves the password via `get_credential()` with plaintext fallback

#### Fix 2 — WMI False Positive Whitelist
- Added `WMI_KNOWN_SAFE` constant (BVTFilter, SCM Event Log Consumer, NTEventLogEventConsumer, etc.)
- `check_wmi_persistence()` now skips any subscription object whose name is in `WMI_KNOWN_SAFE`

#### Fix 3 — Network Scan Timeout
- Wrapped `psutil.net_connections()` in a `ThreadPoolExecutor` with a **10-second timeout**
- Busy machines no longer cause a 30-second hang; summary reads `"Network scan timed out (>10s) — skipped"` if exceeded

#### Fix 4 — `chrome://extensions` Subprocess Fix
- `--clean` wizard now uses `subprocess.run(shell=False)` instead of `Popen(shell=True)` to reliably open `chrome://extensions` on Windows 11

#### Testing
- Added `test_v230.py` with 4 unit tests (WMI whitelist, net timeout, keyring round-trip, E2E `--test`) — all pass

---

## [2.0.0] — 2026-02-25


### 🚀 Major Release — Enterprise EDR Engine

#### Added (New Checks)
- **Windows Services** — detects new auto-start services or services running from risky paths
- **Startup Folders** — scans User and AllUsers startup folders for new/changed items
- **WMI Persistence** — detects WMI EventFilters and CommandLineEventConsumers
- **PowerShell Profiles** — checks for tampered PS profiles with download cradles
- **BITS Jobs** — detects Background Intelligent Transfer Service abuse
- **Self-Integrity** — validates script SHA256 hash against stored baseline and ensures the scheduled task hasn't been removed
- **Event Log Audit** — scans Windows Security Event Logs for the last 24h (failed logons, user creation, new services)
- **OpenClaw Config Scanning** — dedicated detection for OpenClaw AI tool config directories

#### Enhanced (Existing Checks)
- Chrome Extensions: Added baseline drift detection and configurable permission threshold
- Startup Items: Added baseline drift detection for new registry Run keys
- Scheduled Tasks: Added baseline drift detection for new tasks
- Windows Defender: Added signature staleness check and exclusions audit
- Network Connections: Added TOR exit node IP prefix detection

#### New Features
- `--doctor` flag — diagnoses common installation issues
- `--baseline` flag — regenerates the system baseline.json snapshot
- `--test` flag — simulates 5 threat types for E2E validation
- Severity scoring: P0 (CRITICAL) / P1 (HIGH) / P2 (MEDIUM) / P3 (LOW)
- Structured JSON logging alongside human-readable console output
- Baseline drift detection across extensions, startup items, services, and tasks
- Graceful degradation: email failure falls back to file log and Windows notification

#### Enterprise
- Windows Credential Manager integration (no more plaintext `config.json` secrets)
- BitLocker detection and warning
- Detection mode selector: `paranoid` / `standard` / `light`
- Windows Event Log audit trail for the installer
- Self-healing scheduled task validation

#### Documentation
- MITRE ATT&CK coverage matrix
- Comparison table vs Sysmon and CarbonBlack
- Architecture Mermaid flowchart
- Troubleshooting guide
- SECURITY.txt vulnerability disclosure
- GitHub Actions CI/CD pipeline

---

## [1.0.0] — 2026-02-20

### Initial Release
- 8 security checks: Chrome Extensions, Startup Registry, Processes, Network, Hosts File, AI Configs, Defender, Scheduled Tasks
- Email alerts via Gmail SMTP
- Windows balloon tip notifications
- Interactive PowerShell setup
