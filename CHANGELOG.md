# Changelog

All notable changes to Security Monitor are documented here.

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
