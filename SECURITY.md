# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | ✅ Yes             |
| 1.x     | ⚠️ End of Life     |

## Reporting a Vulnerability

If you discover a security vulnerability in Security Monitor, please **do not open a public GitHub issue**.

Instead, report it privately:

1. Go to the repository's **Security** tab on GitHub.
2. Click **"Report a vulnerability"**.
3. Provide a detailed description including steps to reproduce and potential impact.

We aim to respond within **48 hours** and will work to release a fix within **7 days** for critical issues.

## Disclosure Policy

- Private report received → acknowledged within 48h
- Fix developed and tested internally
- Patch released → public disclosure coordinated with reporter
- Credit given in CHANGELOG.md (unless reporter requests anonymity)

## Scope

The following are in scope for vulnerability reports:
- Script injection or bypass of detection checks
- Credential leakage from `config.json` or Windows Credential Manager
- Privilege escalation via the scheduled task

The following are **out of scope**:
- False positive/negative detection rates
- Feature requests
