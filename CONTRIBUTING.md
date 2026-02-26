# Contributing to Security Monitor

Thank you for your interest in contributing! Please read this short guide before submitting a PR.

---

## Platform

> **This project is Windows-only by design.**
> It uses Windows Credential Manager, the Windows Registry, PowerShell, WMI, and Task Scheduler natively.
> Cross-platform support is **not** a roadmap item.
> Contributors are welcome to fork and extend it for Linux/macOS.

---

## Getting Started

```powershell
git clone https://github.com/Amitro123/security_monitor.git
cd security_monitor
pip install -r requirements.txt
pytest tests/ -v
```

All tests should pass before you start making changes.

---

## Coding Style

| Rule | Detail |
|------|--------|
| **Type hints** | Required on all function parameters and return values |
| **Docstrings** | Required on all public functions (`"""Short summary.\n\nLonger explanation."""`) |
| **String formatting** | Use f-strings only — no `%` formatting or `.format()` |
| **Line length** | Maximum 100 characters |
| **Linting** | Passes `flake8 security_check.py --max-line-length=120 --ignore=E501,W503,E221,E241,E272,E226,E302,E305,E127,E128,W291,W293` |

---

## Submitting a PR

1. **Fork** the repo and create a **feature branch**: `git checkout -b feat/my-feature`
2. Make your changes
3. Run `pytest tests/ -v` — all tests must pass
4. Update **CHANGELOG.md** with a brief note under `[Unreleased]`
5. Submit a PR with a clear description of what changed and why

---

## Adding a New Detection Check

The project follows a consistent pattern for all 15 detection checks:

### 1. Write the check function

```python
def check_my_new_thing(baseline: dict) -> tuple[list, str]:
    """Scan for XYZ threat.

    Returns:
        (findings, summary) where findings is a list of (severity, message) tuples.
    """
    findings = []
    # ... your detection logic ...
    summary = f"{count} items scanned" + (" – OK" if not findings else "")
    return findings, summary
```

### 2. Register it in `main()`

```python
checks = [
    ...
    ("My New Check", lambda: check_my_new_thing(baseline_data)),
]
```

### 3. Add a CTA to `CTA_MAP`

```python
CTA_MAP = {
    ...
    "My New Check": "👉 Fix: Open XYZ → do this specific thing",
}
```

### 4. Add an explanation to `_explain_finding()`

```python
def _explain_finding(chk: str, sev: str, msg: str) -> str:
    ...
    if chk == "My New Check":
        return "Why this matters: explanation in plain English."
```

### 5. Write a test

Add a test in `tests/test_security_check.py` that covers the happy path and at least one edge case.

---

## Questions?

Open an issue — we're happy to help!
