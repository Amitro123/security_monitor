"""
v2.3.0 unit tests for security_check.py
Run: python test_v230.py
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))

# Patch CONFIG_FILE before importing to avoid migration side effects
import importlib
import security_check as sc

print("Running v2.3.0 tests...\n")

# ── Test 1: WMI known-safe whitelist ─────────────────────────────────────────
# BVTFilter and the SCM consumer are in WMI_KNOWN_SAFE and must not appear.
findings, summary = sc.check_wmi_persistence()
safe_names = sc.WMI_KNOWN_SAFE
for name in safe_names:
    assert not any(name in msg for _, msg in findings), \
        f"FAIL: '{name}' appeared in WMI findings but should be whitelisted"
print(f"PASS: WMI whitelist  ({len(findings)} non-safe finding(s) kept, {summary})")

# ── Test 2: net_connections timeout ──────────────────────────────────────────
import psutil as _psutil
_orig_net = _psutil.net_connections
_psutil.net_connections = lambda *a, **kw: (time.sleep(15), _orig_net(*a, **kw))[1]
findings2, summary2 = sc.check_network_connections()
_psutil.net_connections = _orig_net
assert "timed out" in summary2.lower(), \
    f"FAIL: expected 'timed out' in summary, got: {summary2!r}"
print(f"PASS: net_connections timeout  (summary: {summary2!r})")

# ── Test 3: keyring round-trip ───────────────────────────────────────────────
if sc.KEYRING_AVAILABLE:
    sc.save_credential("SecurityMonitor_Test", "test@test.com", "s3cr3t")
    val = sc.get_credential("SecurityMonitor_Test", "test@test.com")
    assert val == "s3cr3t", f"FAIL: expected 's3cr3t', got {val!r}"
    print("PASS: keyring round-trip")
else:
    print("SKIP: keyring not available on this machine")

# ── Test 4: E2E --test flag ───────────────────────────────────────────────────
import subprocess, sys as _sys
result = subprocess.run(
    [_sys.executable, "security_check.py", "--test"],
    capture_output=True, text=True, timeout=120
)
combined = result.stdout + result.stderr
assert result.returncode == 1, \
    f"FAIL: --test should exit 1 (threats found), got {result.returncode}"
assert any(kw in combined for kw in ("SECURITY SCORE", "Security Monitor", "HIGH")), \
    f"FAIL: dashboard not found in output. stdout={result.stdout[:300]!r}"
print("PASS: E2E --test completed (exit 1 = threats detected as expected)")

print("\n✅ All tests passed!")
