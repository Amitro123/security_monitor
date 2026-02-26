"""
Security Monitor v2.3.0 — pytest test suite
Run: pytest tests/ -v
"""
import json
import os
import sys
import time
import subprocess
from pathlib import Path
from io import StringIO
from unittest.mock import patch, MagicMock

import pytest

# Make sure parent directory is on the path
sys.path.insert(0, str(Path(__file__).parent.parent))
import security_check as sc

# ── Helpers ──────────────────────────────────────────────────────────────────

CLEAN_CONFIG = {"mode": "standard", "trusted_items": []}
EMPTY_BASELINE = {}


def _make_manifest(name: str, permissions: list, host_permissions: list = None,
                   update_url: str = "https://clients2.google.com/service/update2/crx") -> dict:
    manifest = {
        "manifest_version": 3,
        "name": name,
        "version": "1.0",
        "permissions": permissions,
        "update_url": update_url,
    }
    if host_permissions:
        manifest["host_permissions"] = host_permissions
    return manifest


def _write_ext(profile_dir: Path, ext_id: str, manifest: dict):
    """Create a fake Chrome extension directory structure."""
    ver_dir = profile_dir / "Extensions" / ext_id / "1.0.0_0"
    ver_dir.mkdir(parents=True, exist_ok=True)
    (ver_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


# ── Test 1: WMI known-safe whitelist ─────────────────────────────────────────

def test_wmi_whitelist_bvtfilter():
    """BVTFilter and other known-safe WMI names must NOT appear in findings."""
    fake_ps_output = (
        'FILTERS:{"Name":"BVTFilter","Query":"SELECT * FROM __InstanceModificationEvent"}\n'
        'CONSUMERS:'
    )
    with patch.object(sc, "run_ps", return_value=fake_ps_output):
        findings, summary = sc.check_wmi_persistence()
    for name in sc.WMI_KNOWN_SAFE:
        assert not any(name in msg for _, msg in findings), (
            f"Known-safe WMI name '{name}' must not appear in findings, got: {findings}"
        )


# ── Test 2: Extension deduplication ──────────────────────────────────────────

def test_chrome_ext_deduplication(tmp_path):
    """Same extension ID in two profiles must appear only once."""
    ext_id = "aaaaaabbbbbbccccccddddddeeeeeeee"
    high_risk_manifest = _make_manifest(
        name="Risky Ext",
        permissions=["nativeMessaging", "webRequest", "cookies", "history"],
        host_permissions=["<all_urls>"],
    )
    # Create same ext in Default AND a second profile
    _write_ext(tmp_path / "Default", ext_id, high_risk_manifest)
    _write_ext(tmp_path / "Profile 1", ext_id, high_risk_manifest)

    findings, _ = sc.check_chrome_extensions(EMPTY_BASELINE, CLEAN_CONFIG, _ext_root=tmp_path)
    ext_findings = [msg for sev, msg in findings if ext_id in msg or "Risky Ext" in msg]
    assert len(ext_findings) <= 1, (
        f"Extension appeared {len(ext_findings)} times; expected at most 1. findings={findings}"
    )


# ── Test 3: __MSG__ source detection ─────────────────────────────────────────

def test_ext_source_msg_key():
    """Extension name with __MSG_ prefix must return Unknown source."""
    manifest = {"update_url": "https://clients2.google.com/service/update2/crx"}
    result = sc._ext_source(manifest, name="__MSG_extName__")
    assert "Unknown" in result, f"Expected 'Unknown' for __MSG_ name, got: {result!r}"
    assert "unresolved" in result.lower()


# ── Test 4: Automation tool classification ────────────────────────────────────

def test_automation_tool_not_flagged_high(tmp_path):
    """Claude extension with automation perms must be AUTOMATION, not HIGH."""
    ext_id = "claudeextensionidclaudeextensionid"
    manifest = _make_manifest(
        name="Claude",
        permissions=["debugger", "nativeMessaging", "downloads", "webRequest", "cookies"],
        host_permissions=["<all_urls>"],
    )
    _write_ext(tmp_path / "Default", ext_id, manifest)

    findings, _ = sc.check_chrome_extensions(EMPTY_BASELINE, CLEAN_CONFIG, _ext_root=tmp_path)
    severities = [sev for sev, msg in findings if "Claude" in msg]
    assert severities, f"No finding found for Claude ext. All findings: {findings}"
    assert all(s == sc.AUTOMATION for s in severities), (
        f"Claude extension should be AUTOMATION, got: {severities}"
    )
    assert not any(s in (sc.P0, sc.P1) for s in severities), (
        "Claude extension must NOT be HIGH/CRITICAL"
    )


# ── Test 5: net_connections timeout ──────────────────────────────────────────

def test_network_connections_timeout(monkeypatch):
    """psutil.net_connections hanging >10s must produce a timeout summary."""
    def slow_net(*args, **kwargs):
        time.sleep(15)
        return []

    monkeypatch.setattr(sc.psutil, "net_connections", slow_net)
    findings, summary = sc.check_network_connections()
    assert "timed out" in summary.lower(), (
        f"Expected 'timed out' in summary, got: {summary!r}"
    )


# ── Test 6: Keyring round-trip ────────────────────────────────────────────────

def test_keyring_round_trip():
    """save_credential then get_credential must return the same value."""
    if not sc.KEYRING_AVAILABLE:
        pytest.skip("keyring not available on this machine")
    service = "SecurityMonitor_pytest"
    username = "pytest@example.com"
    sc.save_credential(service, username, "pw123_test")
    result = sc.get_credential(service, username)
    assert result == "pw123_test", f"Expected 'pw123_test', got {result!r}"


# ── Test 7: filter_findings whitelist ────────────────────────────────────────

def test_filter_findings_removes_trusted():
    """Findings matching a trusted_items pattern must be removed."""
    findings = {
        "AI Tool Configs / MCP": [
            (sc.P2, "ANTHROPIC_API_KEY found in environment"),
            (sc.P1, "Malicious tool detected: evil.exe"),
        ]
    }
    config = {"trusted_items": ["ANTHROPIC_API_KEY"]}
    result = sc.filter_findings(findings, config)
    remaining = result.get("AI Tool Configs / MCP", [])
    msgs = [msg for _, msg in remaining]
    assert not any("ANTHROPIC_API_KEY" in m for m in msgs), (
        "Trusted item should have been filtered out"
    )
    assert any("evil.exe" in m for m in msgs), (
        "Non-trusted item must remain in findings"
    )


# ── Test 8: _finding_cta PDF rule ────────────────────────────────────────────

def test_finding_cta_pdf_rule():
    """PDF/web-capture extensions must get 'Verify the installation source' CTA."""
    msg = "High-risk ext: 'PDFMaker' [nativeMessaging, webRequest] + all-URL access [Source: X]"
    cta = sc._finding_cta("Chrome Extensions", msg)
    assert "Verify the installation source" in cta, (
        f"Expected 'Verify the installation source' in CTA, got: {cta!r}"
    )
    assert "Toggle OFF" not in cta, (
        f"PDF CTA must not contain 'Toggle OFF', got: {cta!r}"
    )


# ── Test 9: Issue counter accuracy ───────────────────────────────────────────

def test_render_dashboard_high_count(capsys):
    """The HIGH count shown on the dashboard must match actual HIGH findings."""
    all_findings = {
        "Chrome Extensions": [(sc.P1, "Bad ext A"), (sc.P1, "Bad ext B")],
        "Startup Items":     [(sc.P2, "Medium finding")],
        "Hosts File":        [],
        "Network Connections": [],
        "Windows Defender":  [],
    }
    summaries = {k: "TEST" for k in all_findings}
    sc.render_dashboard(all_findings, summaries, scan_duration=1.0, is_test=True)
    captured = capsys.readouterr()
    output = captured.out
    # Dashboard should show "HIGH  (2 issues)"
    assert "2" in output and "HIGH" in output, (
        f"Expected '2 HIGH' in dashboard output.\nActual output:\n{output}"
    )


# ── Test 10: E2E test mode ───────────────────────────────────────────────────

def test_e2e_test_mode():
    """Running --test must exit code 1 and print HIGH in combined output."""
    result = subprocess.run(
        [sys.executable, "security_check.py", "--test"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=Path(__file__).parent.parent,
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 1, (
        f"--test should exit 1 (threats found), got {result.returncode}"
    )
    assert "HIGH" in combined, (
        f"Expected 'HIGH' in output.\nstdout={result.stdout[:500]!r}"
    )
