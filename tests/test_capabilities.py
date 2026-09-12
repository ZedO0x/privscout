"""Tests for modules/capabilities.py (Module 05 - Capabilities)."""

from modules import capabilities

SAMPLE_OUTPUT = """/usr/bin/dumpcap cap_net_admin,cap_net_raw=eip
/usr/bin/python3.11 cap_setuid,cap_setgid=ep
/usr/bin/fping cap_net_raw=ep
"""


def make_result(success=True, stdout="", stderr="", returncode=0, error=None):
    return {"success": success, "stdout": stdout, "stderr": stderr, "returncode": returncode, "error": error}


def test_parse_getcap_output_extracts_entries():
    entries = capabilities.parse_getcap_output(SAMPLE_OUTPUT)
    assert len(entries) == 3
    assert entries[0]["path"] == "/usr/bin/dumpcap"
    assert entries[0]["capabilities"] == ["cap_net_admin", "cap_net_raw"]


def test_parse_getcap_output_ignores_blank_lines():
    entries = capabilities.parse_getcap_output("\n\n" + SAMPLE_OUTPUT + "\n")
    assert len(entries) == 3


def test_classify_entry_dangerous_setuid_is_critical():
    entry = {"path": "/usr/bin/python3.11", "capabilities": ["cap_setuid", "cap_setgid"], "raw": "cap_setuid,cap_setgid=ep"}
    severity, matched = capabilities.classify_entry(entry)
    assert severity == "CRITICAL"
    assert set(matched) == {"cap_setuid", "cap_setgid"}


def test_classify_entry_net_raw_is_low():
    entry = {"path": "/usr/bin/fping", "capabilities": ["cap_net_raw"], "raw": "cap_net_raw=ep"}
    severity, matched = capabilities.classify_entry(entry)
    assert severity == "LOW"
    assert matched == ["cap_net_raw"]


def test_classify_entry_unknown_cap_is_info_and_unmatched():
    entry = {"path": "/usr/bin/weird", "capabilities": ["cap_something_unlisted"], "raw": "cap_something_unlisted=ep"}
    severity, matched = capabilities.classify_entry(entry)
    assert severity == "INFO"
    assert matched == []


def test_build_findings_skips_entries_with_no_dangerous_caps():
    entries = [{"path": "/usr/bin/weird", "capabilities": ["cap_something_unlisted"], "raw": "x"}]
    assert capabilities.build_findings(entries) == []


def test_build_findings_produces_finding_for_dangerous_caps():
    entries = capabilities.parse_getcap_output(SAMPLE_OUTPUT)
    findings = capabilities.build_findings(entries)
    # dumpcap (LOW/net caps), python3.11 (CRITICAL setuid/setgid), fping (LOW net_raw)
    assert len(findings) == 3
    severities = {f.severity for f in findings}
    assert "CRITICAL" in severities


def test_run_returns_expected_shape(monkeypatch):
    monkeypatch.setattr(capabilities, "check_capabilities", lambda: make_result(success=True, stdout=SAMPLE_OUTPUT))
    result = capabilities.run()
    assert "data" in result
    assert "findings" in result
    assert result["data"]["available"] is True
    assert len(result["data"]["entries"]) == 3


def test_run_handles_missing_getcap_binary(monkeypatch):
    monkeypatch.setattr(
        capabilities, "check_capabilities",
        lambda: make_result(success=False, error="Command not found: getcap"),
    )
    result = capabilities.run()
    assert result["data"]["available"] is False
    assert result["findings"] == []
