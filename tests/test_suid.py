"""Tests for modules/suid.py (Module 04 - SUID/SGID)."""

from modules import suid


def test_classify_binary_standard():
    assert suid.classify_binary("/usr/bin/passwd") == "standard"
    assert suid.classify_binary("/bin/su") == "standard"


def test_classify_binary_interesting_unrecognized_in_standard_dir():
    assert suid.classify_binary("/usr/bin/some_weird_capture_tool") == "interesting"


def test_classify_binary_custom_outside_standard_dirs():
    assert suid.classify_binary("/opt/tools/backup") == "custom"
    assert suid.classify_binary("/usr/local/bin/passwd") == "custom"  # even a known name, wrong dir


def test_summarize_counts_each_classification():
    binaries = [
        {"classification": "standard"},
        {"classification": "standard"},
        {"classification": "interesting"},
        {"classification": "custom"},
    ]
    assert suid.summarize(binaries) == {"standard": 2, "interesting": 1, "custom": 1}


def test_build_findings_flags_custom_as_high():
    binaries = [{"path": "/opt/tools/backup", "suid": True, "sgid": False, "classification": "custom"}]
    findings = suid.build_findings(binaries)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].category == "SUID"


def test_build_findings_flags_interesting_as_medium():
    binaries = [{"path": "/usr/bin/oddtool", "suid": True, "sgid": False, "classification": "interesting"}]
    findings = suid.build_findings(binaries)
    assert findings[0].severity == "MEDIUM"


def test_build_findings_ignores_standard_binaries():
    binaries = [{"path": "/usr/bin/passwd", "suid": True, "sgid": False, "classification": "standard"}]
    assert suid.build_findings(binaries) == []


def test_build_findings_flags_gtfobins_binary_as_critical_regardless_of_location():
    binaries = [{"path": "/usr/bin/find", "suid": True, "sgid": False, "classification": "standard"}]
    findings = suid.build_findings(binaries)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "find" in findings[0].title


def test_find_suid_binaries_dedupes_symlinked_directories(monkeypatch, tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    binary = real_dir / "tool"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o4755)

    link_dir = tmp_path / "link"
    link_dir.symlink_to(real_dir)

    monkeypatch.setattr(suid, "SEARCH_DIRS", [str(real_dir), str(link_dir)])
    found = suid.find_suid_binaries()
    assert len(found) == 1


def test_run_returns_expected_shape():
    result = suid.run()
    assert "data" in result
    assert "findings" in result
    assert "binaries" in result["data"]
    assert "summary" in result["data"]
    assert isinstance(result["findings"], list)
