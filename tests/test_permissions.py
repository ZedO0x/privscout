"""Tests for modules/permissions.py (Module 09 - Permissions)."""

from modules import permissions


def test_check_sensitive_files_flags_writable_passwd(monkeypatch, tmp_path):
    fake_passwd = tmp_path / "passwd"
    fake_passwd.write_text("root:x:0:0:root:/root:/bin/bash\n")

    checks = [(str(fake_passwd), "writable", "CRITICAL", "writable passwd is bad")]
    monkeypatch.setattr(permissions, "SENSITIVE_FILE_CHECKS", checks)

    results = permissions.check_sensitive_files()
    assert len(results) == 1
    assert results[0]["path"] == str(fake_passwd)
    assert results[0]["issue"] == "writable"


def test_check_sensitive_files_skips_missing_files(monkeypatch):
    checks = [("/nonexistent/file", "writable", "CRITICAL", "n/a")]
    monkeypatch.setattr(permissions, "SENSITIVE_FILE_CHECKS", checks)
    assert permissions.check_sensitive_files() == []


def test_check_sensitive_files_readable_check(monkeypatch, tmp_path):
    fake_shadow = tmp_path / "shadow"
    fake_shadow.write_text("root:!:19000:0:99999:7:::\n")
    fake_shadow.chmod(0o644)  # readable by everyone for this test

    checks = [(str(fake_shadow), "readable", "HIGH", "shadow readable is bad")]
    monkeypatch.setattr(permissions, "SENSITIVE_FILE_CHECKS", checks)

    results = permissions.check_sensitive_files()
    assert len(results) == 1
    assert results[0]["issue"] == "readable"


def test_check_sudoers_d_flags_writable_fragment(monkeypatch, tmp_path):
    fragment = tmp_path / "custom"
    fragment.write_text("kali ALL=(ALL) ALL\n")
    fragment.chmod(0o666)

    monkeypatch.setattr(permissions, "SUDOERS_D_DIR", str(tmp_path))
    writable = permissions.check_sudoers_d()
    assert writable == [str(fragment)]


def test_check_sudoers_d_missing_dir_returns_empty(monkeypatch):
    monkeypatch.setattr(permissions, "SUDOERS_D_DIR", "/nonexistent/dir")
    assert permissions.check_sudoers_d() == []


def test_find_world_writable_etc_files(monkeypatch, tmp_path):
    writable_file = tmp_path / "bad.conf"
    writable_file.write_text("x=1\n")
    writable_file.chmod(0o666)

    normal_file = tmp_path / "normal.conf"
    normal_file.write_text("x=1\n")
    normal_file.chmod(0o644)

    monkeypatch.setattr(permissions, "ETC_DIR", str(tmp_path))
    found = permissions.find_world_writable_etc_files()
    assert found == [str(writable_file)]


def test_build_findings_covers_all_three_categories():
    sensitive_results = [{"path": "/etc/passwd", "issue": "writable", "severity": "CRITICAL", "description": "d"}]
    writable_sudoers_d = ["/etc/sudoers.d/custom"]
    world_writable = ["/etc/bad.conf"]

    findings = permissions.build_findings(sensitive_results, writable_sudoers_d, world_writable)
    assert len(findings) == 3
    categories = {f.category for f in findings}
    assert categories == {"Permissions"}
    severities = [f.severity for f in findings]
    assert severities == ["CRITICAL", "CRITICAL", "HIGH"]


def test_build_findings_empty_when_nothing_found():
    assert permissions.build_findings([], [], []) == []


def test_run_returns_expected_shape():
    result = permissions.run()
    assert "data" in result
    assert "findings" in result
    for key in ("sensitive_file_issues", "writable_sudoers_d", "world_writable_etc_files"):
        assert key in result["data"]
    assert isinstance(result["findings"], list)
