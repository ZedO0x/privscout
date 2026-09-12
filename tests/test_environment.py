"""Tests for modules/environment.py (Module 10 - Environment)."""

from modules import environment


def test_get_path_directories_splits_and_drops_empty(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin::/bin:")
    assert environment.get_path_directories() == ["/usr/bin", "/bin"]


def test_analyze_path_directories_flags_relative_entry():
    analysis = environment.analyze_path_directories([".", "relative/dir"])
    assert all(entry["relative"] for entry in analysis)
    assert all(not entry["writable"] for entry in analysis)


def test_analyze_path_directories_flags_writable_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", "/nonexistent/unrelated/home")
    writable_dir = tmp_path / "bin"
    writable_dir.mkdir()
    writable_dir.chmod(0o777)

    analysis = environment.analyze_path_directories([str(writable_dir)])
    assert analysis[0]["exists"] is True
    assert analysis[0]["writable"] is True
    assert analysis[0]["relative"] is False
    assert analysis[0]["in_home"] is False


def test_analyze_path_directories_marks_home_subdirectory(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    bin_dir = tmp_path / ".local" / "bin"
    bin_dir.mkdir(parents=True)

    analysis = environment.analyze_path_directories([str(bin_dir)])
    assert analysis[0]["in_home"] is True


def test_analyze_path_directories_handles_missing_dir():
    analysis = environment.analyze_path_directories(["/this/does/not/exist"])
    assert analysis[0]["exists"] is False
    assert analysis[0]["writable"] is False


def test_get_library_env_vars_only_returns_set_vars(monkeypatch):
    monkeypatch.delenv("LD_PRELOAD", raising=False)
    monkeypatch.delenv("LD_LIBRARY_PATH", raising=False)
    assert environment.get_library_env_vars() == {}

    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    assert environment.get_library_env_vars() == {"LD_PRELOAD": "/tmp/evil.so"}


def test_build_findings_flags_relative_path_entry():
    analysis = [{"path": ".", "exists": False, "relative": True, "writable": False, "in_home": False}]
    findings = environment.build_findings(analysis, {})
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].category == "Environment"


def test_build_findings_flags_writable_path_entry_outside_home():
    analysis = [{"path": "/opt/bin", "exists": True, "relative": False, "writable": True, "in_home": False}]
    findings = environment.build_findings(analysis, {})
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_build_findings_ignores_writable_dir_inside_home():
    analysis = [{"path": "/home/kali/.local/bin", "exists": True, "relative": False, "writable": True, "in_home": True}]
    assert environment.build_findings(analysis, {}) == []


def test_build_findings_ignores_normal_entries():
    analysis = [{"path": "/usr/bin", "exists": True, "relative": False, "writable": False, "in_home": False}]
    assert environment.build_findings(analysis, {}) == []


def test_build_findings_deduplicates_repeated_path_entries():
    analysis = [
        {"path": "/opt/bin", "exists": True, "relative": False, "writable": True, "in_home": False},
        {"path": "/opt/bin", "exists": True, "relative": False, "writable": True, "in_home": False},
    ]
    findings = environment.build_findings(analysis, {})
    assert len(findings) == 1


def test_build_findings_flags_ld_preload():
    findings = environment.build_findings([], {"LD_PRELOAD": "/tmp/evil.so"})
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "LD_PRELOAD" in findings[0].title


def test_run_returns_expected_shape():
    result = environment.run()
    assert "data" in result
    assert "findings" in result
    for key in ("path_directories", "path_analysis", "library_env_vars"):
        assert key in result["data"]
    assert isinstance(result["findings"], list)
