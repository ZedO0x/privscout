"""Tests for modules/services.py (Module 07 - Services)."""

from modules import services

SAMPLE_OUTPUT = """accounts-daemon.service loaded active running Accounts Service
apache2.service loaded active running The Apache HTTP Server
apparmor.service loaded inactive dead Load AppArmor profiles
broken.service loaded failed failed A broken service
"""


def test_parse_service_units_extracts_fields():
    units = services.parse_service_units(SAMPLE_OUTPUT)
    assert len(units) == 4
    assert units[0]["unit"] == "accounts-daemon.service"
    assert units[0]["sub"] == "running"
    assert units[0]["description"] == "Accounts Service"


def test_parse_service_units_ignores_blank_lines():
    units = services.parse_service_units("\n\n" + SAMPLE_OUTPUT)
    assert len(units) == 4


def test_summarize_counts_running_and_failed():
    units = services.parse_service_units(SAMPLE_OUTPUT)
    summary = services.summarize(units)
    assert summary["total"] == 4
    assert summary["running"] == 2
    assert summary["failed"] == 1


def test_find_unit_files_only_matches_service_suffix(tmp_path, monkeypatch):
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    (unit_dir / "foo.service").write_text("[Unit]\n")
    (unit_dir / "foo.timer").write_text("[Timer]\n")

    monkeypatch.setattr(services, "UNIT_DIRS", [str(unit_dir)])
    found = services.find_unit_files()
    assert found == [str(unit_dir / "foo.service")]


def test_find_writable_unit_files_flags_writable_file(tmp_path, monkeypatch):
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    unit_file = unit_dir / "writable.service"
    unit_file.write_text("[Unit]\n")
    unit_file.chmod(0o666)

    monkeypatch.setattr(services, "UNIT_DIRS", [str(unit_dir)])
    writable = services.find_writable_unit_files()
    assert writable == [str(unit_file)]


def test_find_writable_unit_files_ignores_masked_units(tmp_path, monkeypatch):
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    masked = unit_dir / "masked.service"
    masked.symlink_to("/dev/null")

    monkeypatch.setattr(services, "UNIT_DIRS", [str(unit_dir)])
    assert services.find_writable_unit_files() == []


def test_build_findings_flags_each_writable_unit_as_critical():
    findings = services.build_findings(["/etc/systemd/system/evil.service"])
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].category == "Services"


def test_build_findings_empty_when_nothing_writable():
    assert services.build_findings([]) == []


def test_run_returns_expected_shape():
    result = services.run()
    assert "data" in result
    assert "findings" in result
    assert "units" in result["data"]
    assert "summary" in result["data"]
    assert "writable_unit_files" in result["data"]
    assert isinstance(result["findings"], list)
