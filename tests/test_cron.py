"""Tests for modules/cron.py (Module 06 - Cron)."""

from modules import cron


def test_parse_user_crontab_extracts_jobs():
    stdout = "# comment\n*/5 * * * * /home/kali/backup.sh\n\n"
    jobs = cron.parse_user_crontab(stdout)
    assert len(jobs) == 1
    assert jobs[0]["schedule"] == "*/5 * * * *"
    assert jobs[0]["command"] == "/home/kali/backup.sh"
    assert jobs[0]["source"] == "user crontab"


def test_parse_system_crontab_file_skips_comments_and_env_vars(tmp_path):
    content = (
        "# a comment\n"
        "SHELL=/bin/sh\n"
        "PATH=/usr/bin:/bin\n"
        "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
    )
    path = tmp_path / "crontab"
    path.write_text(content)

    jobs = cron.parse_system_crontab_file(str(path))
    assert len(jobs) == 1
    assert jobs[0]["user"] == "root"
    assert "run-parts" in jobs[0]["command"]
    assert jobs[0]["source_file"] == str(path)


def test_parse_system_crontab_file_supports_special_schedules(tmp_path):
    path = tmp_path / "crontab"
    path.write_text("@reboot root /usr/local/bin/startup.sh\n")
    jobs = cron.parse_system_crontab_file(str(path))
    assert len(jobs) == 1
    assert jobs[0]["schedule"] == "@reboot"
    assert jobs[0]["command"] == "/usr/local/bin/startup.sh"


def test_parse_system_crontab_file_missing_file_returns_empty(tmp_path):
    assert cron.parse_system_crontab_file(str(tmp_path / "nope")) == []


def test_extract_candidate_paths_only_existing_paths(tmp_path):
    real_file = tmp_path / "script.sh"
    real_file.write_text("#!/bin/sh\n")
    command = f"[ -x {real_file} ] && {real_file} --flag && /nonexistent/path"
    paths = cron.extract_candidate_paths(command)
    assert str(real_file) in paths
    assert "/nonexistent/path" not in paths


def test_extract_candidate_paths_ignores_redirect_targets():
    command = "command -v debian-sa1 > /dev/null && debian-sa1 1 1"
    paths = cron.extract_candidate_paths(command)
    assert "/dev/null" not in paths


def test_extract_candidate_paths_ignores_dev_null_even_without_redirect():
    # Belt-and-suspenders: /dev/null is never a meaningful target regardless of context.
    assert "/dev/null" not in cron.extract_candidate_paths("/dev/null")


def test_find_writable_targets_flags_writable_script(tmp_path):
    script = tmp_path / "writable.sh"
    script.write_text("#!/bin/sh\n")
    script.chmod(0o777)

    job = {
        "source": "cron.daily/writable", "source_file": None, "user": "root",
        "schedule": "cron.daily", "command": str(script),
    }
    writable = cron.find_writable_targets([job])
    assert len(writable) == 1
    assert writable[0][1] == str(script)
    assert writable[0][2] == "script_target"


def test_find_writable_targets_flags_writable_cron_definition(tmp_path):
    definition = tmp_path / "myjob"
    definition.write_text("* * * * * root /bin/true\n")
    definition.chmod(0o666)

    job = {
        "source": str(definition), "source_file": str(definition), "user": "root",
        "schedule": "* * * * *", "command": "/bin/true",
    }
    writable = cron.find_writable_targets([job])
    kinds = {w[2] for w in writable}
    assert "cron_definition" in kinds


def test_build_findings_deduplicates_and_flags_critical(tmp_path):
    script = tmp_path / "writable.sh"
    script.write_text("#!/bin/sh\n")
    job = {
        "source": "cron.daily/writable", "source_file": None, "user": "root",
        "schedule": "cron.daily", "command": str(script),
    }
    writable_targets = [(job, str(script), "script_target"), (job, str(script), "script_target")]
    findings = cron.build_findings(writable_targets)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].category == "Cron"


def test_build_findings_empty_when_nothing_writable():
    assert cron.build_findings([]) == []


def test_run_returns_expected_shape():
    result = cron.run()
    assert "data" in result
    assert "findings" in result
    assert "jobs" in result["data"]
    assert "writable_target_count" in result["data"]
    assert isinstance(result["findings"], list)
