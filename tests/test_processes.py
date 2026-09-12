"""Tests for modules/processes.py (Module 08 - Processes)."""

import os

from modules import processes


def test_read_process_info_reads_real_current_process():
    # Using the real /proc/self entry (via our own PID) is more robust than
    # mocking /proc's file layout, and exercises the actual parsing logic.
    info = processes.read_process_info(str(os.getpid()))
    assert info is not None
    assert info["uid"] == os.getuid()
    assert info["exe"] == os.readlink("/proc/self/exe")


def test_read_process_info_returns_none_for_nonexistent_pid():
    assert processes.read_process_info("999999999") is None


def test_summarize_counts_by_owner(monkeypatch):
    monkeypatch.setattr(processes.os, "getuid", lambda: 1000)
    procs = [
        {"pid": "1", "name": "init", "uid": 0, "exe": None},
        {"pid": "2", "name": "bash", "uid": 1000, "exe": None},
        {"pid": "3", "name": "sshd", "uid": 0, "exe": None},
        {"pid": "4", "name": "other", "uid": 1001, "exe": None},
    ]
    summary = processes.summarize(procs)
    assert summary == {"total": 4, "root_owned": 2, "own": 1, "other": 1}


def test_find_writable_root_executables_flags_writable_binary(tmp_path):
    binary = tmp_path / "evil"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o777)

    procs = [{"pid": "1", "name": "evil", "uid": 0, "exe": str(binary)}]
    writable = processes.find_writable_root_executables(procs)
    assert writable == [str(binary)]


def test_find_writable_root_executables_ignores_non_root_processes(tmp_path):
    binary = tmp_path / "evil"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o777)

    procs = [{"pid": "1", "name": "evil", "uid": 1000, "exe": str(binary)}]
    assert processes.find_writable_root_executables(procs) == []


def test_find_writable_root_executables_ignores_missing_exe():
    procs = [{"pid": "1", "name": "gone", "uid": 0, "exe": "/nonexistent/path"}]
    assert processes.find_writable_root_executables(procs) == []


def test_find_writable_root_executables_deduplicates_shared_binary(tmp_path):
    binary = tmp_path / "bash"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o777)

    procs = [
        {"pid": "1", "name": "bash", "uid": 0, "exe": str(binary)},
        {"pid": "2", "name": "bash", "uid": 0, "exe": str(binary)},
    ]
    assert processes.find_writable_root_executables(procs) == [str(binary)]


def test_build_findings_flags_each_writable_executable_as_critical():
    findings = processes.build_findings(["/opt/evil"])
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].category == "Processes"


def test_build_findings_empty_when_nothing_writable():
    assert processes.build_findings([]) == []


def test_run_returns_expected_shape():
    result = processes.run()
    assert "data" in result
    assert "findings" in result
    assert "processes" in result["data"]
    assert "summary" in result["data"]
    assert "writable_root_executables" in result["data"]
    assert result["data"]["summary"]["total"] > 0
