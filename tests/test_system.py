"""Tests for modules/system.py (Module 01 - System Information)."""

from modules import system


def test_get_os_info_keys():
    info = system.get_os_info()
    for key in ("operating_system", "kernel", "architecture", "hostname"):
        assert key in info
        assert info[key] != ""


def test_get_process_info_keys():
    info = system.get_process_info()
    for key in ("os_name", "working_directory", "process_id", "parent_process_id", "current_user"):
        assert key in info


def test_get_process_info_pid_is_current_process():
    import os as os_module
    info = system.get_process_info()
    assert info["process_id"] == os_module.getpid()


def test_get_current_user_never_raises():
    # Should always return a non-empty string, even if os.getlogin() fails.
    user = system.get_current_user()
    assert isinstance(user, str)
    assert user != ""


def test_get_safe_environment_only_returns_allowed_keys():
    env = system.get_safe_environment()
    assert set(env.keys()) == set(system.SAFE_ENV_VARS)


def test_get_safe_environment_does_not_leak_full_environ(monkeypatch):
    monkeypatch.setenv("PRIVSCOUT_TEST_SECRET", "should-not-appear")
    env = system.get_safe_environment()
    assert "PRIVSCOUT_TEST_SECRET" not in env


def test_collect_returns_expected_top_level_structure():
    data = system.collect()
    assert "system" in data
    assert "environment" in data
    assert isinstance(data["system"], dict)
    assert isinstance(data["environment"], dict)
