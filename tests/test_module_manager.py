"""Tests for core/module_manager.py."""

from core import module_manager


ALL_MODULE_NAMES = (
    "system", "users", "sudo", "suid", "capabilities", "cron",
    "services", "processes", "permissions", "environment",
)


def test_all_modules_are_registered_and_runnable():
    for name in ALL_MODULE_NAMES:
        entry = module_manager.get_module(name)
        assert entry is not None
        assert entry.implemented
        assert callable(entry.run)


def test_unknown_module_returns_none():
    assert module_manager.get_module("does-not-exist") is None


def test_implemented_modules_list_matches_full_registry():
    names = [entry.name for entry in module_manager.implemented_modules()]
    assert names == list(ALL_MODULE_NAMES)


def test_all_modules_returns_full_registry_in_order():
    names = [entry.name for entry in module_manager.all_modules()]
    assert names[0] == "system"
    assert len(names) == len(set(names))  # no duplicates


def test_system_run_returns_expected_shape():
    entry = module_manager.get_module("system")
    result = entry.run()
    assert "data" in result
    assert "findings" in result
    assert isinstance(result["findings"], list)
    assert "system" in result["data"]
    assert "environment" in result["data"]


def test_users_run_returns_expected_shape():
    entry = module_manager.get_module("users")
    result = entry.run()
    assert "data" in result
    assert "findings" in result
    assert isinstance(result["findings"], list)
    assert "current_identity" in result["data"]
    assert "local_users" in result["data"]
    assert "uid_zero_accounts" in result["data"]
