"""Tests for core/executor.py (centralized command execution)."""

import pytest

from core import executor


def test_run_command_success():
    result = executor.run_command(["echo", "hello"])
    assert result["success"] is True
    assert result["stdout"].strip() == "hello"
    assert result["returncode"] == 0
    assert result["error"] is None


def test_run_command_nonzero_exit():
    result = executor.run_command(["false"])
    assert result["success"] is False
    assert result["returncode"] != 0
    assert result["error"] is None


def test_run_command_missing_binary():
    result = executor.run_command(["this-binary-does-not-exist-xyz"])
    assert result["success"] is False
    assert result["returncode"] is None
    assert "not found" in result["error"]


def test_run_command_timeout():
    result = executor.run_command(["sleep", "5"], timeout=0.1)
    assert result["success"] is False
    assert result["returncode"] is None
    assert "timed out" in result["error"]


def test_run_command_rejects_string_args():
    with pytest.raises(TypeError):
        executor.run_command("echo hello")
