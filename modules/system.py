"""
Module 01 - System Information.

Collects basic, non-sensitive information about the host: operating
system details, kernel/architecture, hostname, current user/session
identifiers, and a small set of safe environment variables.

This module only reads information already exposed by the standard
library. It does not execute external commands, modify system state,
or access anything requiring elevated privileges.
"""

import os
import platform


# Only these environment variables are considered safe/relevant to report.
# We deliberately avoid dumping the full environment, since arbitrary
# variables can carry API keys, tokens, or other secrets.
SAFE_ENV_VARS = ["USER", "HOME", "SHELL", "PWD", "PATH"]


def get_os_info():
    """Return operating system and kernel/architecture details."""
    info = {}
    try:
        info["operating_system"] = platform.system()
    except Exception:
        info["operating_system"] = "unknown"

    try:
        info["kernel"] = platform.release()
    except Exception:
        info["kernel"] = "unknown"

    try:
        info["architecture"] = platform.machine()
    except Exception:
        info["architecture"] = "unknown"

    try:
        info["hostname"] = platform.node()
    except Exception:
        info["hostname"] = "unknown"

    return info


def get_process_info():
    """Return process/session identifiers using the os module."""
    info = {}
    try:
        info["os_name"] = os.name
    except Exception:
        info["os_name"] = "unknown"

    try:
        info["working_directory"] = os.getcwd()
    except Exception:
        info["working_directory"] = "unknown"

    try:
        info["process_id"] = os.getpid()
    except Exception:
        info["process_id"] = "unknown"

    try:
        info["parent_process_id"] = os.getppid()
    except Exception:
        info["parent_process_id"] = "unknown"

    info["current_user"] = get_current_user()

    return info


def get_current_user():
    """Return the current username, falling back safely if unavailable.

    os.getlogin() can fail in SSH sessions, containers, or when there is
    no controlling terminal, so we fall back to environment variables.
    """
    try:
        return os.getlogin()
    except Exception:
        pass

    for var in ("USER", "LOGNAME"):
        value = os.environ.get(var)
        if value:
            return value

    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return "unknown"


def get_safe_environment():
    """Return a curated, safe subset of environment variables.

    Only variables listed in SAFE_ENV_VARS are collected. The full
    environment is intentionally never dumped, since it may contain
    secrets such as API keys, tokens, or passwords.
    """
    return {var: os.environ.get(var, "unset") for var in SAFE_ENV_VARS}


def collect():
    """Run Module 01 and return structured system information.

    Returns a dict with two top-level keys: "system" (OS/process info)
    and "environment" (safe environment variables).
    """
    system_info = {}
    system_info.update(get_os_info())
    system_info.update(get_process_info())

    return {
        "system": system_info,
        "environment": get_safe_environment(),
    }


def run():
    """Module entry point used by the module manager.

    Returns the standard module-manager shape: the module's raw
    collected data plus any findings it produced. System information
    is descriptive rather than security-relevant on its own, so this
    module never produces findings itself.
    """
    return {
        "data": collect(),
        "findings": [],
    }
