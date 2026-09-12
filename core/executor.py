"""
Centralized command execution.

Enumeration modules that need information not available through the
Python standard library (sudo rules, file capabilities, systemd unit
state, ...) run external commands through this module instead of
calling subprocess directly, so execution stays centralized,
consistent, and auditable in one place.

Every command PrivScout runs here is a fixed, read-only enumeration
command baked into a module - never user-supplied input, never passed
through a shell, and never anything that changes system state.
"""

import subprocess

DEFAULT_TIMEOUT = 10  # seconds


def run_command(args, timeout=DEFAULT_TIMEOUT):
    """Run a read-only enumeration command and capture its output.

    `args` must be a list of strings (e.g. ["sudo", "-l", "-n"]), never
    a shell string - there is no shell involved, so there is no shell
    interpretation or injection risk.

    Never raises: a missing binary, a timeout, or a non-zero exit are
    all reported in the returned dict instead of propagating, so one
    module's failed command can never crash the tool.

    Returns:
        {
            "success": bool,           # True only on a zero exit code
            "stdout": str,
            "stderr": str,
            "returncode": int | None,
            "error": str | None,       # set when the command couldn't run at all
        }
    """
    if isinstance(args, str):
        raise TypeError("run_command requires a list of arguments, not a string")

    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "success": completed.returncode == 0,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "returncode": completed.returncode,
            "error": None,
        }
    except FileNotFoundError:
        return {
            "success": False, "stdout": "", "stderr": "", "returncode": None,
            "error": f"Command not found: {args[0]}",
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False, "stdout": "", "stderr": "", "returncode": None,
            "error": f"Command timed out after {timeout}s: {' '.join(args)}",
        }
    except Exception as exc:
        return {
            "success": False, "stdout": "", "stderr": "", "returncode": None,
            "error": str(exc),
        }
