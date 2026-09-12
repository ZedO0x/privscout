"""
Module 10 - Environment.

Analyzes the current user's PATH and library-loading environment
variables for classic hijacking vectors: a writable or relative
directory in PATH (a command run from one can be silently replaced),
and LD_PRELOAD/LD_LIBRARY_PATH, which can inject a shared library into
anything that inherits the environment.
"""

import os

from core.findings import Finding

LIBRARY_ENV_VAR_NAMES = ("LD_PRELOAD", "LD_LIBRARY_PATH")


def get_path_directories():
    """Return the current user's PATH, split into individual entries."""
    path_value = os.environ.get("PATH", "")
    return [entry for entry in path_value.split(":") if entry != ""]


def analyze_path_directories(directories):
    """Classify each PATH entry: relative, missing, writable, or in-home.

    A writable directory under the user's own home directory (e.g.
    ~/.local/bin) is normal and not itself a privilege boundary - it's
    always writable by that same user. It's tracked (in_home=True) but
    not treated as a finding; a writable directory *outside* the home
    directory is the actually interesting, rare case.
    """
    home = os.environ.get("HOME", "")
    analysis = []
    for directory in directories:
        entry = {
            "path": directory, "exists": False, "relative": False,
            "writable": False, "in_home": False,
        }

        if not directory.startswith("/"):
            entry["relative"] = True
        else:
            entry["exists"] = os.path.isdir(directory)
            if entry["exists"]:
                entry["writable"] = os.access(directory, os.W_OK)
            if home and (directory == home or directory.startswith(home.rstrip("/") + "/")):
                entry["in_home"] = True

        analysis.append(entry)
    return analysis


def get_library_env_vars():
    """Return any set LD_PRELOAD / LD_LIBRARY_PATH values."""
    return {
        name: os.environ[name]
        for name in LIBRARY_ENV_VAR_NAMES
        if os.environ.get(name)
    }


def build_findings(path_analysis, library_env_vars):
    """Analyze PATH entries and library env vars, return Finding objects.

    Writable directories under the user's own home are skipped (see
    analyze_path_directories), and each distinct path only produces one
    finding even if PATH lists it more than once.
    """
    findings = []
    seen_paths = set()

    for entry in path_analysis:
        if entry["path"] in seen_paths:
            continue

        if entry["relative"]:
            seen_paths.add(entry["path"])
            findings.append(Finding(
                title=f"Relative directory in PATH: '{entry['path']}'",
                description=(
                    "A relative PATH entry resolves based on the current working "
                    "directory, so it can be tricked into running an attacker-planted "
                    "file instead of the intended command."
                ),
                severity="HIGH",
                category="Environment",
                evidence=[f"PATH entry: {entry['path']}"],
                recommendation="Remove relative entries (including '.') from PATH.",
            ))
        elif entry["writable"] and not entry["in_home"]:
            seen_paths.add(entry["path"])
            findings.append(Finding(
                title=f"Writable directory in PATH: {entry['path']}",
                description=(
                    "This PATH directory can be modified by the current user. If a "
                    "privileged process or another user inherits a PATH containing it, "
                    "planting a file with a common command name can hijack execution."
                ),
                severity="HIGH",
                category="Environment",
                evidence=[f"PATH entry: {entry['path']}"],
                recommendation="Remove write access for this user/group, or drop it from PATH.",
            ))

    for name, value in library_env_vars.items():
        findings.append(Finding(
            title=f"{name} is set",
            description=f"{name} can inject a shared library into any process that inherits this environment.",
            severity="MEDIUM",
            category="Environment",
            evidence=[f"{name}={value}"],
            recommendation="Confirm this is intentional; unset it if not required.",
        ))

    return findings


def collect():
    """Collect Module 10 data: PATH analysis and library-injection env vars."""
    directories = get_path_directories()
    return {
        "path_directories": directories,
        "path_analysis": analyze_path_directories(directories),
        "library_env_vars": get_library_env_vars(),
    }


def run():
    """Module entry point used by the module manager."""
    data = collect()
    findings = build_findings(data["path_analysis"], data["library_env_vars"])
    return {
        "data": data,
        "findings": findings,
    }
