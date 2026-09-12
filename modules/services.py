"""
Module 07 - Services.

Enumerates systemd services via `systemctl list-units` and checks
whether any unit file is writable by the current user. A systemd
service almost always runs as root; a writable unit file lets the
current user redefine what runs as root on the service's next start
(or the next boot) - a direct privilege escalation path.
"""

import os

from core.executor import run_command
from core.findings import Finding

UNIT_DIRS = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
]

# systemd's convention for masking a unit is symlinking it to /dev/null.
# /dev/null is always world-writable, which would otherwise make every
# masked (i.e. deliberately disabled) unit look like a writable-unit finding.
MASKED_UNIT_TARGET = "/dev/null"


def list_services():
    """Run `systemctl list-units` for services and return the raw result."""
    return run_command(
        ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"],
        timeout=15,
    )


def parse_service_units(stdout):
    """Parse `systemctl list-units` output into a list of unit dicts."""
    units = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue

        unit, load, active, sub = parts[:4]
        description = parts[4] if len(parts) > 4 else ""
        units.append({
            "unit": unit, "load": load, "active": active,
            "sub": sub, "description": description,
        })
    return units


def find_unit_files():
    """Return every *.service unit file path under UNIT_DIRS."""
    paths = []
    for directory in UNIT_DIRS:
        try:
            walker = os.walk(directory)
        except OSError:
            continue

        for root, _dirs, files in walker:
            for filename in files:
                if filename.endswith(".service"):
                    paths.append(os.path.join(root, filename))
    return paths


def find_writable_unit_files():
    """Return unit file paths writable by the current user.

    Masked units (symlinked to /dev/null) are skipped - /dev/null is
    always world-writable, but writing to it is meaningless.
    """
    writable = []
    for path in find_unit_files():
        if os.path.realpath(path) == MASKED_UNIT_TARGET:
            continue
        if os.access(path, os.W_OK):
            writable.append(path)
    return writable


def summarize(units):
    """Return counts of total/running/failed services."""
    summary = {"total": len(units), "running": 0, "failed": 0}
    for unit in units:
        if unit["sub"] == "running":
            summary["running"] += 1
        if unit["sub"] == "failed" or unit["active"] == "failed":
            summary["failed"] += 1
    return summary


def build_findings(writable_units):
    """Analyze writable unit files and return Finding objects."""
    findings = []
    for path in writable_units:
        findings.append(Finding(
            title=f"Writable systemd unit file: {path}",
            description=(
                "This unit file can be modified by the current user. Services normally "
                "run as root, so editing it can redefine what runs as root on the "
                "service's next start or the next boot."
            ),
            severity="CRITICAL",
            category="Services",
            evidence=[path],
            recommendation="Remove write access for this user/group, or investigate why it's writable.",
        ))
    return findings


def collect():
    """Collect Module 07 data: enumerated services and unit file writability."""
    result = list_services()
    units = parse_service_units(result["stdout"]) if result["stdout"] else []
    writable_units = find_writable_unit_files()

    return {
        "available": result["error"] is None,
        "error": result["error"],
        "units": units,
        "summary": summarize(units),
        "writable_unit_files": writable_units,
    }


def run():
    """Module entry point used by the module manager."""
    data = collect()
    findings = build_findings(data["writable_unit_files"])
    return {
        "data": data,
        "findings": findings,
    }
