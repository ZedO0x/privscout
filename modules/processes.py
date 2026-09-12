"""
Module 08 - Processes.

Enumerates running processes via /proc (Linux-specific) and flags one
well-known privilege escalation signal: a process running as root
whose executable file the current user can write to. If that binary
gets replaced, root runs the new code the next time it's launched.

Per-PID data that isn't readable (another user's process, or one that
exited mid-scan) is skipped rather than treated as an error - that is
normal and expected, not a failure.
"""

import os

from core.findings import Finding


def list_processes():
    """Return one dict per readable process under /proc."""
    processes = []
    try:
        pids = os.listdir("/proc")
    except OSError:
        return processes

    for entry in pids:
        if not entry.isdigit():
            continue
        info = read_process_info(entry)
        if info is not None:
            processes.append(info)
    return processes


def read_process_info(pid):
    """Read name, owner UID, and executable path for one PID.

    Returns None if the process disappeared mid-scan or its info isn't
    readable (typically a process owned by another user).
    """
    try:
        with open(f"/proc/{pid}/status", "r") as handle:
            status_lines = handle.readlines()
    except OSError:
        return None

    name = None
    uid = None
    for line in status_lines:
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Uid:"):
            parts = line.split()
            if len(parts) > 1:
                uid = int(parts[1])  # real UID

    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe_path = None

    return {"pid": pid, "name": name, "uid": uid, "exe": exe_path}


def summarize(processes):
    """Return counts of processes by owner: total, root-owned, own, other."""
    current_uid = os.getuid()
    summary = {"total": len(processes), "root_owned": 0, "own": 0, "other": 0}
    for proc in processes:
        if proc["uid"] == 0:
            summary["root_owned"] += 1
        elif proc["uid"] == current_uid:
            summary["own"] += 1
        else:
            summary["other"] += 1
    return summary


def find_writable_root_executables(processes):
    """Return unique executable paths of root-owned processes that the
    current user can write to."""
    seen = set()
    writable = []
    for proc in processes:
        exe = proc["exe"]
        if proc["uid"] != 0 or not exe or exe in seen:
            continue
        seen.add(exe)
        if os.path.exists(exe) and os.access(exe, os.W_OK):
            writable.append(exe)
    return writable


def build_findings(writable_root_executables):
    """Analyze writable root-owned executables and return Finding objects."""
    findings = []
    for exe in writable_root_executables:
        findings.append(Finding(
            title=f"Writable executable for a root-owned process: {exe}",
            description=(
                "A process currently running as root uses this executable, and the "
                "current user can modify it. Replacing it lets root run arbitrary code "
                "the next time the process (or a new instance) starts."
            ),
            severity="CRITICAL",
            category="Processes",
            evidence=[exe],
            recommendation="Remove write access for this user/group, or investigate why it's writable.",
        ))
    return findings


def collect():
    """Collect Module 08 data: enumerated processes and writable root executables."""
    processes = list_processes()
    writable_root_executables = find_writable_root_executables(processes)

    return {
        "processes": processes,
        "summary": summarize(processes),
        "writable_root_executables": writable_root_executables,
    }


def run():
    """Module entry point used by the module manager."""
    data = collect()
    findings = build_findings(data["writable_root_executables"])
    return {
        "data": data,
        "findings": findings,
    }
