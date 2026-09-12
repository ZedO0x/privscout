"""
Module 06 - Cron.

Enumerates the current user's crontab and the system-wide cron
configuration (/etc/crontab, /etc/cron.d/*, and the run-parts
directories cron.hourly/daily/weekly/monthly), then checks whether any
job's target script - or the cron definition file itself - is
writable by the current user.

A cron job that runs as root but points at a file the current user
can modify is a direct privilege escalation path: whatever gets
written there runs as root on the job's next tick.
"""

import os
import re

from core.executor import run_command
from core.findings import Finding

SYSTEM_CRONTAB = "/etc/crontab"
CRON_D_DIR = "/etc/cron.d"
RUN_PARTS_DIRS = {
    "cron.hourly": "/etc/cron.hourly",
    "cron.daily": "/etc/cron.daily",
    "cron.weekly": "/etc/cron.weekly",
    "cron.monthly": "/etc/cron.monthly",
}

# minute hour dom month dow user command   OR   @special user command
SYSTEM_CRON_LINE = re.compile(
    r"^\s*(?P<schedule>@\w+|(?:\S+\s+){4}\S+)\s+(?P<user>\S+)\s+(?P<command>.+)$"
)
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
PATH_TOKEN_PATTERN = re.compile(r"(/[^\s;&|]+)")
REDIRECT_TARGET_PATTERN = re.compile(r"[0-9]?>>?\s*(/[^\s;&|]+)")

# Always-world-writable pseudo-files that are never a meaningful privesc
# target - writing to them has no effect on what cron later executes.
IGNORED_TARGET_PATHS = {
    "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/full",
    "/dev/tty", "/dev/stdin", "/dev/stdout", "/dev/stderr",
}


def get_user_crontab():
    """Return the current user's crontab jobs, via `crontab -l`."""
    result = run_command(["crontab", "-l"])
    if not result["success"]:
        return []
    return parse_user_crontab(result["stdout"])


def parse_user_crontab(stdout):
    """Parse `crontab -l` output (5 schedule fields + command, no user field)."""
    jobs = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        jobs.append({
            "source": "user crontab",
            "source_file": None,
            "user": "current user",
            "schedule": " ".join(parts[:5]),
            "command": parts[5],
        })
    return jobs


def parse_system_crontab_file(path):
    """Parse a system-style crontab file (/etc/crontab or /etc/cron.d/*)."""
    jobs = []
    try:
        with open(path, "r") as handle:
            lines = handle.readlines()
    except OSError:
        return jobs

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or ENV_ASSIGNMENT.match(line):
            continue
        match = SYSTEM_CRON_LINE.match(line)
        if not match:
            continue
        jobs.append({
            "source": path,
            "source_file": path,
            "user": match.group("user"),
            "schedule": match.group("schedule"),
            "command": match.group("command").strip(),
        })
    return jobs


def get_cron_d_jobs():
    """Return every job defined under /etc/cron.d/."""
    jobs = []
    try:
        filenames = sorted(os.listdir(CRON_D_DIR))
    except OSError:
        return jobs

    for filename in filenames:
        if filename.startswith("."):
            continue
        path = os.path.join(CRON_D_DIR, filename)
        if os.path.isfile(path):
            jobs.extend(parse_system_crontab_file(path))
    return jobs


def get_run_parts_jobs():
    """Return one job per script under cron.hourly/daily/weekly/monthly."""
    jobs = []
    for label, directory in RUN_PARTS_DIRS.items():
        try:
            filenames = sorted(os.listdir(directory))
        except OSError:
            continue

        for filename in filenames:
            path = os.path.join(directory, filename)
            if not os.path.isfile(path):
                continue
            jobs.append({
                "source": f"{label}/{filename}",
                "source_file": path,
                "user": "root",
                "schedule": label,
                "command": path,
            })
    return jobs


def extract_candidate_paths(command):
    """Return absolute-path-looking tokens that are actual job targets.

    Excludes shell redirect destinations (e.g. the "/dev/null" in
    `> /dev/null`) and well-known harmless pseudo-files, since those are
    never a meaningful privilege-escalation target even when writable.
    """
    redirect_targets = set(REDIRECT_TARGET_PATTERN.findall(command))
    candidates = []
    for token in PATH_TOKEN_PATTERN.findall(command):
        if token in redirect_targets or token in IGNORED_TARGET_PATHS:
            continue
        if os.path.exists(token):
            candidates.append(token)
    return candidates


def find_writable_targets(jobs):
    """Return (job, path, kind) for every writable cron file or job target.

    kind is "cron_definition" (the schedule file itself) or
    "script_target" (a script/binary path referenced in the command).
    """
    writable = []
    for job in jobs:
        if job["source_file"] and os.access(job["source_file"], os.W_OK):
            writable.append((job, job["source_file"], "cron_definition"))

        for path in extract_candidate_paths(job["command"]):
            if os.access(path, os.W_OK):
                writable.append((job, path, "script_target"))
    return writable


def build_findings(writable_targets):
    """Analyze writable cron targets and return Finding objects."""
    findings = []
    seen = set()

    for job, path, kind in writable_targets:
        key = (job["source"], path, kind)
        if key in seen:
            continue
        seen.add(key)

        if kind == "cron_definition":
            title = f"Cron definition file is writable: {path}"
            description = (
                f"The cron definition '{path}' runs as {job['user']} and can be modified "
                "by the current user."
            )
        else:
            title = f"Cron job target is writable: {path}"
            description = (
                f"A cron job from {job['source']} (runs as {job['user']}) executes '{path}', "
                "which the current user can modify."
            )

        findings.append(Finding(
            title=title,
            description=description,
            severity="CRITICAL",
            category="Cron",
            evidence=[f"{job['source']} ({job['schedule']}): {job['command']}"],
            recommendation="Remove write access for this user/group, or fix the cron job's target.",
        ))
    return findings


def collect():
    """Collect Module 06 data: every cron job PrivScout could enumerate."""
    jobs = []
    jobs.extend(get_user_crontab())
    jobs.extend(parse_system_crontab_file(SYSTEM_CRONTAB))
    jobs.extend(get_cron_d_jobs())
    jobs.extend(get_run_parts_jobs())

    return {"jobs": jobs}


def run():
    """Module entry point used by the module manager."""
    data = collect()
    writable_targets = find_writable_targets(data["jobs"])
    findings = build_findings(writable_targets)
    data["writable_target_count"] = len({(j["source"], p, k) for j, p, k in writable_targets})

    return {
        "data": data,
        "findings": findings,
    }
