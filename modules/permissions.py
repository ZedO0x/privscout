"""
Module 09 - Permissions.

Checks a fixed set of security-sensitive system files for access the
current user shouldn't have (a writable /etc/passwd or sudoers file,
a readable /etc/shadow, ...), plus a scan for world-writable files
directly under /etc - each a distinct, well-known privilege
escalation or information-disclosure vector.
"""

import os
import stat

from core.findings import Finding

ETC_DIR = "/etc"
SUDOERS_D_DIR = "/etc/sudoers.d"

# (path, check, severity, description) - check is "writable" or "readable",
# describing the access that shouldn't be possible for a normal user.
SENSITIVE_FILE_CHECKS = [
    ("/etc/passwd", "writable", "CRITICAL",
     "The user database is writable; an attacker can add a UID 0 account to gain root."),
    ("/etc/shadow", "readable", "HIGH",
     "Password hashes are readable and could potentially be cracked offline."),
    ("/etc/gshadow", "readable", "MEDIUM",
     "Group password hashes are readable."),
    ("/etc/sudoers", "writable", "CRITICAL",
     "The sudoers file is writable; an attacker can grant themselves full sudo access."),
    ("/etc/crontab", "writable", "CRITICAL",
     "The system crontab is writable; an attacker can schedule a command to run as root."),
]


def check_sensitive_files():
    """Check each hardcoded sensitive file for the risky access it shouldn't have."""
    results = []
    for path, check, severity, description in SENSITIVE_FILE_CHECKS:
        if not os.path.exists(path):
            continue

        has_access = os.access(path, os.W_OK) if check == "writable" else os.access(path, os.R_OK)
        if has_access:
            results.append({
                "path": path, "issue": check,
                "severity": severity, "description": description,
            })
    return results


def check_sudoers_d():
    """Return any writable file under /etc/sudoers.d/."""
    writable = []
    try:
        filenames = os.listdir(SUDOERS_D_DIR)
    except OSError:
        return writable

    for filename in filenames:
        path = os.path.join(SUDOERS_D_DIR, filename)
        if os.path.isfile(path) and os.access(path, os.W_OK):
            writable.append(path)
    return writable


def find_world_writable_etc_files():
    """Return world-writable regular files directly under /etc (non-recursive)."""
    found = []
    try:
        entries = list(os.scandir(ETC_DIR))
    except OSError:
        return found

    for entry in entries:
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if st.st_mode & stat.S_IWOTH:
            found.append(entry.path)
    return found


def build_findings(sensitive_results, writable_sudoers_d, world_writable_etc_files):
    """Analyze permission checks and return a list of Finding objects."""
    findings = []

    for result in sensitive_results:
        verb = "writable" if result["issue"] == "writable" else "readable"
        findings.append(Finding(
            title=f"{result['path']} is unexpectedly {verb}",
            description=result["description"],
            severity=result["severity"],
            category="Permissions",
            evidence=[result["path"]],
            recommendation=f"Restrict {verb} access on this file to root only.",
        ))

    for path in writable_sudoers_d:
        findings.append(Finding(
            title=f"Writable sudoers.d file: {path}",
            description="A sudoers.d fragment is writable; an attacker can grant themselves sudo rules.",
            severity="CRITICAL",
            category="Permissions",
            evidence=[path],
            recommendation="Restrict write access on this file to root only.",
        ))

    for path in world_writable_etc_files:
        findings.append(Finding(
            title=f"World-writable file in /etc: {path}",
            description="A configuration file directly under /etc is writable by any user.",
            severity="HIGH",
            category="Permissions",
            evidence=[path],
            recommendation="Remove world-write access; review what reads this file and as which user.",
        ))

    return findings


def collect():
    """Collect Module 09 data: sensitive-file access and world-writable /etc files."""
    sensitive_results = check_sensitive_files()
    writable_sudoers_d = check_sudoers_d()
    world_writable_etc_files = find_world_writable_etc_files()

    return {
        "sensitive_file_issues": sensitive_results,
        "writable_sudoers_d": writable_sudoers_d,
        "world_writable_etc_files": world_writable_etc_files,
    }


def run():
    """Module entry point used by the module manager."""
    data = collect()
    findings = build_findings(
        data["sensitive_file_issues"],
        data["writable_sudoers_d"],
        data["world_writable_etc_files"],
    )
    return {
        "data": data,
        "findings": findings,
    }
