"""
Module 02 - Users & Groups.

Collects the current user's identity and group memberships, plus a
system-wide view of local accounts: every UID 0 (root-equivalent)
account and basic per-account fields (UID/GID, home directory, shell).

Unlike Module 01, this module analyzes what it collects: membership
in a privileged group (sudo, docker, lxd, ...) or an extra account
sharing UID 0 with root produces a structured Finding, not just a
printed line.
"""

import getpass
import grp
import os
import pwd

from core.findings import Finding

# Groups worth flagging when the current user is a member, and the
# severity/reasoning for each. Severity reflects how directly the group
# tends to grant root-equivalent access, not whether membership is
# actually a misconfiguration - it may well be expected.
INTERESTING_GROUPS = {
    "docker": ("HIGH", "Members can control the Docker daemon (runs as root); commonly usable to gain root."),
    "lxd": ("HIGH", "Members can create LXD/LXC containers, commonly usable to gain root."),
    "disk": ("HIGH", "Members have raw access to block devices, bypassing normal file permissions."),
    "sudo": ("MEDIUM", "Members can typically run commands as root via sudo."),
    "wheel": ("MEDIUM", "Members can typically run commands as root via sudo/su on many distributions."),
    "admin": ("MEDIUM", "Administrative group with elevated privileges on some distributions."),
    "adm": ("LOW", "Members can typically read system log files, which may contain sensitive data."),
    "root": ("LOW", "Root's primary group; notable, though it grants no direct extra rights by itself."),
}


def get_current_identity():
    """Return UID/GID/username/groups for the user running PrivScout."""
    info = {}

    try:
        info["uid"] = os.getuid()
    except Exception:
        info["uid"] = "unknown"

    try:
        info["gid"] = os.getgid()
    except Exception:
        info["gid"] = "unknown"

    try:
        info["username"] = getpass.getuser()
    except Exception:
        info["username"] = "unknown"

    info["groups"] = get_current_groups()

    return info


def get_current_groups():
    """Return the sorted group names the current process belongs to."""
    try:
        gids = set(os.getgroups())
    except Exception:
        return []

    try:
        gids.add(os.getgid())
    except Exception:
        pass

    names = []
    for gid in gids:
        try:
            names.append(grp.getgrgid(gid).gr_name)
        except (KeyError, OverflowError):
            names.append(str(gid))
    return sorted(names)


def get_local_users():
    """Return every local account from the system's user database.

    Reads the user database via the pwd module (equivalent to
    /etc/passwd), which requires no special privileges to enumerate.
    """
    try:
        entries = pwd.getpwall()
    except Exception:
        return []

    return [
        {
            "username": entry.pw_name,
            "uid": entry.pw_uid,
            "gid": entry.pw_gid,
            "home_directory": entry.pw_dir,
            "shell": entry.pw_shell,
        }
        for entry in entries
    ]


def get_uid_zero_accounts(local_users):
    """Return every local account that shares UID 0 with root."""
    return [user for user in local_users if user["uid"] == 0]


def build_findings(current_identity, uid_zero_accounts):
    """Analyze collected data and return a list of Finding objects."""
    findings = []

    for group in current_identity.get("groups", []):
        if group in INTERESTING_GROUPS:
            severity, description = INTERESTING_GROUPS[group]
            findings.append(Finding(
                title=f"Member of interesting group: {group}",
                description=description,
                severity=severity,
                category="Users",
                evidence=[f"Current user is a member of '{group}'"],
                recommendation="Confirm this group membership is expected and review what it grants.",
            ))

    for user in uid_zero_accounts:
        if user["username"] == "root":
            continue
        findings.append(Finding(
            title="Additional UID 0 account",
            description=f"Account '{user['username']}' shares UID 0 with root.",
            severity="CRITICAL",
            category="Users",
            evidence=[f"{user['username']}:{user['uid']}:{user['home_directory']}:{user['shell']}"],
            recommendation="Investigate why this account has root-equivalent privileges; remove or lock it if unauthorized.",
        ))

    return findings


def collect():
    """Collect Module 02 data: current identity, local users, UID 0 accounts."""
    current_identity = get_current_identity()
    local_users = get_local_users()
    uid_zero_accounts = get_uid_zero_accounts(local_users)

    return {
        "current_identity": current_identity,
        "local_users": local_users,
        "uid_zero_accounts": uid_zero_accounts,
    }


def run():
    """Module entry point used by the module manager.

    Returns the standard module-manager shape: the module's raw
    collected data plus any findings produced from analyzing it.
    """
    data = collect()
    findings = build_findings(data["current_identity"], data["uid_zero_accounts"])
    return {
        "data": data,
        "findings": findings,
    }
