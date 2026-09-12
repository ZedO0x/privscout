"""
Module 03 - Sudo.

Enumerates the current user's sudo configuration via `sudo -l -n` (the
-n flag ensures PrivScout never prompts for or waits on a password)
and parses the rules instead of just dumping the raw text.

Rules are classified by how directly they let the current user gain
a root shell: unrestricted access, a command with a well-known
GTFOBins sudo bypass, or a narrower command worth a closer look.
"""

import os
import re

from core.executor import run_command
from core.findings import Finding

# Commands with a well-documented technique (see gtfobins.github.io) for
# spawning a root shell when allowed to run via sudo.
GTFOBINS_SUDO_COMMANDS = {
    "awk", "cpan", "docker", "ed", "env", "expect", "find", "ftp", "gdb",
    "git", "less", "make", "man", "more", "mysql", "nano", "nmap", "node",
    "openssl", "perl", "pip", "pip3", "python", "python3", "rsync", "ruby",
    "scp", "sqlite3", "ssh", "socat", "systemctl", "tar", "vi", "vim", "zip",
}

# A rule matching one of these commands grants an unrestricted root shell.
FULL_ACCESS_COMMANDS = {"ALL"}

RULE_PATTERN = re.compile(r"^\s*\((?P<runas>[^)]+)\)\s*(?P<tags>(?:[A-Z]+:\s*)*)(?P<command>.+)$")


def check_sudo_available():
    """Run `sudo -l -n` and return its raw result.

    -n makes sudo fail immediately instead of prompting for a password,
    so this check never blocks waiting on interactive input.
    """
    return run_command(["sudo", "-l", "-n"])


def parse_sudo_rules(stdout):
    """Parse the command rules out of `sudo -l` output.

    Only lines shaped like "(run_as) TAG: command" are treated as
    rules; header/Defaults lines are ignored.
    """
    rules = []
    for line in stdout.splitlines():
        match = RULE_PATTERN.match(line)
        if not match:
            continue

        run_as = match.group("runas").strip()
        tags_raw = match.group("tags") or ""
        tags = [tag.strip() for tag in tags_raw.split(":") if tag.strip()]
        command = match.group("command").strip()

        rules.append({"run_as": run_as, "tags": tags, "command": command})
    return rules


def determine_status(result, rules):
    """Classify what the sudo check told us: rules_found, no_rules,
    password_required, not_permitted, or error."""
    if result["error"]:
        return "error"

    if result["success"]:
        return "rules_found" if rules else "no_rules"

    stderr = (result["stderr"] or "").lower()
    if "password is required" in stderr:
        return "password_required"
    if "may not run sudo" in stderr or "is not in the sudoers file" in stderr:
        return "not_permitted"
    return "unknown"


def classify_rule(rule):
    """Return (severity, reason) for one parsed sudo rule."""
    command = rule["command"].strip()
    first_token = command.split()[0] if command.split() else command
    base = os.path.basename(first_token)

    if command in FULL_ACCESS_COMMANDS or base in FULL_ACCESS_COMMANDS:
        return "CRITICAL", "This rule grants unrestricted root access via sudo."

    if base in GTFOBINS_SUDO_COMMANDS:
        return (
            "HIGH",
            f"'{base}' has a well-known technique (see GTFOBins) for spawning a root "
            "shell when run via sudo.",
        )

    return (
        "LOW",
        "A specific command is allowed via sudo; review whether it can be abused "
        "to gain broader access.",
    )


def build_findings(status, rules):
    """Analyze the sudo status/rules and return a list of Finding objects."""
    if status != "rules_found":
        return []

    findings = []
    for rule in rules:
        severity, reason = classify_rule(rule)
        run_as = rule["run_as"]
        command = rule["command"]
        findings.append(Finding(
            title=f"Sudo rule allows: {command}",
            description=reason,
            severity=severity,
            category="Sudo",
            evidence=[f"(run as {run_as}) {', '.join(rule['tags']) + ': ' if rule['tags'] else ''}{command}"],
            recommendation="Investigate the allowed command and its execution context.",
        ))
    return findings


def collect():
    """Collect Module 03 data: sudo availability status and parsed rules."""
    result = check_sudo_available()
    rules = parse_sudo_rules(result["stdout"]) if result["stdout"] else []
    status = determine_status(result, rules)

    return {
        "status": status,
        "rules": rules,
        "raw_output": result["stdout"],
        "message": (result["error"] or result["stderr"] or "").strip(),
    }


def run():
    """Module entry point used by the module manager."""
    data = collect()
    findings = build_findings(data["status"], data["rules"])
    return {
        "data": data,
        "findings": findings,
    }
