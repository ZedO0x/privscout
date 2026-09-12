"""
Module 05 - Linux Capabilities.

Runs `getcap -r` over the common binary/library directories (not a
full filesystem scan - that takes tens of seconds even on a modest
system, see modules/suid.py for the same trade-off) and parses which
files carry which capability sets, then flags the ones that grant
meaningful privilege escalation potential (cap_setuid, cap_sys_admin,
cap_dac_override, ...) rather than just listing every capability found.
"""

import re

from core.executor import run_command
from core.findings import Finding
from core.scoring import SEVERITY_LEVELS

SEARCH_DIRS = [
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin", "/opt", "/usr/lib",
]

CAP_NAME_PATTERN = re.compile(r"cap_[a-z_]+")

# Capabilities worth flagging, and how severe granting them is.
DANGEROUS_CAPS = {
    "cap_setuid": "CRITICAL",
    "cap_setgid": "CRITICAL",
    "cap_sys_admin": "CRITICAL",
    "cap_sys_module": "CRITICAL",
    "cap_dac_override": "HIGH",
    "cap_dac_read_search": "HIGH",
    "cap_sys_ptrace": "HIGH",
    "cap_sys_rawio": "HIGH",
    "cap_chown": "MEDIUM",
    "cap_fowner": "MEDIUM",
    "cap_net_admin": "LOW",
    "cap_net_raw": "LOW",
}


def check_capabilities():
    """Run `getcap -r` over SEARCH_DIRS and return the raw result."""
    return run_command(["getcap", "-r"] + SEARCH_DIRS, timeout=20)


def parse_getcap_output(stdout):
    """Parse `getcap -r` output into a list of {path, capabilities, raw}."""
    entries = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue

        parts = line.split(None, 1)
        if len(parts) != 2:
            continue

        path, cap_spec = parts
        caps = sorted(set(CAP_NAME_PATTERN.findall(cap_spec.lower())))
        if not caps:
            continue

        entries.append({"path": path, "capabilities": caps, "raw": cap_spec})
    return entries


def classify_entry(entry):
    """Return (severity, matched_dangerous_caps) for one parsed entry."""
    matched = [cap for cap in entry["capabilities"] if cap in DANGEROUS_CAPS]
    if not matched:
        return "INFO", []

    worst = max(matched, key=lambda cap: SEVERITY_LEVELS.index(DANGEROUS_CAPS[cap]))
    return DANGEROUS_CAPS[worst], matched


def build_findings(entries):
    """Analyze parsed capability entries and return Finding objects."""
    findings = []
    for entry in entries:
        severity, matched = classify_entry(entry)
        if not matched:
            continue

        findings.append(Finding(
            title=f"File capabilities set on {entry['path']}",
            description=f"Capabilities granted: {', '.join(matched)}.",
            severity=severity,
            category="Capabilities",
            evidence=[f"{entry['path']} {entry['raw']}"],
            recommendation="Confirm this capability is required; remove it if not intentional.",
        ))
    return findings


def collect():
    """Collect Module 05 data: parsed file capability entries."""
    result = check_capabilities()
    entries = parse_getcap_output(result["stdout"]) if result["stdout"] else []

    return {
        "available": result["error"] is None,
        "error": result["error"],
        "entries": entries,
        "search_dirs": SEARCH_DIRS,
    }


def run():
    """Module entry point used by the module manager."""
    data = collect()
    findings = build_findings(data["entries"])
    return {
        "data": data,
        "findings": findings,
    }
