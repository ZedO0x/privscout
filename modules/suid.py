"""
Module 04 - SUID/SGID.

Walks the common system binary directories for files with the SUID or
SGID bit set, then classifies each one instead of just listing them:

    standard    - a known baseline binary in a normal package-managed
                  directory (passwd, sudo, mount, ...)
    interesting - an unrecognized binary in an otherwise normal
                  directory - worth a closer look
    custom      - a SUID/SGID binary outside the normal package
                  directories entirely (/opt, /usr/local/*, ...)

Binaries matching a well-known GTFOBins SUID privilege-escalation
technique (a SUID copy of find/python/vim/etc.) are flagged regardless
of classification, since that combination is almost always directly
exploitable.

Scope is intentionally limited to common binary directories rather
than a full filesystem walk, to keep the check fast and avoid
permission-denied noise from scanning unrelated mount points.
"""

import os
import stat

from core.findings import Finding

SEARCH_DIRS = [
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin", "/opt",
]

# Directories where a recognized baseline binary is expected to live.
# A SUID/SGID file outside these is treated as "custom" regardless of name.
STANDARD_LOCATION_DIRS = {"/bin", "/sbin", "/usr/bin", "/usr/sbin"}

# Common, expected SUID/SGID binaries on a typical Debian/Kali system.
STANDARD_SUID_BASENAMES = {
    "sudo", "sudoedit", "su", "passwd", "chsh", "chfn", "chage", "gpasswd",
    "newgrp", "mount", "umount", "mount.cifs", "mount.nfs", "mount.nfs4",
    "pkexec", "fusermount", "fusermount3", "unix_chkpwd", "expiry",
    "dotlockfile", "crontab", "pppd", "ssh-agent", "plocate", "ntfs-3g",
    "Xorg", "sg", "wall", "write", "ping", "ping6", "traceroute6.iputils",
}

# General-purpose binaries with a well-known GTFOBins SUID escalation
# technique. A SUID/SGID copy of any of these is a direct root path.
SUID_GTFOBINS = {
    "find", "vim", "vi", "nano", "less", "more", "awk", "perl", "python",
    "python3", "ruby", "tar", "zip", "gdb", "env", "make", "node",
    "openssl", "git", "cp", "nmap", "docker",
}


def find_suid_binaries():
    """Scan SEARCH_DIRS for regular files with the SUID or SGID bit set.

    Symlinked directories (e.g. /bin -> /usr/bin, common on modern
    Debian/Kali) are de-duplicated by resolved real path so the same
    binary isn't reported twice.
    """
    found = []
    for directory in SEARCH_DIRS:
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue

        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue

            if not stat.S_ISREG(st.st_mode):
                continue

            is_suid = bool(st.st_mode & stat.S_ISUID)
            is_sgid = bool(st.st_mode & stat.S_ISGID)
            if not (is_suid or is_sgid):
                continue

            found.append({
                "path": entry.path,
                "suid": is_suid,
                "sgid": is_sgid,
                "owner_uid": st.st_uid,
            })

    seen_real_paths = set()
    unique = []
    for item in found:
        real_path = os.path.realpath(item["path"])
        if real_path in seen_real_paths:
            continue
        seen_real_paths.add(real_path)
        unique.append(item)

    return unique


def classify_binary(path):
    """Return 'standard', 'interesting', or 'custom' for one SUID/SGID path."""
    directory = os.path.dirname(path)
    basename = os.path.basename(path)

    if directory not in STANDARD_LOCATION_DIRS:
        return "custom"
    if basename in STANDARD_SUID_BASENAMES:
        return "standard"
    return "interesting"


def summarize(binaries):
    """Return counts of binaries per classification."""
    counts = {"standard": 0, "interesting": 0, "custom": 0}
    for binary in binaries:
        counts[binary["classification"]] = counts.get(binary["classification"], 0) + 1
    return counts


def build_findings(binaries):
    """Analyze classified binaries and return a list of Finding objects."""
    findings = []

    for binary in binaries:
        path = binary["path"]
        basename = os.path.basename(path)
        bit = "SUID" if binary["suid"] else "SGID"

        if basename in SUID_GTFOBINS:
            findings.append(Finding(
                title=f"{bit} binary with known privesc technique: {basename}",
                description=(
                    f"'{basename}' has a well-known technique (see GTFOBins) for spawning "
                    f"a root shell when it has the {bit} bit set."
                ),
                severity="CRITICAL",
                category="SUID",
                evidence=[path],
                recommendation=f"Remove the {bit} bit unless this is intentional and tightly controlled.",
            ))
            continue

        if binary["classification"] == "custom":
            findings.append(Finding(
                title=f"Custom {bit} binary outside standard directories: {path}",
                description=f"A {bit} binary was found outside the normal package-managed directories.",
                severity="HIGH",
                category="SUID",
                evidence=[path],
                recommendation="Investigate the binary's origin and whether the {} bit is required.".format(bit),
            ))
        elif binary["classification"] == "interesting":
            findings.append(Finding(
                title=f"Unrecognized {bit} binary: {path}",
                description=f"A {bit} binary not on PrivScout's baseline list was found in a standard directory.",
                severity="MEDIUM",
                category="SUID",
                evidence=[path],
                recommendation="Confirm this binary is expected and legitimately requires the {} bit.".format(bit),
            ))

    return findings


def collect():
    """Collect Module 04 data: every SUID/SGID binary found, classified."""
    binaries = find_suid_binaries()
    for binary in binaries:
        binary["classification"] = classify_binary(binary["path"])

    return {
        "binaries": binaries,
        "summary": summarize(binaries),
        "search_dirs": SEARCH_DIRS,
    }


def run():
    """Module entry point used by the module manager."""
    data = collect()
    findings = build_findings(data["binaries"])
    return {
        "data": data,
        "findings": findings,
    }
