#!/usr/bin/env python3
"""
PrivScout - Modular Linux privilege-escalation enumeration tool.

For authorized penetration testing, CTFs, and security labs only.
"""

import argparse
import time

from rich.console import Console

from core import module_manager, reporter

console = Console(highlight=False)

BANNER = r"""
╔══════════════════════════════════════════╗
║                PRIVSCOUT                  ║
║   Linux Privilege Escalation Enumerator   ║
╚══════════════════════════════════════════╝
"""


FALLBACK_VALUES = {"unknown", "unset"}

STEP_DELAY = 0.15

LABEL_WIDTH = 18


SYSTEM_STEPS = [
    ("Detecting OS name...", "OS Name", "os_name"),
    ("Detecting operating system...", "Operating System", "operating_system"),
    ("Detecting kernel...", "Kernel", "kernel"),
    ("Detecting architecture...", "Architecture", "architecture"),
    ("Detecting hostname...", "Hostname", "hostname"),
    ("Detecting current user...", "Current User", "current_user"),
    ("Detecting working directory...", "Working Directory", "working_directory"),
    ("Getting process ID...", "Process ID", "process_id"),
    ("Getting parent process ID...", "Parent PID", "parent_process_id"),
]


ENV_STEPS = [
    ("Reading USER...", "USER"),
    ("Reading HOME...", "HOME"),
    ("Reading SHELL...", "SHELL"),
    ("Reading PWD...", "PWD"),
    ("Reading PATH...", "PATH"),
]


SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}

STATUS_LABELS = {
    "no_rules": "sudo -l succeeded but returned no rules",
    "password_required": "cannot determine - a password is required",
    "not_permitted": "current user is not permitted to run sudo",
    "unknown": "could not determine sudo status",
    "error": "check failed",
}


def build_arg_parser():
    """Build the CLI argument parser, with one flag per registered module."""
    parser = argparse.ArgumentParser(
        prog="privscout",
        description="PrivScout - modular Linux privilege escalation enumeration tool.",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run all implemented modules (default if no flags are given)",
    )
    parser.add_argument(
        "--module", action="append", dest="modules", metavar="NAME",
        help="Run a specific module by name, e.g. --module system (repeatable)",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Save TXT/JSON/HTML reports under reports/ after the run",
    )
    parser.add_argument(
        "--output-dir", default=reporter.REPORTS_DIR, metavar="DIR",
        help=f"Directory to save reports into with --report (default: {reporter.REPORTS_DIR})",
    )
    for entry in module_manager.all_modules():
        parser.add_argument(f"--{entry.name}", action="store_true", help=entry.description)
    return parser


def resolve_selected_modules(args):
    """Turn parsed CLI args into an ordered, de-duplicated list of module names."""
    if args.all:
        selected = [entry.name for entry in module_manager.all_modules()]
    else:
        selected = list(args.modules or [])
        for entry in module_manager.all_modules():
            if getattr(args, entry.name, False):
                selected.append(entry.name)

    if not selected:
        # No flags at all: run whatever is actually implemented, rather
        # than spamming "planned" notices for the rest of the registry.
        selected = [entry.name for entry in module_manager.implemented_modules()]

    seen = set()
    ordered = []
    for name in selected:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def print_banner():
    """Print the PrivScout banner."""
    console.print(BANNER, style="bold cyan")


def print_section_header(title):
    """Print a colored section header, e.g. '[*] System Information'."""
    console.print(f"\n[bold cyan][*] {title}[/bold cyan]\n")


def run_step(spinner_text, label, value):
    """Show a spinner while 'running' one check, then print its result.

    Values PrivScout could not determine (the "unknown"/"unset" fallbacks
    from modules/system.py) are shown as warnings rather than successes,
    so a failed check is visible instead of silently blending in.
    """
    with console.status(f"[cyan]{spinner_text}[/cyan]", spinner="dots"):
        time.sleep(STEP_DELAY)

    padded_label = f"{label:<{LABEL_WIDTH}}"
    if str(value) in FALLBACK_VALUES:
        console.print(
            f"[yellow]⚠[/yellow] [bold]{padded_label}[/bold]: [yellow]{value}[/yellow]",
            soft_wrap=True,
        )
    else:
        console.print(
            f"[green]✓[/green] [bold]{padded_label}[/bold]: [white]{value}[/white]",
            soft_wrap=True,
        )


def print_findings(findings):
    """Print a module's structured findings, colored by severity.

    Shared across every module that produces Finding objects, so the
    same rendering also backs the JSON/HTML reports (see core/reporter.py).
    """
    if not findings:
        return

    print_section_header("Findings")
    for finding in findings:
        style = SEVERITY_STYLES.get(finding.severity, "white")
        console.print(f"[{style}][{finding.severity}][/{style}] {finding.title}", soft_wrap=True)
        console.print(f"    {finding.description}", style="dim", soft_wrap=True)
        for item in finding.evidence:
            console.print(f"    Evidence: {item}", style="dim", soft_wrap=True)
        if finding.recommendation:
            console.print(f"    Recommendation: {finding.recommendation}", style="dim", soft_wrap=True)
        console.print()


def render_system(result):
    """Render Module 01 results one item at a time."""
    data = result.get("data", {})

    print_section_header("System Information")
    system_data = data.get("system", {})
    for spinner_text, label, key in SYSTEM_STEPS:
        run_step(spinner_text, label, system_data.get(key, "unknown"))

    print_section_header("Environment")
    env_data = data.get("environment", {})
    for spinner_text, name in ENV_STEPS:
        run_step(spinner_text, name, env_data.get(name, "unset"))


def render_users(result):
    """Render Module 02 results one item at a time."""
    data = result.get("data", {})
    findings = result.get("findings", [])

    print_section_header("Current Identity")
    identity = data.get("current_identity", {})
    run_step("Detecting current user...", "Username", identity.get("username", "unknown"))
    run_step("Detecting UID...", "UID", identity.get("uid", "unknown"))
    run_step("Detecting GID...", "GID", identity.get("gid", "unknown"))
    groups = identity.get("groups", [])
    run_step("Detecting group memberships...", "Groups", ", ".join(groups) if groups else "unknown")

    print_section_header("Local Accounts")
    local_users = data.get("local_users", [])
    run_step("Enumerating local user accounts...", "Local Users", f"{len(local_users)} accounts found")

    uid_zero_accounts = data.get("uid_zero_accounts", [])
    uid0_names = ", ".join(u["username"] for u in uid_zero_accounts) if uid_zero_accounts else "none found"
    run_step("Checking for UID 0 accounts...", "UID 0 Accounts", uid0_names)

    print_findings(findings)


def render_sudo(result):
    """Render Module 03 results one item at a time."""
    data = result.get("data", {})
    findings = result.get("findings", [])
    status = data.get("status", "unknown")
    rules = data.get("rules", [])

    print_section_header("Sudo Enumeration")
    with console.status("[cyan]Checking sudo availability...[/cyan]", spinner="dots"):
        time.sleep(STEP_DELAY)

    padded_label = f"{'Sudo Access':<{LABEL_WIDTH}}"
    if status == "rules_found":
        console.print(f"[green]✓[/green] [bold]{padded_label}[/bold]: [white]{len(rules)} rule(s) found[/white]")
    else:
        label = STATUS_LABELS.get(status, status)
        message = data.get("message")
        value = f"{label} ({message})" if message else label
        console.print(
            f"[yellow]⚠[/yellow] [bold]{padded_label}[/bold]: [yellow]{value}[/yellow]",
            soft_wrap=True,
        )

    print_findings(findings)


def render_suid(result):
    """Render Module 04 results one item at a time."""
    data = result.get("data", {})
    findings = result.get("findings", [])
    binaries = data.get("binaries", [])
    summary = data.get("summary", {})

    print_section_header("SUID/SGID Enumeration")
    run_step("Scanning common binary directories...", "Binaries Found", f"{len(binaries)} total")
    run_step("Classifying binaries...", "Standard", summary.get("standard", 0))
    run_step("Classifying binaries...", "Interesting", summary.get("interesting", 0))
    run_step("Classifying binaries...", "Custom", summary.get("custom", 0))

    print_findings(findings)


def render_capabilities(result):
    """Render Module 05 results one item at a time."""
    data = result.get("data", {})
    findings = result.get("findings", [])
    entries = data.get("entries", [])

    print_section_header("Capabilities Enumeration")
    with console.status("[cyan]Scanning for file capabilities...[/cyan]", spinner="dots"):
        time.sleep(STEP_DELAY)

    padded_label = f"{'Capabilities Found':<{LABEL_WIDTH}}"
    if data.get("available"):
        console.print(f"[green]✓[/green] [bold]{padded_label}[/bold]: [white]{len(entries)} file(s)[/white]")
    else:
        console.print(
            f"[yellow]⚠[/yellow] [bold]{padded_label}[/bold]: [yellow]{data.get('error') or 'unavailable'}[/yellow]",
            soft_wrap=True,
        )

    print_findings(findings)


def render_cron(result):
    """Render Module 06 results one item at a time."""
    data = result.get("data", {})
    findings = result.get("findings", [])
    jobs = data.get("jobs", [])
    writable_count = data.get("writable_target_count", 0)

    print_section_header("Cron Enumeration")
    run_step("Enumerating cron jobs...", "Cron Jobs", f"{len(jobs)} found")
    run_step("Checking cron targets for write access...", "Writable Targets", f"{writable_count} found")

    print_findings(findings)


def render_services(result):
    """Render Module 07 results one item at a time."""
    data = result.get("data", {})
    findings = result.get("findings", [])
    summary = data.get("summary", {})
    writable = data.get("writable_unit_files", [])

    print_section_header("Service Enumeration")
    run_step("Enumerating systemd services...", "Total Services", summary.get("total", 0))
    run_step("Checking service states...", "Running", summary.get("running", 0))
    run_step("Checking service states...", "Failed", summary.get("failed", 0))
    run_step("Checking unit file permissions...", "Writable Unit Files", len(writable))

    print_findings(findings)


def render_processes(result):
    """Render Module 08 results one item at a time."""
    data = result.get("data", {})
    findings = result.get("findings", [])
    summary = data.get("summary", {})
    writable = data.get("writable_root_executables", [])

    print_section_header("Process Enumeration")
    run_step("Enumerating processes...", "Total Processes", summary.get("total", 0))
    run_step("Checking process owners...", "Root-Owned", summary.get("root_owned", 0))
    run_step("Checking process owners...", "Owned By You", summary.get("own", 0))
    run_step("Checking executable permissions...", "Writable Root Executables", len(writable))

    print_findings(findings)


def render_permissions(result):
    """Render Module 09 results one item at a time."""
    data = result.get("data", {})
    findings = result.get("findings", [])

    print_section_header("Permissions Enumeration")
    run_step("Checking sensitive file access...", "Sensitive File Issues", len(data.get("sensitive_file_issues", [])))
    run_step("Checking sudoers.d fragments...", "Writable sudoers.d Files", len(data.get("writable_sudoers_d", [])))
    run_step("Scanning /etc for world-writable files...", "World-Writable /etc Files", len(data.get("world_writable_etc_files", [])))

    print_findings(findings)


def render_environment(result):
    """Render Module 10 results one item at a time."""
    data = result.get("data", {})
    findings = result.get("findings", [])
    directories = data.get("path_directories", [])
    library_env_vars = data.get("library_env_vars", {})

    print_section_header("Environment Enumeration")
    run_step("Parsing PATH...", "PATH Entries", f"{len(directories)} found")
    run_step("Checking for library-injection variables...", "LD_PRELOAD/LD_LIBRARY_PATH", len(library_env_vars))

    print_findings(findings)


# One rendering function per implemented module, keyed by module name.
RENDERERS = {
    "system": render_system,
    "users": render_users,
    "sudo": render_sudo,
    "suid": render_suid,
    "capabilities": render_capabilities,
    "cron": render_cron,
    "services": render_services,
    "processes": render_processes,
    "permissions": render_permissions,
    "environment": render_environment,
}


def run_module(name):
    """Run one module by name, render its output, and return its result.

    Returns None (after printing a status/error line) if the module is
    unknown, not yet implemented, or raised while running - callers use
    the None to know it contributed nothing reportable.
    """
    entry = module_manager.get_module(name)

    if entry is None:
        console.print(f"[red]✗ Unknown module: {name}[/red]\n")
        return None

    if not entry.implemented:
        console.print(
            f"[yellow][*] Module: {entry.display_name} — planned, not yet implemented[/yellow]\n"
        )
        return None

    console.print(f"[bold cyan][+] Module: {entry.display_name}[/bold cyan]")
    try:
        result = entry.run()
    except Exception as exc:
        console.print(f"[red]✗ Module failed: {exc}[/red]\n")
        return None

    renderer = RENDERERS.get(entry.name)
    if renderer:
        renderer(result)
    return result


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    selected = resolve_selected_modules(args)

    print_banner()
    module_results = {}
    for name in selected:
        result = run_module(name)
        if result is not None:
            module_results[name] = result
    console.print()

    if args.report:
        paths = reporter.save_reports(module_results, output_dir=args.output_dir)
        console.print("[bold cyan][*] Reports saved:[/bold cyan]")
        for fmt, path in paths.items():
            console.print(f"    {fmt.upper():<5}: {path}")
        console.print()


if __name__ == "__main__":
    main()
