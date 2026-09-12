"""
Module manager.

A single registry the CLI uses to look up and run enumeration modules
by name, instead of privscout.py importing and wiring up each module
by hand. Every module in the architecture is registered here, even
ones not implemented yet — an unimplemented entry simply has no
`run` callable, so the CLI can report "planned" instead of crashing
on an unrecognized name.

Each implemented module exposes a `run()` function returning:
    {"data": <module-specific dict>, "findings": [Finding, ...]}
"""

from dataclasses import dataclass
from typing import Callable, Optional

from modules import capabilities, cron, environment, permissions, processes, services, sudo, suid, system, users


@dataclass
class ModuleEntry:
    """One registered module: its name, description, and entry point."""

    name: str
    description: str
    run: Optional[Callable[[], dict]] = None
    display_name: Optional[str] = None

    def __post_init__(self):
        if self.display_name is None:
            self.display_name = self.name.capitalize()

    @property
    def implemented(self):
        return self.run is not None


# Order here defines the default run order (e.g. for --all).
REGISTRY = [
    ModuleEntry("system", "System information", system.run),
    ModuleEntry("users", "Users, groups, and account information", users.run),
    ModuleEntry("sudo", "Sudo configuration analysis", sudo.run),
    ModuleEntry("suid", "SUID/SGID binary analysis", suid.run, display_name="SUID/SGID"),
    ModuleEntry("capabilities", "Linux file capabilities analysis", capabilities.run),
    ModuleEntry("cron", "Cron and scheduled-task enumeration", cron.run),
    ModuleEntry("services", "Service enumeration", services.run),
    ModuleEntry("processes", "Process enumeration", processes.run),
    ModuleEntry("permissions", "File/directory permission analysis", permissions.run),
    ModuleEntry("environment", "PATH/environment security checks", environment.run),
]

_BY_NAME = {entry.name: entry for entry in REGISTRY}


def get_module(name):
    """Return the ModuleEntry registered under `name`, or None if unknown."""
    return _BY_NAME.get(name)


def all_modules():
    """Return every registered module entry, implemented or planned."""
    return list(REGISTRY)


def implemented_modules():
    """Return only the module entries that currently have a run()."""
    return [entry for entry in REGISTRY if entry.implemented]
