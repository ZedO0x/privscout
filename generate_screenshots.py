"""
One-off script to generate documentation screenshots under screenshots/.

Not part of the PrivScout package - run manually when the CLI's look
changes and the README screenshots need refreshing. Uses Rich's own
SVG export (a real terminal-window-styled render of what was actually
printed), so these are genuine tool output, not mockups.
"""

import sys
from contextlib import contextmanager

sys.path.insert(0, ".")

from rich.console import Console

import privscout


@contextmanager
def _no_spinner(*args, **kwargs):
    # Rich's Live-updating console.status() doesn't export cleanly when
    # recorded (the exported SVG can reference a clip-path that was never
    # defined, e.g. for the line the spinner last redrew). A screenshot is
    # static anyway, so skip the animation and just print the final line.
    yield


def capture(width, callback, title):
    privscout.console = Console(record=True, width=width, highlight=False)
    privscout.console.status = _no_spinner
    callback()
    return privscout.console.export_svg(title=title, theme=None)


def shot_banner_and_system():
    privscout.print_banner()
    privscout.run_module("system")


def shot_users_findings():
    privscout.run_module("users")


def shot_suid_findings():
    privscout.run_module("suid")


def shot_sudo_module():
    privscout.run_module("sudo")


shots = [
    ("screenshots/01_banner_system.svg", 100, shot_banner_and_system, "privscout — system"),
    ("screenshots/02_users_findings.svg", 100, shot_users_findings, "privscout --users"),
    ("screenshots/03_suid_findings.svg", 100, shot_suid_findings, "privscout --suid"),
    ("screenshots/04_sudo_module.svg", 100, shot_sudo_module, "privscout --sudo"),
]

for path, width, callback, title in shots:
    svg = capture(width, callback, title)
    with open(path, "w") as handle:
        handle.write(svg)
    print(f"wrote {path}")
