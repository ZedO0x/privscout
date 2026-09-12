 # PrivScout

A modular Linux privilege-escalation enumeration and security-assessment tool, designed for authorized penetration testing, CTFs, and security labs.

## Overview

PrivScout collects and structures information relevant to Linux privilege escalation assessments. It is built as a set of independent enumeration modules that feed into a shared finding engine, rather than a single monolithic script. Each module doesn't just dump data — it analyzes what it finds and produces structured, severity-rated findings.

## Features

- **10 enumeration modules**, each analyzing one concern: system info, users/groups, sudo, SUID/SGID, capabilities, cron, services, processes, permissions, and PATH/environment
- **Module manager** (`core/module_manager.py`) — modules are registered once and selected by name, instead of the CLI wiring each one up by hand
- **CLI flags** to run specific modules (`--sudo`, `--suid`, `--module <name>`, `--all`, ...) instead of always running everything
- **Structured findings** (`core/findings.py`): title, description, severity, category, evidence, and recommendation — shared by every module and by the report generator
- **Report generation** (`core/reporter.py`) — `--report` writes `report.txt`, `report.json`, and a self-contained, syntax-safe `report.html` under `reports/`, all built from the same findings the CLI printed
- **Centralized command execution** (`core/executor.py`) — the handful of external commands PrivScout needs (`sudo -l`, `getcap`, `systemctl`, `crontab -l`) all run through one safe, list-args-only, timeout-bounded wrapper
- **Real analysis, not dumps** — e.g. SUID binaries are classified standard/interesting/custom rather than just listed; sudo rules are parsed and checked against known GTFOBins techniques; writable cron/systemd/process targets are flagged as direct root paths
- **Graceful error handling** — a missing binary, a permission error, or an unreadable file never crashes the tool; each module degrades to reporting what it could determine
- **Careful handling of environment variables** — only a fixed, safe allowlist (`USER`, `HOME`, `SHELL`, `PWD`, `PATH`) is ever read; the full environment is never dumped, since it can carry secrets
- **Colored, spinner-driven terminal output** (via [Rich](https://github.com/Textualize/rich)) — findings are colored by severity (INFO through CRITICAL)

## Project Architecture

```text
privscout/
│
├── privscout.py          # CLI entry point
│
├── modules/               # One file per enumeration concern
│   ├── system.py          # Module 01 — OS, kernel, process identity
│   ├── users.py           # Module 02 — identity, groups, UID 0 accounts
│   ├── sudo.py             # Module 03 — parsed `sudo -l` rule analysis
│   ├── suid.py             # Module 04 — SUID/SGID binary classification
│   ├── capabilities.py     # Module 05 — Linux file capabilities (getcap)
│   ├── cron.py             # Module 06 — cron jobs + writable-target checks
│   ├── services.py         # Module 07 — systemd units + unit file writability
│   ├── processes.py        # Module 08 — /proc enumeration, writable root exes
│   ├── permissions.py      # Module 09 — sensitive file/dir permission checks
│   └── environment.py      # Module 10 — PATH hijacking, LD_PRELOAD checks
│
├── core/                   # Shared engine components
│   ├── module_manager.py   # Module registry the CLI runs against
│   ├── findings.py         # Structured finding representation
│   ├── scoring.py          # Severity vocabulary (INFO..CRITICAL)
│   ├── executor.py         # Centralized, safe external command execution
│   └── reporter.py         # TXT/JSON/HTML report generation
│
├── reports/                 # Generated reports land here (--report)
├── tests/                   # Test suite (pytest)
├── screenshots/              # Real CLI output, captured via generate_screenshots.py
├── generate_screenshots.py   # Dev utility: regenerates screenshots/*.svg
├── requirements.txt
├── LICENSE
└── README.md
```

Enumeration flow:

```text
                    PRIVSCOUT
                        │
                        ▼
                CLI / Module Manager
                        │
       ┌────────┬───────┼───────┬────────┬─────────┬──────────┬─────────────┐
       ▼        ▼       ▼       ▼        ▼         ▼          ▼             ▼
    System    Users   Sudo    SUID   Capabilities  Cron    Services    Processes
                                                                             │
                                                              Permissions ◄──┘
                                                                   │
                                                              Environment
                                                                   │
                                                                   ▼
                                                            Finding Engine
                                                                   │
                                                                   ▼
                                                              CLI output
                                                                   │
                                                          --report (optional)
                                                                   │
                                                                   ▼
                                                      reports/report.{txt,json,html}
```

Modules are registered independently in `core/module_manager.py` and can be enabled/disabled per run via CLI flags, without changing the core engine.

## Installation

Requires Python 3.8+ and, for full functionality, a Linux system with `sudo`, `getcap` (libcap2-bin), and `systemctl` available (each module degrades gracefully if its optional binary is missing).

```bash
git clone <repository-url>
cd privscout
pip install -r requirements.txt   # installs rich (CLI output) and pytest (tests)
```

## Usage

```bash
python3 privscout.py                  # runs every implemented module (currently: all 10)
python3 privscout.py --sudo           # run just the sudo module
python3 privscout.py --module suid    # equivalent, name-based form
python3 privscout.py --system --users # run more than one module at once
python3 privscout.py --all            # run every registered module
python3 privscout.py --all --report   # also save reports/report.{txt,json,html}
python3 privscout.py --report --output-dir /tmp/assessment  # save reports elsewhere
python3 privscout.py --help           # list all available module flags
```

## Example Output

Real output from this project's own development machine (a Kali VM) — not staged. See `screenshots/` for the source SVGs, or regenerate them yourself with `python3 generate_screenshots.py`.

## Current Modules

| # | Module | Status | Highlights |
|---|--------|--------|------------|
| 01 | System Information (`system.py`) | Implemented | OS/kernel/arch, process identity, safe env vars |
| 02 | Users & Groups (`users.py`) | Implemented | Privileged group membership, extra UID 0 accounts |
| 03 | Sudo (`sudo.py`) | Implemented | Parses `sudo -l -n`, flags GTFOBins/full-access rules |
| 04 | SUID/SGID (`suid.py`) | Implemented | Classifies standard/interesting/custom binaries |
| 05 | Capabilities (`capabilities.py`) | Implemented | Parses `getcap -r`, flags dangerous capability sets |
| 06 | Cron (`cron.py`) | Implemented | Enumerates jobs, flags writable job targets/definitions |
| 07 | Services (`services.py`) | Implemented | Lists systemd units, flags writable unit files |
| 08 | Processes (`processes.py`) | Implemented | Enumerates /proc, flags writable root-owned executables |
| 09 | Permissions (`permissions.py`) | Implemented | Checks passwd/shadow/sudoers/etc for risky access |
| 10 | Environment (`environment.py`) | Implemented | PATH hijack risks (writable/relative dirs), LD_PRELOAD |

`core/findings.py` (structured `Finding` representation) and `core/scoring.py` (severity vocabulary: INFO/LOW/MEDIUM/HIGH/CRITICAL) back every module's findings. `core/executor.py` centralizes the small set of external commands used (sudo, getcap, systemctl, crontab). `core/reporter.py` turns a run's results into `reports/report.txt`, `report.json`, and `report.html` on request (`--report`).

## Roadmap

- [x] Project architecture and module scaffolding
- [x] CLI arguments (`--<module>`, `--module <name>`, `--all`)
- [x] Module manager (`core/module_manager.py`)
- [x] Structured finding representation (`core/findings.py`) and severity vocabulary (`core/scoring.py`)
- [x] Centralized command execution (`core/executor.py`)
- [x] Report generation — TXT / JSON / HTML (`core/reporter.py`, `--report`)
- [x] Module 01 — System Information
- [x] Module 02 — Users & Groups
- [x] Module 03 — Sudo
- [x] Module 04 — SUID/SGID
- [x] Module 05 — Capabilities
- [x] Module 06 — Cron
- [x] Module 07 — Services
- [x] Module 08 — Processes
- [x] Module 09 — Permissions
- [x] Module 10 — Environment
- [ ] Risk scoring engine — automatic weighting/prioritization across findings (`core/scoring.py`)

## Testing

```bash
python3 -m pytest tests/ -v
```

Every module and core component has a corresponding test file under `tests/`, using mocked command output and temporary files/directories so the suite doesn't depend on the state of the machine it runs on.

## Legal / Authorized Use

PrivScout is intended strictly for **authorized** security testing: penetration tests with explicit written permission, CTF competitions, and personal security labs.

Do not run this tool against systems you do not own or do not have explicit authorization to test. The authors accept no liability for misuse.

PrivScout is an enumeration and reporting tool. It does not exploit vulnerabilities, execute privilege-escalation payloads, modify system files, harvest credentials, establish persistence, or bypass authentication.
