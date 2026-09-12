"""
Risk scoring.

Defines the severity vocabulary shared by findings and reports. The
automatic scoring/prioritization logic itself is still planned and
will be built once modules start producing real findings (starting
with sudo/SUID analysis) — for now this module only defines the
allowed severity levels so core/findings.py has something to validate
against.
"""

INFO = "INFO"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

# Ordered from least to most severe.
SEVERITY_LEVELS = [INFO, LOW, MEDIUM, HIGH, CRITICAL]
