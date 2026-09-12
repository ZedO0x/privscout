"""
Structured finding representation.

A Finding is the single shape every enumeration module produces its
security-relevant observations in, so the same data can drive the
terminal output, and later the JSON and HTML reports, without each
module inventing its own format.
"""

from dataclasses import dataclass, field
from typing import List

from core.scoring import SEVERITY_LEVELS


@dataclass
class Finding:
    """A single security-relevant observation produced by a module."""

    title: str
    description: str
    severity: str
    category: str
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity {self.severity!r}. Must be one of: {', '.join(SEVERITY_LEVELS)}"
            )

    def to_dict(self):
        """Return a plain dict, suitable for JSON/HTML reporting."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
