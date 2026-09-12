"""Tests for core/findings.py (structured finding representation)."""

import pytest

from core.findings import Finding


def make_finding(**overrides):
    fields = dict(
        title="Unusual SUID Binary",
        description="A non-standard SUID binary was found.",
        severity="HIGH",
        category="SUID",
        evidence=["/opt/example"],
        recommendation="Investigate whether the binary can be abused.",
    )
    fields.update(overrides)
    return Finding(**fields)


def test_finding_holds_expected_fields():
    finding = make_finding()
    assert finding.title == "Unusual SUID Binary"
    assert finding.severity == "HIGH"
    assert finding.category == "SUID"
    assert finding.evidence == ["/opt/example"]


def test_finding_rejects_invalid_severity():
    with pytest.raises(ValueError):
        make_finding(severity="SUPER_CRITICAL")


def test_finding_to_dict_round_trips_fields():
    finding = make_finding()
    as_dict = finding.to_dict()
    assert as_dict == {
        "title": "Unusual SUID Binary",
        "description": "A non-standard SUID binary was found.",
        "severity": "HIGH",
        "category": "SUID",
        "evidence": ["/opt/example"],
        "recommendation": "Investigate whether the binary can be abused.",
    }


def test_finding_evidence_and_recommendation_have_safe_defaults():
    finding = Finding(
        title="Info",
        description="Just informational.",
        severity="INFO",
        category="System",
    )
    assert finding.evidence == []
    assert finding.recommendation == ""
