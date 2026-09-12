"""Tests for core/reporter.py (report generation)."""

import datetime
import json

from core import reporter
from core.findings import Finding


def make_result(findings, data=None):
    return {"data": data or {}, "findings": findings}


SAMPLE_RESULTS = {
    "sudo": make_result(
        [
            Finding(
                title="Sudo rule allows: ALL",
                description="This rule grants unrestricted root access via sudo.",
                severity="CRITICAL",
                category="Sudo",
                evidence=["(run as ALL : ALL) ALL"],
                recommendation="Investigate the allowed command and its execution context.",
            ),
        ],
        data={"status": "rules_found", "rules": []},
    ),
    "system": make_result([], data={"system": {"hostname": "kali"}}),
}

FIXED_TIME = datetime.datetime(2026, 1, 1, 12, 0, 0)


def test_count_by_severity_includes_zero_counts_for_absent_levels():
    findings = [Finding(title="t", description="d", severity="HIGH", category="c")]
    counts = reporter.count_by_severity(findings)
    assert counts["HIGH"] == 1
    assert counts["CRITICAL"] == 0
    assert counts["INFO"] == 0


def test_collect_all_findings_sorts_most_severe_first():
    findings = [
        Finding(title="a", description="d", severity="LOW", category="c"),
        Finding(title="b", description="d", severity="CRITICAL", category="c"),
        Finding(title="c", description="d", severity="MEDIUM", category="c"),
    ]
    results = {"mod": make_result(findings)}
    ordered = reporter.collect_all_findings(results)
    assert [f.severity for f in ordered] == ["CRITICAL", "MEDIUM", "LOW"]


def test_generate_text_report_includes_findings_and_summary():
    text = reporter.generate_text_report(SAMPLE_RESULTS, generated_at=FIXED_TIME)
    assert "PRIVSCOUT SECURITY ASSESSMENT" in text
    assert "2026-01-01T12:00:00" in text
    assert "CRITICAL" in text
    assert "Sudo rule allows: ALL" in text
    assert "MODULE: system" in text
    assert "No findings." in text


def test_generate_json_report_is_valid_json_with_expected_shape():
    raw = reporter.generate_json_report(SAMPLE_RESULTS, generated_at=FIXED_TIME)
    report = json.loads(raw)

    assert report["generated_at"] == "2026-01-01T12:00:00"
    assert report["summary"]["CRITICAL"] == 1
    assert "sudo" in report["modules"]
    assert report["modules"]["sudo"]["findings"][0]["severity"] == "CRITICAL"
    assert report["modules"]["system"]["data"]["system"]["hostname"] == "kali"


def test_generate_html_report_escapes_untrusted_content():
    malicious_results = {
        "sudo": make_result([
            Finding(
                title="<script>alert(1)</script>",
                description="d",
                severity="HIGH",
                category="Sudo",
                evidence=["<img src=x onerror=alert(1)>"],
            ),
        ]),
    }
    html_output = reporter.generate_html_report(malicious_results, generated_at=FIXED_TIME)
    assert "<script>alert(1)</script>" not in html_output
    assert "&lt;script&gt;" in html_output
    assert "<img src=x onerror=alert(1)>" not in html_output


def test_generate_html_report_shows_no_findings_message():
    html_output = reporter.generate_html_report({}, generated_at=FIXED_TIME)
    assert "No findings." in html_output
    assert "PrivScout Security Assessment" in html_output


def test_save_reports_writes_all_three_files(tmp_path):
    output_dir = tmp_path / "reports"
    paths = reporter.save_reports(SAMPLE_RESULTS, output_dir=str(output_dir))

    assert set(paths.keys()) == {"txt", "json", "html"}
    for fmt, path in paths.items():
        assert (output_dir / f"report.{fmt}").exists()
        content = (output_dir / f"report.{fmt}").read_text()
        assert len(content) > 0


def test_save_reports_creates_output_dir_if_missing(tmp_path):
    output_dir = tmp_path / "nested" / "reports"
    assert not output_dir.exists()
    reporter.save_reports(SAMPLE_RESULTS, output_dir=str(output_dir))
    assert output_dir.exists()
