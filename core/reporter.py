"""
Report generation.

Turns one PrivScout run (a {module_name: {"data": ..., "findings": [...]}}
mapping - exactly what core/module_manager.py's run() calls return) into
three report formats: a plain-text summary, a JSON dump, and a
self-contained HTML report. All three are built from the same
underlying data, so they never drift apart from one another or from
what the CLI printed.
"""

import datetime
import html
import json
import os

from core.scoring import SEVERITY_LEVELS

REPORTS_DIR = "reports"

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#f87171",
    "MEDIUM": "#facc15",
    "LOW": "#38bdf8",
    "INFO": "#9ca3af",
}


def count_by_severity(all_findings):
    """Return {severity: count} for every severity level (0 if none found)."""
    counts = {level: 0 for level in SEVERITY_LEVELS}
    for finding in all_findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def collect_all_findings(module_results):
    """Flatten every module's findings into one list, most severe first."""
    order = {level: index for index, level in enumerate(SEVERITY_LEVELS)}
    all_findings = []
    for result in module_results.values():
        all_findings.extend(result.get("findings", []))
    all_findings.sort(key=lambda finding: order.get(finding.severity, 0), reverse=True)
    return all_findings


def generate_text_report(module_results, generated_at=None):
    """Return a plain-text report as a string."""
    generated_at = generated_at or datetime.datetime.now()
    all_findings = collect_all_findings(module_results)
    counts = count_by_severity(all_findings)

    lines = [
        "=" * 60,
        "PRIVSCOUT SECURITY ASSESSMENT",
        "=" * 60,
        f"Generated: {generated_at.isoformat(timespec='seconds')}",
        "",
        "Findings by severity:",
    ]
    for level in reversed(SEVERITY_LEVELS):
        lines.append(f"  {level:<10}: {counts[level]}")
    lines.append("")

    for module_name, result in module_results.items():
        findings = result.get("findings", [])
        lines.append("-" * 60)
        lines.append(f"MODULE: {module_name}")
        lines.append("-" * 60)
        if not findings:
            lines.append("  No findings.")
        for finding in findings:
            lines.append(f"[{finding.severity}] {finding.title}")
            lines.append(f"    {finding.description}")
            for item in finding.evidence:
                lines.append(f"    Evidence: {item}")
            if finding.recommendation:
                lines.append(f"    Recommendation: {finding.recommendation}")
            lines.append("")
        lines.append("")

    return "\n".join(lines)


def generate_json_report(module_results, generated_at=None):
    """Return a JSON report (module data + findings) as a string."""
    generated_at = generated_at or datetime.datetime.now()
    all_findings = collect_all_findings(module_results)

    report = {
        "generated_at": generated_at.isoformat(timespec="seconds"),
        "summary": count_by_severity(all_findings),
        "modules": {
            name: {
                "data": result.get("data", {}),
                "findings": [finding.to_dict() for finding in result.get("findings", [])],
            }
            for name, result in module_results.items()
        },
    }
    return json.dumps(report, indent=2, default=str)


def generate_html_report(module_results, generated_at=None):
    """Return a self-contained HTML report as a string.

    All module-derived text is HTML-escaped before interpolation, since
    it originates from the scanned system (paths, usernames, ...) and
    must never be treated as trusted markup.
    """
    generated_at = generated_at or datetime.datetime.now()
    all_findings = collect_all_findings(module_results)
    counts = count_by_severity(all_findings)

    finding_blocks = []
    for finding in all_findings:
        evidence_html = "".join(
            f"<div class='evidence'>{html.escape(item)}</div>" for item in finding.evidence
        )
        recommendation_html = (
            f"<p class='rec'>Recommendation: {html.escape(finding.recommendation)}</p>"
            if finding.recommendation else ""
        )
        color = SEVERITY_COLORS.get(finding.severity, "#9ca3af")
        finding_blocks.append(f"""
        <div class="finding">
          <span class="badge" style="background:{color}">{html.escape(finding.severity)}</span>
          <strong>{html.escape(finding.title)}</strong>
          <p>{html.escape(finding.description)}</p>
          {evidence_html}
          {recommendation_html}
          <div class="meta">Category: {html.escape(finding.category)}</div>
        </div>""")

    summary_blocks = "".join(
        f"<div class='stat'><span class='count'>{counts[level]}</span>"
        f"<span class='label'>{html.escape(level)}</span></div>"
        for level in reversed(SEVERITY_LEVELS)
    )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>PrivScout Security Assessment</title>
<style>
  body {{ font-family: -apple-system, 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e5e7eb; margin: 0; padding: 2rem; }}
  h1 {{ color: #22d3ee; margin-bottom: 0.25rem; }}
  .generated {{ color: #6b7280; font-size: 0.85rem; margin-bottom: 1.5rem; }}
  .summary {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: #1a1d27; border-radius: 8px; padding: 1rem 1.5rem; text-align: center; min-width: 5rem; }}
  .stat .count {{ display: block; font-size: 1.8rem; font-weight: bold; }}
  .stat .label {{ font-size: 0.75rem; color: #9ca3af; letter-spacing: 0.05em; }}
  .finding {{ background: #1a1d27; border-left: 4px solid #374151; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }}
  .badge {{ color: #0f1117; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 0.5rem; }}
  .evidence {{ font-family: 'SF Mono', Consolas, monospace; background: #0f1117; padding: 0.3rem 0.6rem; border-radius: 4px; margin-top: 0.5rem; font-size: 0.85rem; color: #d1d5db; word-break: break-all; }}
  .rec {{ color: #86efac; font-size: 0.9rem; }}
  .meta {{ color: #6b7280; font-size: 0.75rem; margin-top: 0.5rem; }}
</style>
</head>
<body>
<h1>PrivScout Security Assessment</h1>
<div class="generated">Generated: {html.escape(generated_at.isoformat(timespec="seconds"))}</div>
<div class="summary">{summary_blocks}</div>
<h2>Findings ({len(all_findings)})</h2>
{"".join(finding_blocks) if finding_blocks else "<p>No findings.</p>"}
</body>
</html>
"""


def save_reports(module_results, output_dir=REPORTS_DIR):
    """Write report.txt, report.json, and report.html under output_dir.

    Returns {"txt": path, "json": path, "html": path}.
    """
    os.makedirs(output_dir, exist_ok=True)
    generated_at = datetime.datetime.now()

    generators = {
        "txt": (generate_text_report, "report.txt"),
        "json": (generate_json_report, "report.json"),
        "html": (generate_html_report, "report.html"),
    }

    paths = {}
    for fmt, (generate, filename) in generators.items():
        content = generate(module_results, generated_at=generated_at)
        path = os.path.join(output_dir, filename)
        with open(path, "w") as handle:
            handle.write(content)
        paths[fmt] = path

    return paths
