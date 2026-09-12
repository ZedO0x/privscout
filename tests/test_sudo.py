"""Tests for modules/sudo.py (Module 03 - Sudo)."""

from modules import sudo


SAMPLE_OUTPUT = """Matching Defaults entries for kali on kali:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin

User kali may run the following commands on kali:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/vim
    (root) /usr/local/bin/backup.sh
"""


def make_result(success=True, stdout="", stderr="", returncode=0, error=None):
    return {"success": success, "stdout": stdout, "stderr": stderr, "returncode": returncode, "error": error}


def test_parse_sudo_rules_extracts_all_rules():
    rules = sudo.parse_sudo_rules(SAMPLE_OUTPUT)
    assert len(rules) == 3
    assert rules[0] == {"run_as": "ALL : ALL", "tags": [], "command": "ALL"}
    assert rules[1] == {"run_as": "root", "tags": ["NOPASSWD"], "command": "/usr/bin/vim"}
    assert rules[2]["command"] == "/usr/local/bin/backup.sh"


def test_parse_sudo_rules_ignores_header_lines():
    rules = sudo.parse_sudo_rules("Matching Defaults entries for kali on kali:\n    env_reset\n")
    assert rules == []


def test_determine_status_rules_found():
    result = make_result(success=True, stdout=SAMPLE_OUTPUT)
    rules = sudo.parse_sudo_rules(SAMPLE_OUTPUT)
    assert sudo.determine_status(result, rules) == "rules_found"


def test_determine_status_password_required():
    result = make_result(success=False, stderr="sudo: a password is required", returncode=1)
    assert sudo.determine_status(result, []) == "password_required"


def test_determine_status_not_permitted():
    result = make_result(success=False, stderr="Sorry, user bob may not run sudo on host.", returncode=1)
    assert sudo.determine_status(result, []) == "not_permitted"


def test_determine_status_error():
    result = make_result(success=False, error="Command not found: sudo")
    assert sudo.determine_status(result, []) == "error"


def test_classify_rule_full_access_is_critical():
    severity, _ = sudo.classify_rule({"run_as": "ALL", "tags": [], "command": "ALL"})
    assert severity == "CRITICAL"


def test_classify_rule_gtfobins_command_is_high():
    severity, _ = sudo.classify_rule({"run_as": "root", "tags": ["NOPASSWD"], "command": "/usr/bin/vim"})
    assert severity == "HIGH"


def test_classify_rule_narrow_command_is_low():
    severity, _ = sudo.classify_rule({"run_as": "root", "tags": [], "command": "/usr/local/bin/backup.sh"})
    assert severity == "LOW"


def test_build_findings_only_when_rules_found():
    assert sudo.build_findings("password_required", []) == []
    assert sudo.build_findings("not_permitted", []) == []


def test_build_findings_produces_one_finding_per_rule():
    rules = sudo.parse_sudo_rules(SAMPLE_OUTPUT)
    findings = sudo.build_findings("rules_found", rules)
    assert len(findings) == 3
    assert findings[0].severity == "CRITICAL"
    assert findings[1].severity == "HIGH"
    assert findings[2].severity == "LOW"


def test_run_returns_expected_shape(monkeypatch):
    monkeypatch.setattr(sudo, "check_sudo_available", lambda: make_result(success=True, stdout=SAMPLE_OUTPUT))
    result = sudo.run()
    assert "data" in result
    assert "findings" in result
    assert result["data"]["status"] == "rules_found"
    assert len(result["findings"]) == 3


def test_run_no_findings_when_password_required(monkeypatch):
    monkeypatch.setattr(
        sudo, "check_sudo_available",
        lambda: make_result(success=False, stderr="sudo: a password is required", returncode=1),
    )
    result = sudo.run()
    assert result["data"]["status"] == "password_required"
    assert result["findings"] == []
