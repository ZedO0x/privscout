"""Tests for modules/users.py (Module 02 - Users & Groups)."""

from modules import users


def test_get_current_identity_keys():
    identity = users.get_current_identity()
    for key in ("uid", "gid", "username", "groups"):
        assert key in identity
    assert isinstance(identity["groups"], list)


def test_get_current_groups_returns_sorted_names(monkeypatch):
    monkeypatch.setattr(users.os, "getgroups", lambda: [0, 27])
    monkeypatch.setattr(users.os, "getgid", lambda: 1000)
    groups = users.get_current_groups()
    assert groups == sorted(groups)
    assert "root" in groups  # gid 0


def test_get_current_groups_never_raises_on_failure(monkeypatch):
    def boom():
        raise OSError("no groups for you")
    monkeypatch.setattr(users.os, "getgroups", boom)
    assert users.get_current_groups() == []


def test_get_local_users_shape(monkeypatch):
    fake_entry = type("Entry", (), {
        "pw_name": "alice", "pw_uid": 1001, "pw_gid": 1001,
        "pw_dir": "/home/alice", "pw_shell": "/bin/bash",
    })()
    monkeypatch.setattr(users.pwd, "getpwall", lambda: [fake_entry])
    local_users = users.get_local_users()
    assert local_users == [{
        "username": "alice", "uid": 1001, "gid": 1001,
        "home_directory": "/home/alice", "shell": "/bin/bash",
    }]


def test_get_uid_zero_accounts_filters_by_uid():
    local_users = [
        {"username": "root", "uid": 0, "gid": 0, "home_directory": "/root", "shell": "/bin/bash"},
        {"username": "backdoor", "uid": 0, "gid": 0, "home_directory": "/home/backdoor", "shell": "/bin/sh"},
        {"username": "alice", "uid": 1001, "gid": 1001, "home_directory": "/home/alice", "shell": "/bin/bash"},
    ]
    uid0 = users.get_uid_zero_accounts(local_users)
    assert {u["username"] for u in uid0} == {"root", "backdoor"}


def test_build_findings_flags_interesting_group():
    identity = {"groups": ["sudo", "users"]}
    findings = users.build_findings(identity, [])
    titles = [f.title for f in findings]
    assert "Member of interesting group: sudo" in titles
    assert not any("users" in t for t in titles)


def test_build_findings_ignores_plain_root_account():
    identity = {"groups": []}
    uid_zero_accounts = [{"username": "root", "uid": 0, "gid": 0, "home_directory": "/root", "shell": "/bin/bash"}]
    findings = users.build_findings(identity, uid_zero_accounts)
    assert findings == []


def test_build_findings_flags_extra_uid_zero_account():
    identity = {"groups": []}
    uid_zero_accounts = [
        {"username": "root", "uid": 0, "gid": 0, "home_directory": "/root", "shell": "/bin/bash"},
        {"username": "backdoor", "uid": 0, "gid": 0, "home_directory": "/home/backdoor", "shell": "/bin/sh"},
    ]
    findings = users.build_findings(identity, uid_zero_accounts)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "backdoor" in findings[0].description


def test_run_returns_expected_shape():
    result = users.run()
    assert "data" in result
    assert "findings" in result
    assert isinstance(result["findings"], list)
    for key in ("current_identity", "local_users", "uid_zero_accounts"):
        assert key in result["data"]
