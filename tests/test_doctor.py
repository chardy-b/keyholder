from __future__ import annotations

import os
import subprocess
import threading

from keyholderd import cli
from keyholderd.cli import CheckResult
from keyholderd.server import UnixHTTPServer


def test_check_systemd_version_ok(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/systemctl")
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="systemd 255 (255.4)\n")
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: completed)
    result = cli.check_systemd_version()
    assert result.status == "ok"
    assert "255" in result.detail


def test_check_systemd_version_fail_when_old(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/systemctl")
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="systemd 249 (249)\n")
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: completed)
    result = cli.check_systemd_version()
    assert result.status == "fail"


def test_check_systemd_version_warn_when_missing(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    result = cli.check_systemd_version()
    assert result.status == "warn"


def test_check_bws_ok_when_on_path(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/local/bin/bws" if name == "bws" else None)
    result = cli.check_bws()
    assert result.status == "ok"


def test_check_bws_fails_when_missing_and_unit_installed(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    monkeypatch.setattr(cli, "_unit_installed", lambda: True)
    result = cli.check_bws()
    assert result.status == "fail"


def test_check_bws_warns_when_missing_and_no_unit(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    monkeypatch.setattr(cli, "_unit_installed", lambda: False)
    result = cli.check_bws()
    assert result.status == "warn"


def test_check_service_active_ok(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/systemctl")
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="active\n")
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: completed)
    result = cli.check_service_active()
    assert result.status == "ok"


def test_check_service_active_fails_when_inactive(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/systemctl")
    completed = subprocess.CompletedProcess(args=[], returncode=3, stdout="inactive\n")
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: completed)
    result = cli.check_service_active()
    assert result.status == "fail"
    assert "journalctl" in result.detail


def test_check_socket_missing(tmp_path):
    result = cli.check_socket(str(tmp_path / "nope.sock"))
    assert result.status == "fail"


def test_check_socket_not_a_socket(tmp_path):
    f = tmp_path / "notasocket"
    f.write_text("x")
    result = cli.check_socket(str(f))
    assert result.status == "fail"
    assert "not a socket" in result.detail


def test_check_group_membership_fail_when_group_missing(monkeypatch):
    def raise_keyerror(name):
        raise KeyError(name)
    monkeypatch.setattr(cli.grp, "getgrnam", raise_keyerror)
    result = cli.check_group_membership("someuser")
    assert result.status == "fail"


def test_check_group_membership_warn_when_configured_but_inactive(monkeypatch):
    class FakeGroup:
        gr_mem = ["someuser"]
        gr_gid = 4242
    monkeypatch.setattr(cli.grp, "getgrnam", lambda name: FakeGroup())
    monkeypatch.setattr(cli.pwd, "getpwnam", lambda name: type("P", (), {"pw_gid": 1})())
    monkeypatch.setattr(cli.os, "getgroups", lambda: [1, 2, 3])
    result = cli.check_group_membership("someuser")
    assert result.status == "warn"
    assert "newgrp" in result.detail


def test_check_group_membership_ok_when_active(monkeypatch):
    class FakeGroup:
        gr_mem = ["someuser"]
        gr_gid = 4242
    monkeypatch.setattr(cli.grp, "getgrnam", lambda name: FakeGroup())
    monkeypatch.setattr(cli.pwd, "getpwnam", lambda name: type("P", (), {"pw_gid": 1})())
    monkeypatch.setattr(cli.os, "getgroups", lambda: [1, 2, 4242])
    result = cli.check_group_membership("someuser")
    assert result.status == "ok"


def test_check_policy_permission_denied_on_directory(monkeypatch):
    # /etc/keyholder is 0750 root:keyholder; a caller outside that group hits
    # PermissionError just from Path.exists(), before ever reaching open().
    def raise_permission_error(self):
        raise PermissionError("permission denied")
    monkeypatch.setattr(cli.Path, "exists", raise_permission_error)
    result = cli.check_policy("/etc/keyholder/policy.yaml")
    assert result.status == "ok"
    assert "unreadable" in result.detail


def test_check_credential_permission_denied_on_directory(monkeypatch):
    def raise_permission_error(self):
        raise PermissionError("permission denied")
    monkeypatch.setattr(cli.Path, "exists", raise_permission_error)
    result = cli.check_credential("/etc/keyholder/bws-access-token.cred")
    assert result.status == "warn"
    assert "permission denied" in result.detail


def test_check_policy_missing(tmp_path):
    result = cli.check_policy(str(tmp_path / "policy.yaml"))
    assert result.status == "fail"


def test_check_policy_unreadable(tmp_path, monkeypatch):
    p = tmp_path / "policy.yaml"
    p.write_text("version: 1\ncallers: {}\n")
    monkeypatch.setattr(cli.os, "access", lambda path, mode: False)
    result = cli.check_policy(str(p))
    assert result.status == "ok"
    assert "unreadable" in result.detail


def test_check_policy_parses(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("version: 1\ncallers: {}\n")
    result = cli.check_policy(str(p))
    assert result.status == "ok"


def test_check_policy_bad_yaml_fails(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("version: 2\ncallers: {}\n")
    result = cli.check_policy(str(p))
    assert result.status == "fail"


def test_check_credential_missing(tmp_path):
    result = cli.check_credential(str(tmp_path / "nope.cred"))
    assert result.status == "fail"


def test_check_credential_warns_when_not_root(tmp_path, monkeypatch):
    p = tmp_path / "token.cred"
    p.write_text("sealed")
    monkeypatch.setattr(cli.os, "getuid", lambda: 1000)
    result = cli.check_credential(str(p))
    assert result.status == "warn"
    assert "sudo" in result.detail


def test_check_grants_endpoint_reports_count(monkeypatch):
    monkeypatch.setattr(cli, "request", lambda *a, **k: {"grants": [{"name": "a"}, {"name": "b"}]})
    result = cli.check_grants_endpoint("/tmp/whatever.sock")
    assert result.status == "ok"
    assert "2 grant" in result.detail


def test_check_grants_endpoint_fails_when_unreachable(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(cli, "request", boom)
    result = cli.check_grants_endpoint("/tmp/whatever.sock")
    assert result.status == "fail"


def test_doctor_e2e_against_fake_server(tmp_path, capsys):
    sock = str(tmp_path / "keyholder.sock")
    current_user = os.environ.get("USER", "hermes")
    cfg = {
        "version": 1,
        "paths": {"leases_db": str(tmp_path / "leases.db"), "audit_log": str(tmp_path / "audit.jsonl")},
        "callers": {"me": {"uid_name": current_user, "profiles": {"default": {"grants": [
            {"name": "fake", "provider": "fake", "ttl_seconds": 30, "max_ttl_seconds": 60, "bitwarden_refs": {}}
        ]}}}},
    }
    httpd = UnixHTTPServer(sock, cfg)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        cli.main(["--socket", sock, "doctor"])
        out = capsys.readouterr().out
        assert "grants endpoint" in out
        assert "1 grant" in out
    finally:
        httpd.shutdown()
        httpd.server_close()
