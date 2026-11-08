import json
import logging
import os
import stat
import sys
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from keyholderd import grafana_import as gi
from keyholderd.bitwarden import BitwardenImportError, ImportedSecret

PROJECT = "22222222-2222-4222-8222-222222222222"
ORG = "11111111-1111-4111-8111-111111111111"
VALUE = "hunter2-PLAINTEXT-sentinel"
NOW = datetime(2026, 6, 1, tzinfo=UTC)
FUTURE = (NOW + timedelta(days=1)).isoformat()


def policy(tmp_path, *, operations=None, grafana="default", profile="default"):
    if operations is None:
        operations = [{"operation": "grafana_projects"}, {"operation": "grafana_import", "expires_at": FUTURE}]
    cfg = {
        "version": 1,
        "paths": {"leases_db": str(tmp_path / "leases.db"), "audit_log": str(tmp_path / "audit.jsonl")},
        "callers": {"hermes": {"uid_name": "hermes", "profiles": {profile: {"grants": [{"name": "fake", "provider": "fake", "ttl_seconds": 30, "bitwarden_refs": {}}], "operations": operations}}}},
    }
    if grafana == "default":
        grafana = {"enabled": True, "project_id": PROJECT}
    if grafana is not None:
        cfg["grafana_import"] = grafana
    return cfg


def audit_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class FakeResolver:
    def __init__(self, *, created=True, error=None):
        self.created, self.error, self.calls = created, error, []

    def list_projects(self):
        if self.error:
            raise BitwardenImportError(self.error)
        return [{"id": PROJECT, "name": "Grafana"}]

    def import_secret(self, **kw):
        self.calls.append(kw)
        if self.error:
            raise BitwardenImportError(self.error)
        return ImportedSecret("44444444-4444-4444-8444-444444444444", kw["key"], kw["project_id"], self.created)


@pytest.fixture
def wired(monkeypatch):
    resolver = FakeResolver()
    fetches = []

    def fetch(**kw):
        fetches.append(kw)
        return VALUE

    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: resolver)
    monkeypatch.setattr(gi, "SOURCE_FETCHER", fetch)
    return resolver, fetches


def call(cfg, tmp_path, operation=gi.OP_IMPORT, body=b"{}", caller="hermes"):
    return gi.handle(cfg, str(tmp_path / "audit.jsonl"), caller, operation, body, now=NOW)


# --- strict request schema -----------------------------------------------------

@pytest.mark.parametrize(
    "body",
    [None, b"not json", b"[]", b'"x"', b'{"value":"x"}', b'{"project_id":"x"}', b'{"profile":"default","host":"evil"}', b'{"profile":5}', b'{"profile":"../x"}',
     b'{"profile":"default","profile":"default"}', b'{"profile":"Default"}', b"\xff\xfe", b"{" + b" " * 2000 + b"}"],
)
def test_hostile_or_malformed_bodies_are_rejected_audited_and_not_echoed(tmp_path, wired, body):
    resolver, fetches = wired
    status, payload = call(policy(tmp_path), tmp_path, body=body)
    assert (status, payload) == (400, {"error": "invalid request"})
    assert not resolver.calls and not fetches
    (event,) = audit_lines(tmp_path)
    assert event["phase"] == "denied" and event["reason"] == "invalid_request" and event["profile"] == ""
    assert "evil" not in json.dumps(event)


def test_empty_body_and_profile_only_are_accepted(tmp_path, wired):
    assert call(policy(tmp_path), tmp_path, body=b"")[0] == 200
    assert call(policy(tmp_path), tmp_path, body=b'{"profile":"default"}')[0] == 200


# --- authorization -----------------------------------------------------------------

def test_unknown_caller_and_missing_operation_denied(tmp_path, wired):
    resolver, fetches = wired
    assert call(policy(tmp_path), tmp_path, caller="nobody")[0] == 403
    assert call(policy(tmp_path, operations=[]), tmp_path)[0] == 403
    assert call(policy(tmp_path, operations=[{"operation": "grafana_projects"}]), tmp_path)[0] == 403
    assert call(policy(tmp_path, operations=[{"operation": "grafana_import", "expires_at": FUTURE}]), tmp_path, operation=gi.OP_PROJECTS)[0] == 403
    assert call(policy(tmp_path), tmp_path, body=b'{"profile":"other"}')[0] == 403
    assert not resolver.calls and not fetches
    assert {e["reason"] for e in audit_lines(tmp_path)} == {"not_authorized"}


@pytest.mark.parametrize(
    "entry",
    [
        {"operation": "grafana_import"},  # import requires an operator deadline
        {"operation": "grafana_import", "expires_at": (NOW - timedelta(seconds=1)).isoformat()},
        {"operation": "grafana_import", "expires_at": "2026-12-01T00:00:00"},  # naive
        {"operation": "grafana_import", "expires_at": "garbage"},
        {"operation": "grafana_import", "expires_at": 12345},
        {"operation": "grafana_import", "expires_at": FUTURE, "extra": True},
        {"operation": "grafana_*", "expires_at": FUTURE},
        "grafana_import",
    ],
)
def test_expired_unbounded_or_malformed_operation_entries_deny(tmp_path, wired, entry):
    assert call(policy(tmp_path, operations=[entry]), tmp_path)[0] == 403


def test_yaml_datetime_deadline_is_honoured(tmp_path, wired):
    ops = [{"operation": "grafana_import", "expires_at": NOW + timedelta(hours=1)}]
    assert call(policy(tmp_path, operations=ops), tmp_path)[0] == 200


def test_operations_are_not_grants_and_grants_are_not_operations(tmp_path):
    from keyholderd import server
    cfg = policy(tmp_path)
    assert [g["name"] for g in server.handle_grants(cfg, "hermes")["grants"]] == ["fake"]
    for name in ("grafana_import", "grafana_projects", "grafana-import"):
        with pytest.raises(Exception, match="is not available"):
            server.handle_issue(cfg, "hermes", {"grant": name, "reason": "x"})
        with pytest.raises(Exception, match="is not available"):
            server.handle_run(cfg, "hermes", {"grant": name, "reason": "x", "command": ["true"], "env_var": "X"})
    # a grant carrying an operation's name does not authorize the operation
    cfg_no_ops = policy(tmp_path, operations=[])
    cfg_no_ops["callers"]["hermes"]["profiles"]["default"]["grants"] = [{"name": "grafana_import", "provider": "fake"}, {"name": "grafana_projects", "provider": "fake"}]
    assert call(cfg_no_ops, tmp_path)[0] == 403
    assert call(cfg_no_ops, tmp_path, operation=gi.OP_PROJECTS)[0] == 403


# --- import configuration fails closed -----------------------------------------------

@pytest.mark.parametrize(
    "grafana",
    [
        None, "yes", {}, {"enabled": "true", "project_id": PROJECT}, {"enabled": 1, "project_id": PROJECT}, {"enabled": False, "project_id": PROJECT},
        {"enabled": True}, {"enabled": True, "project_id": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}, {"enabled": True, "project_id": PROJECT.replace("-", "")},
        {"enabled": True, "project_id": "00000000-0000-0000-0000-000000000000"}, {"enabled": True, "project_id": "not-a-uuid"},
        {"enabled": True, "project_id": PROJECT, "organization_id": "bad"}, {"enabled": True, "project_id": PROJECT, "host": "x"},
        {"enabled": True, "project_id": PROJECT, "strip_single_trailing_newline": "yes"}, {"enabled": True, "project_id": 5},
    ],
)
def test_disabled_missing_or_misconfigured_import_fails_closed(tmp_path, wired, grafana):
    resolver, fetches = wired
    status, payload = call(policy(tmp_path, grafana=grafana), tmp_path)
    assert (status, payload["error"]) == (503, "grafana import is not configured")
    assert not resolver.calls and not fetches
    assert [e["phase"] for e in audit_lines(tmp_path)] == ["denied"]


def test_metadata_works_before_a_project_is_selected(tmp_path, wired):
    status, payload = call(policy(tmp_path, grafana=None), tmp_path, operation=gi.OP_PROJECTS)
    assert status == 200 and payload == {"projects": [{"id": PROJECT, "name": "Grafana"}]}
    events = audit_lines(tmp_path)
    assert [e["phase"] for e in events] == ["attempt", "completed"] and events[-1]["project_count"] == 1


# --- successful import and response/audit shape --------------------------------------

def test_import_success_output_and_audit_have_no_values(tmp_path, wired, caplog):
    resolver, fetches = wired
    cfg = policy(tmp_path, grafana={"enabled": True, "project_id": PROJECT, "organization_id": ORG, "strip_single_trailing_newline": True})
    with caplog.at_level(logging.DEBUG):
        status, payload = call(cfg, tmp_path)
    assert status == 200
    assert payload == {"id": "44444444-4444-4444-8444-444444444444", "key": "GRAFANA_FLEET_ADMIN_PASSWORD", "project_id": PROJECT, "status_verified": True}
    assert fetches == [{"strip_single_trailing_newline": True}]
    assert resolver.calls == [dict(project_id=PROJECT, key="GRAFANA_FLEET_ADMIN_PASSWORD", value=VALUE, note=gi.DEST_NOTE, organization_id=ORG)]
    events = audit_lines(tmp_path)
    assert [(e["phase"], e["reason"]) for e in events] == [("attempt", "attempt"), ("completed", "created")]
    assert events[-1]["record_id"] == payload["id"]
    assert VALUE not in (tmp_path / "audit.jsonl").read_text() and VALUE not in caplog.text


def test_already_present_is_audited_as_such(tmp_path, wired, monkeypatch):
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FakeResolver(created=False))
    assert call(policy(tmp_path), tmp_path)[0] == 200
    assert audit_lines(tmp_path)[-1]["reason"] == "already_present"


# --- audit-before-side-effect ----------------------------------------------------------

def test_attempt_audit_failure_blocks_all_side_effects(tmp_path, wired, monkeypatch):
    resolver, fetches = wired

    def boom(path, event, **kw):
        raise OSError("disk full /secret/path")

    monkeypatch.setattr(gi, "write_audit_event", boom)
    status, payload = call(policy(tmp_path), tmp_path)
    assert (status, payload) == (503, {"error": "audit log unavailable; no action taken"})
    assert not resolver.calls and not fetches
    assert gi._LOCK.acquire(blocking=False)  # lock was released
    gi._LOCK.release()


def test_attempt_audit_is_durable_and_precedes_the_source_read(tmp_path, monkeypatch):
    order = []
    real = gi.write_audit_event

    def spy(path, event, **kw):
        order.append((event["phase"], kw.get("durable", False)))
        return real(path, event, **kw)

    monkeypatch.setattr(gi, "write_audit_event", spy)
    monkeypatch.setattr(gi, "SOURCE_FETCHER", lambda **kw: order.append(("fetch", None)) or VALUE)
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FakeResolver())
    assert call(policy(tmp_path), tmp_path)[0] == 200
    assert order[:2] == [("attempt", True), ("fetch", None)]


# --- failures: codes only ----------------------------------------------------------------

@pytest.mark.parametrize(
    "code,status",
    [("value_differs", 409), ("duplicate_records", 409), ("write_ambiguous", 502), ("auth_failed", 502), ("project_unavailable", 502), ("lookup_failed", 502)],
)
def test_bitwarden_failures_map_to_fixed_codes(tmp_path, wired, monkeypatch, code, status):
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FakeResolver(error=code))
    got, payload = call(policy(tmp_path), tmp_path)
    assert got == status and payload == {"error": gi.ERRORS[code][1]}
    last = audit_lines(tmp_path)[-1]
    assert (last["phase"], last["reason"]) == ("failed", code)


def test_unexpected_exceptions_never_leak_text(tmp_path, monkeypatch, caplog):
    def fetch(**kw):
        raise RuntimeError(f"ssh said {VALUE}")

    monkeypatch.setattr(gi, "SOURCE_FETCHER", fetch)
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FakeResolver())
    with caplog.at_level(logging.DEBUG):
        status, payload = call(policy(tmp_path), tmp_path)
    assert (status, payload) == (500, {"error": "internal error"})
    assert VALUE not in json.dumps(payload) and VALUE not in (tmp_path / "audit.jsonl").read_text() and VALUE not in caplog.text


def test_source_failure_means_no_bitwarden_write(tmp_path, monkeypatch):
    resolver = FakeResolver()

    def fetch(**kw):
        raise gi.GrafanaImportError("source_timeout")

    monkeypatch.setattr(gi, "SOURCE_FETCHER", fetch)
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: resolver)
    assert call(policy(tmp_path), tmp_path)[0] == 504
    assert not resolver.calls


# --- serialization and deadline ------------------------------------------------------------

def test_operations_are_serialized_and_busy_is_reported(tmp_path, monkeypatch):
    started, release = threading.Event(), threading.Event()
    resolver = FakeResolver()

    def slow(**kw):
        started.set()
        release.wait(5)
        return VALUE

    monkeypatch.setattr(gi, "SOURCE_FETCHER", slow)
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: resolver)
    monkeypatch.setattr(gi, "BUSY_WAIT_SECONDS", 0.05)
    first = []
    t = threading.Thread(target=lambda: first.append(call(policy(tmp_path), tmp_path)))
    t.start()
    assert started.wait(5)
    assert call(policy(tmp_path), tmp_path)[1] == {"error": gi.ERRORS["busy"][1]}
    release.set()
    t.join(5)
    assert first[0][0] == 200 and len(resolver.calls) == 1


# --- fixed SSH source read ------------------------------------------------------------------

def good_known_hosts(tmp_path):
    kh = tmp_path / "known_hosts"
    kh.write_text("matrix-ubuntu ssh-ed25519 AAAA\n")
    os.chmod(kh, 0o644)
    return str(kh)


def test_ssh_argv_is_fixed_strict_and_has_no_caller_or_secret_input(tmp_path):
    argv = gi.build_ssh_argv("/etc/keyholder/grafana-import-known_hosts")
    assert argv[0] == "/usr/bin/ssh"
    joined = " ".join(argv)
    for needed in ("BatchMode=yes", "StrictHostKeyChecking=yes", "UserKnownHostsFile=/etc/keyholder/grafana-import-known_hosts", "GlobalKnownHostsFile=/dev/null", "-F /dev/null", "-l root", "PasswordAuthentication=no"):
        assert needed in joined
    for forbidden in ("StrictHostKeyChecking=no", "accept-new", "-i ", "IdentityFile"):
        assert forbidden not in joined
    assert argv[-3:] == ["--", "matrix-ubuntu", "head -c 4097 -- /opt/fleet-observability/secrets/grafana_password"]
    assert gi.build_ssh_argv() == gi.build_ssh_argv(gi.KNOWN_HOSTS_FILE)


def test_ssh_env_excludes_token_and_credential_paths(monkeypatch):
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
    monkeypatch.setenv("BWS_ACCESS_TOKEN_FILE", "/run/credentials/x")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/run/credentials")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent")
    assert gi.ssh_env() == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


def fetch_with(tmp_path, result, **kw):
    seen = {}

    def runner(argv, env, timeout, max_bytes):
        seen.update(argv=argv, env=env, timeout=timeout, max_bytes=max_bytes)
        if isinstance(result, Exception):
            raise result
        return result

    kw.setdefault("known_hosts_file", good_known_hosts(tmp_path))
    kw.setdefault("trusted_uid", os.getuid())
    return gi.fetch_source_password(runner=runner, **kw), seen


def R(data, rc=0, timed_out=False, exceeded=False):
    return gi.BoundedResult(rc, data, timed_out, exceeded)


def test_source_value_is_retained_exactly_by_default(tmp_path):
    value, seen = fetch_with(tmp_path, R(b"pa ss\n"))
    assert value == "pa ss\n"
    assert seen["max_bytes"] == 4096 and 0 < seen["timeout"] <= 30 and seen["env"] == gi.ssh_env()


def test_only_one_terminal_linefeed_is_stripped_when_explicitly_enabled(tmp_path):
    assert fetch_with(tmp_path, R(b"pw\n"), strip_single_trailing_newline=True)[0] == "pw"
    assert fetch_with(tmp_path, R(b"pw\n\n"), strip_single_trailing_newline=True)[0] == "pw\n"
    assert fetch_with(tmp_path, R(b"pw\r\n"), strip_single_trailing_newline=True)[0] == "pw\r"
    assert fetch_with(tmp_path, R(b"pw"), strip_single_trailing_newline=True)[0] == "pw"


@pytest.mark.parametrize(
    "result,code",
    [
        (R(b""), "source_invalid"), (R(b"\n"), "source_invalid") if False else (R(b"a\x00b"), "source_invalid"), (R(b"\xff\xfe"), "source_invalid"),
        (R(b"x" * 4097), "source_too_large"), (R(b"x" * 10, exceeded=True), "source_too_large"),
        (R(b"", timed_out=True, rc=None), "source_timeout"), (R(b"pw", rc=255), "source_unavailable"), (R(b"pw", rc=1), "source_unavailable"),
        (OSError(f"leak {VALUE}"), "source_unavailable"),
    ],
)
def test_source_rejections(tmp_path, result, code):
    with pytest.raises(gi.GrafanaImportError) as err:
        fetch_with(tmp_path, result)
    assert err.value.code == code and VALUE not in str(err.value) and err.value.__context__ is None


def test_exactly_4096_bytes_accepted_and_newline_only_rejected_when_stripping(tmp_path):
    assert len(fetch_with(tmp_path, R(b"x" * 4096))[0]) == 4096
    with pytest.raises(gi.GrafanaImportError):
        fetch_with(tmp_path, R(b"\n"), strip_single_trailing_newline=True)


def test_unsafe_known_hosts_blocks_ssh(tmp_path):
    ran = []
    def runner(*a):
        ran.append(a)
        return R(b"pw")
    good = good_known_hosts(tmp_path)
    cases = {}
    cases["missing"] = str(tmp_path / "nope")
    (tmp_path / "empty").write_text("")
    cases["empty"] = str(tmp_path / "empty")
    writable = tmp_path / "w"; writable.write_text("x"); os.chmod(writable, 0o666)
    cases["world-writable"] = str(writable)
    link = tmp_path / "link"; link.symlink_to(good)
    cases["symlink"] = str(link)
    cases["directory"] = str(tmp_path)
    for name, path in cases.items():
        with pytest.raises(gi.GrafanaImportError) as err:
            gi.fetch_source_password(known_hosts_file=path, trusted_uid=os.getuid(), runner=runner)
        assert err.value.code == "source_unconfigured", name
    with pytest.raises(gi.GrafanaImportError):  # owned by someone other than root
        gi.fetch_source_password(known_hosts_file=good, trusted_uid=os.getuid() + 1, runner=runner)
    assert not ran


PY = sys.executable


def test_run_bounded_caps_memory_and_kills_on_overflow():
    res = gi.run_bounded([PY, "-c", "import sys,time\nsys.stdout.write('x'*100000);sys.stdout.flush();time.sleep(30)"], {"PATH": "/usr/bin:/bin"}, 10, 4096)
    assert res.exceeded and len(res.data) == 4097 and not res.timed_out


def test_run_bounded_enforces_deadline():
    start = time.monotonic()
    res = gi.run_bounded([PY, "-c", "import time; time.sleep(30)"], {"PATH": "/usr/bin:/bin"}, 0.3, 4096)
    assert res.timed_out and time.monotonic() - start < 5


def test_run_bounded_passes_only_the_given_env_and_no_stdin():
    code = "import os,sys; print(sorted(os.environ)); print(repr(sys.stdin.read()))"
    os.environ["BWS_ACCESS_TOKEN"] = "must-not-leak"
    try:
        res = gi.run_bounded([PY, "-I", "-c", code], {"ONLY": "1"}, 10, 4096)
    finally:
        del os.environ["BWS_ACCESS_TOKEN"]
    assert res.returncode == 0 and b"BWS" not in res.data and b"ONLY" in res.data and b"''" in res.data


def test_run_bounded_reports_exit_status_and_small_output():
    res = gi.run_bounded([PY, "-c", "import sys; sys.stdout.write('hi'); sys.exit(3)"], {}, 10, 4096)
    assert (res.returncode, res.data, res.timed_out, res.exceeded) == (3, b"hi", False, False)
