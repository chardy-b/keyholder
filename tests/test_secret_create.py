from __future__ import annotations

import hashlib
import json
import logging
import mmap
import os
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import bitwarden_sdk
import pytest

from keyholderd import cli, secret_create as sc, server
from keyholderd.bitwarden import BwsResolver
from keyholderd.policy import PolicyError, get_grant
from test_bitwarden_import import FakeBitwardenInner, ORG, PROJECT, create_commands, secret_model
from test_grafana_import_e2e import post, raw_exchange

KEY = "HERMES_EXAMPLE"
VALUE = hashlib.sha256(b"keyholder-test-only").hexdigest()
REASON = "synthetic-private-reason"
GENERATOR = [sys.executable, "-c", "import hashlib,sys;sys.stdout.write(hashlib.sha256(b'keyholder-test-only').hexdigest()+'\\n')"]


def policy(tmp_path):
    return {
        "version": 1,
        "paths": {"audit_log": str(tmp_path / "audit.jsonl"), "leases_db": str(tmp_path / "leases.db")},
        "proxy": {"enabled": True},  # writer must ignore even an enabled proxy
        "callers": {"me": {"uid_name": pwd.getpwuid(os.getuid()).pw_name, "profiles": {"default": {
            "grants": [{"name": "fake", "provider": "fake", "ttl_seconds": 30}],
            "secret_creates": [{"name": "hermes-generated", "project_id": PROJECT, "organization_id": ORG, "key_prefix": "HERMES_"}],
        }}}},
    }


def body(**extra):
    return json.dumps({"grant": "hermes-generated", "key": KEY, "value": VALUE, "reason": REASON, **extra}).encode()


def argv(sock=None, *, command=None, key=KEY, profile="default"):
    return (["--socket", sock] if sock else []) + ["create-secret", "--grant", "hermes-generated", "--key", key, "--reason", REASON, "--profile", profile, "--"] + (GENERATOR if command is None else command)


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = policy(tmp_path)
    creds = tmp_path / "credentials"
    creds.mkdir()
    (creds / sc.CREDENTIAL_NAME).write_text("synthetic-writer-token")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    inner = FakeBitwardenInner()
    client = bitwarden_sdk.BitwardenClient.__new__(bitwarden_sdk.BitwardenClient)
    client.inner = inner
    monkeypatch.setattr(sc, "RESOLVER_FACTORY", lambda path: BwsResolver(access_token_file=path, sdk_login=lambda token: client))
    # In-process launcher for inspectable fake state; real worker exercised below.
    monkeypatch.setattr(sc, "LAUNCHER", lambda fn, timeout, limit: ("ok", json.dumps(fn()).encode()))
    with tempfile.TemporaryDirectory(prefix="kh") as directory:
        sock = str(Path(directory) / "s")
        httpd = server.UnixHTTPServer(sock, cfg, secret_writer_only=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield SimpleNamespace(sock=sock, cfg=cfg, inner=inner, httpd=httpd, audit=tmp_path / "audit.jsonl", creds=creds)
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=3)


def test_generator_unix_daemon_real_sdk_protocol_and_no_leaks(env, capsys, caplog):
    with caplog.at_level(logging.DEBUG):
        assert cli.main(argv(env.sock)) == 0
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result == {"id": "44444444-4444-4444-8444-444444444444", "key": KEY}
    assert output.err == ""
    assert env.inner.secrets[result["id"]].value == VALUE
    (create,) = create_commands(env.inner)
    assert create["secrets"]["create"] == {"key": KEY, "value": VALUE, "note": sc.NOTE, "organizationId": ORG, "projectIds": [PROJECT]}
    assert env.inner.commands[-1] == {"secrets": {"get": {"id": result["id"]}}}
    events = [json.loads(line) for line in env.audit.read_text().splitlines()]
    assert [(e["phase"], e["reason"]) for e in events] == [("attempt", "attempt"), ("completed", "created")]
    for forbidden in (VALUE, REASON, KEY, "synthetic-writer-token"):
        assert forbidden not in env.audit.read_text() + caplog.text
    assert VALUE not in output.out + output.err
    assert not Path(env.cfg["paths"]["leases_db"]).exists()


def test_real_cli_process_generator_socket_and_forked_sdk_worker(env, monkeypatch, capfd):
    # Shared anonymous memory records verification without persisting any value.
    with mmap.mmap(-1, 32) as observed:
        original = env.inner.run_command

        def noisy_sdk(command_json):
            command = json.loads(command_json)
            os.write(1, VALUE.encode())
            os.write(2, VALUE.encode())
            if "create" in command.get("secrets", {}):
                assert command["secrets"]["create"]["value"] == VALUE
                assert command["secrets"]["create"]["note"] == sc.NOTE
                assert VALUE not in os.environ.values()
            response = original(command_json)
            if "get" in command.get("secrets", {}):
                assert json.loads(response)["data"]["value"] == VALUE
                observed[:8] = b"verified"
            return response

        monkeypatch.setattr(env.inner, "run_command", noisy_sdk)
        monkeypatch.setattr(sc, "LAUNCHER", sc.run_forked)
        child = subprocess.run([sys.executable, "-m", "keyholderd.cli", *argv(env.sock)], capture_output=True, text=True, timeout=10)
        assert child.returncode == 0, child.stderr
        assert json.loads(child.stdout)["key"] == KEY
        assert child.stderr == ""
        assert observed[:8] == b"verified"
    captured = capfd.readouterr()
    assert VALUE not in child.stdout + child.stderr + captured.out + captured.err + env.audit.read_text()


@pytest.mark.parametrize("key,profile,change", [
    ("OTHER_EXAMPLE", "default", None),
    ("HERMES_", "default", None),
    (KEY, "other", None),
    (KEY, "default", "caller"),
    (KEY, "default", "grant"),
])
def test_denied_or_outside_prefix_never_contacts_backend(env, key, profile, change, capsys):
    if change == "caller":
        env.cfg["callers"]["me"]["uid_name"] = "someone-else"
    if change == "grant":
        env.cfg["callers"]["me"]["profiles"]["default"]["secret_creates"] = []
    assert cli.main(argv(env.sock, key=key, profile=profile)) == 2
    assert not env.inner.commands
    output = capsys.readouterr()
    assert output.out == "" and VALUE not in output.err and REASON not in env.audit.read_text()


@pytest.mark.parametrize("existing_value", [VALUE, "different-synthetic-value"])
def test_existing_key_conflicts_without_fetch_or_equality_oracle(env, existing_value, capsys):
    existing = secret_model("55555555-5555-4555-8555-555555555555", key=KEY, value=existing_value)
    env.inner.secrets[str(existing.id)] = existing
    assert cli.main(argv(env.sock)) == 2
    assert "already exists" in capsys.readouterr().err
    assert not create_commands(env.inner)
    assert not any("get" in c.get("secrets", {}) for c in env.inner.commands)
    assert env.inner.secrets[str(existing.id)].value == existing_value


@pytest.mark.parametrize("program,message", [
    ("import sys;print('private-output');sys.exit(1)", "generator failed"),
    ("print('x'*4097)", "exceeds 4096"),
    ("import os;os.write(1,b'\\xff')", "not valid UTF-8"),
    ("import os;os.write(1,b'a\\x00b')", "contains NUL"),
    ("print()", "empty"),
    ("import time;time.sleep(5)", "timed out"),
    ("import os,time;os.close(1);time.sleep(5)", "timed out"),
])
def test_bad_generator_never_sends(env, program, message, monkeypatch, capsys):
    monkeypatch.setattr(cli, "GENERATOR_TIMEOUT_SECONDS", 0.15)
    started = time.monotonic()
    assert cli.main(argv(env.sock, command=[sys.executable, "-c", program])) == 2
    assert time.monotonic() - started < 2
    output = capsys.readouterr()
    assert output.out == "" and message in output.err and "private-output" not in output.err
    assert not env.inner.commands and not env.audit.exists()


@pytest.mark.parametrize("data,raw,expected", [(b"a\n\n", False, "a\n"), (b"a\r\n", False, "a\r"), (b"a\n", True, "a\n"), (b"a" * 4096, False, "a" * 4096)])
def test_exact_value_semantics(data, raw, expected):
    def runner(*args):
        return cli.BoundedResult(0, data, False, False)
    assert cli.generate_value(["trusted"], raw=raw, runner=runner) == expected


@pytest.mark.parametrize("payload", [
    {"project_id": PROJECT}, {"token": "private-token"}, {"command": ["id"]},
    {"value": ""}, {"value": "a" * 4097}, {"value": "\x00"}, {"value": "\ud800"}, {"reason": "\ud800"},
])
def test_malformed_body_fixed_error_no_backend(env, payload):
    status, raw = cli._post_create(env.sock, body(**payload))
    assert (status, json.loads(raw)) == (400, {"error": "invalid request"})
    assert not env.inner.commands
    assert VALUE not in env.audit.read_text()


def test_duplicate_fields_and_ambiguous_framing_rejected(env, monkeypatch):
    malformed = b'{"grant":"hermes-generated","grant":"other","value":"private"}'
    assert cli._post_create(env.sock, malformed) == (400, b'{"error": "invalid request"}')
    for headers, payload in [
        ("Content-Length: 2\r\nContent-Length: 2\r\n", b"{}"),
        ("Transfer-Encoding: chunked\r\n", b"0\r\n\r\n"),
        ("Content-Length: 32769\r\n", b""),
    ]:
        status, response, _ = raw_exchange(env.sock, post(headers, sc.ROUTE), payload)
        assert (status, response) == (400, {"error": "invalid request"})
    monkeypatch.setattr(sc, "BODY_READ_SECONDS", 0.2)
    status, response, elapsed = raw_exchange(env.sock, post("Content-Length: 20\r\n", sc.ROUTE), trickle_to=20, trickle_gap=0.07)
    assert (status, response) == (400, {"error": "invalid request"}) and elapsed < 1
    assert not env.inner.commands


@pytest.mark.parametrize("status,response", [
    (200, {"id": "44444444-4444-4444-8444-444444444444", "key": KEY, "value": VALUE}),
    (200, {"id": VALUE, "key": KEY}),
    (200, {"id": "44444444-4444-4444-8444-444444444444", "key": "OTHER"}),
    (500, {"error": VALUE}), (400, {"error": []}),
])
def test_unsafe_daemon_reply_never_printed(monkeypatch, capsys, status, response):
    monkeypatch.setattr(cli, "_post_create", lambda *args: (status, json.dumps(response).encode()))
    assert cli.main(argv()) == 2
    output = capsys.readouterr()
    assert output.out == "" and VALUE not in output.err and "no valid reply" in output.err


def test_duplicate_and_oversized_replies_rejected():
    for raw in [b'{"error":"private","error":"private"}', VALUE.encode() * 200]:
        with pytest.raises(cli.CreateSecretError, match="no_reply"):
            cli.validate_create_reply(500, raw, KEY)


@pytest.mark.parametrize("arguments", [
    ["create-secret", "--value", VALUE],
    ["create-secret", "--grant", VALUE],
    ["--socket", "create-secret", "--value", VALUE],
    ["--unexpected", "create-secret", VALUE],
])
def test_malformed_cli_arguments_are_fixed_and_private(arguments, capsys):
    assert cli.main(arguments) == 2
    output = capsys.readouterr()
    assert output.out == "" and VALUE not in output.err and "invalid create-secret arguments" in output.err


def test_default_writer_socket_ignores_ambient_main_socket(monkeypatch, capsys):
    paths = []
    monkeypatch.setenv("KEYHOLDER_SOCKET", "/run/keyholder/keyholder.sock")
    def response(path, body):
        paths.append(path)
        return 200, json.dumps({"id": "44444444-4444-4444-8444-444444444444", "key": KEY}).encode()
    monkeypatch.setattr(cli, "_post_create", response)
    assert cli.main(argv()) == 0
    assert cli.main(argv("explicit-test-socket")) == 0
    assert paths == [cli.DEFAULT_CREATE_SOCKET, "explicit-test-socket"]
    capsys.readouterr()


def test_separate_credential_no_read_token_fallback(env, monkeypatch, capsys):
    (env.creds / sc.CREDENTIAL_NAME).unlink()
    (env.creds / "bws-access-token").write_text("private-read-token")
    monkeypatch.setenv("BWS_ACCESS_TOKEN_FILE", str(env.creds / "bws-access-token"))
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "private-ambient-token")
    assert cli.main(argv(env.sock)) == 2
    assert "not configured" in capsys.readouterr().err
    assert not env.inner.commands


@pytest.mark.parametrize("failure,expected", [("list", "nothing was written"), ("create", "outcome unknown"), ("get", "nothing was written")])
def test_sdk_failure_is_fixed_and_private(env, failure, expected, capsys, caplog):
    env.inner.fail = {failure}
    assert cli.main(argv(env.sock)) == 2
    output = capsys.readouterr()
    assert expected in output.err
    assert VALUE not in output.out + output.err + caplog.text + env.audit.read_text()
    assert not any(set(c.get("secrets", {})) & {"update", "delete"} for c in env.inner.commands)


def test_readback_failure_is_ambiguous_and_never_retried_or_rolled_back(env, capsys):
    env.inner.get_override = secret_model("44444444-4444-4444-8444-444444444444", key=KEY, value="wrong")
    assert cli.main(argv(env.sock)) == 2
    assert "outcome unknown" in capsys.readouterr().err
    assert len(create_commands(env.inner)) == 1
    assert not any(set(c.get("secrets", {})) & {"update", "delete"} for c in env.inner.commands)


def test_audit_failure_blocks_write(env, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise OSError(VALUE)
    monkeypatch.setattr(sc, "write_audit_event", fail)
    assert cli.main(argv(env.sock)) == 2
    assert "audit log unavailable" in capsys.readouterr().err
    assert not env.inner.commands


@pytest.mark.parametrize("outcome", ["timeout", "overflow"])
def test_worker_deadline_or_loss_is_ambiguous(env, monkeypatch, capsys, outcome):
    monkeypatch.setattr(sc, "LAUNCHER", lambda *args: (outcome, VALUE.encode()))
    assert cli.main(argv(env.sock)) == 2
    output = capsys.readouterr()
    assert "may exist" in output.err and VALUE not in output.err
    assert not env.inner.commands


def test_normal_server_does_not_expose_create_and_writer_denies_all_other_routes(env):
    env.httpd.secret_writer_only = False
    status, response, _ = raw_exchange(env.sock, post(f"Content-Length: {len(body())}\r\n", sc.ROUTE), body())
    assert (status, response) == (404, {"error": "not found"})
    assert cli.request(env.sock, "GET", "/v1/grants")["grants"][0]["name"] == "fake"
    env.httpd.secret_writer_only = True
    for method, route in [("GET", "/v1/grants"), ("GET", sc.ROUTE)] + [("POST", r) for r in ["/v1/run", "/v1/issue", "/v1/revoke", "/v1/grafana-import", "/v1/grafana-projects", "/unknown"]]:
        with pytest.raises(RuntimeError, match="^not found$"):
            cli.request(env.sock, method, route)
    assert not env.inner.commands


def test_create_entries_cannot_issue_or_run_and_keyholder_peer_is_denied(env, monkeypatch):
    caller = env.cfg["callers"]["me"]["uid_name"]
    with pytest.raises(PolicyError):
        get_grant(env.cfg, caller, "default", "hermes-generated")
    # Even mistakenly authorizing the main daemon's UID cannot bridge the boundary.
    env.cfg["callers"]["me"]["uid_name"] = "keyholder"
    monkeypatch.setattr(server, "uid_to_name", lambda uid: "keyholder")
    assert cli._post_create(env.sock, body()) == (403, b'{"error": "not authorized"}')
    assert not env.inner.commands


def test_writer_startup_disables_proxy_and_uses_exclusive_dispatch(tmp_path, monkeypatch):
    seen = []
    class TestServer:
        def __init__(self, socket_path, config, **kwargs):
            seen.append(kwargs)
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def serve_forever(self): pass
    monkeypatch.setattr(server.os, "getuid", lambda: 12345)
    monkeypatch.setattr(server.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="dedicated-writer"))
    monkeypatch.setattr(server, "load_policy", lambda path: policy(tmp_path))
    monkeypatch.setattr(server, "UnixHTTPServer", TestServer)
    monkeypatch.setattr(server.os, "chmod", lambda *args: None)
    monkeypatch.setattr(server, "create_proxy_server", lambda cfg: pytest.fail("writer started proxy"))
    server.serve("synthetic-policy", "synthetic-socket", secret_writer_only=True)
    assert seen == [{"secret_writer_only": True}]


@pytest.mark.parametrize("uid,name", [(0, "root"), (12345, "keyholder")])
def test_writer_refuses_main_or_root_identity(uid, name, monkeypatch):
    monkeypatch.setattr(server.os, "getuid", lambda: uid)
    monkeypatch.setattr(server.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name=name))
    with pytest.raises(server.ServerError, match="dedicated non-root"):
        server.serve("never-read-policy", "never-open-socket", secret_writer_only=True)


def test_writer_cli_defaults_are_separate(monkeypatch):
    calls = []
    monkeypatch.setattr(server, "configure_logging", lambda *args: None)
    monkeypatch.setattr(server, "serve", lambda *args, **kwargs: calls.append((args, kwargs)))
    assert server.main(["--secret-writer-only"]) == 0
    assert calls == [(("/etc/keyholder-secret-writer/policy.yaml", "/run/keyholder-secret-writer/keyholder.sock", None), {"secret_writer_only": True})]


def test_transport_exception_and_unavailable_socket_are_private(env, monkeypatch, capsys):
    assert cli.main(argv(env.sock + ".missing")) == 2
    output = capsys.readouterr()
    assert output.out == "" and "nothing was sent" in output.err and env.sock not in output.err
    def fail(*args):
        raise RuntimeError(VALUE)
    monkeypatch.setattr(cli, "_post_create", fail)
    assert cli.main(argv()) == 2
    output = capsys.readouterr()
    assert output.out == "" and VALUE not in output.err and "may exist" in output.err


@pytest.mark.parametrize("reply", [
    {"ok": True, "result": {"id": VALUE, "key": KEY, "created": True}},
    {"ok": True, "result": {"id": "44444444-4444-4444-8444-444444444444", "key": KEY, "created": False}},
    {"ok": False, "code": VALUE},
])
def test_unsafe_worker_replies_are_fixed_and_ambiguous(env, monkeypatch, capsys, reply):
    monkeypatch.setattr(sc, "LAUNCHER", lambda *args: ("ok", json.dumps(reply).encode()))
    assert cli.main(argv(env.sock)) == 2
    output = capsys.readouterr()
    assert output.out == "" and VALUE not in output.err and "may exist" in output.err
    assert VALUE not in env.audit.read_text()


def test_opt_in_packaging_keeps_main_credential_boundary():
    import configparser
    from keyholderd.policy import load_policy
    root = Path(__file__).resolve().parents[1]
    unit = configparser.ConfigParser(interpolation=None)
    unit.read(root / "packaging/keyholder-secret-writer.service")
    service = unit["Service"]
    assert service["User"] == service["Group"] == "keyholder-secret-writer"
    assert service["SupplementaryGroups"] == "keyholder-clients"
    assert service["LogsDirectoryMode"] == "0750" and service["UMask"] == "0077"
    assert service["LoadCredentialEncrypted"] == "bws-create-access-token:/etc/keyholder-secret-writer/bws-create-access-token.cred"
    assert "--secret-writer-only" in service["ExecStart"]
    assert "bws-create" not in (root / "packaging/keyholder.service").read_text()
    assert "secret-writer" not in (root / "packaging/install.sh").read_text()
    cfg = load_policy(str(root / "packaging/secret-writer.policy.example.yaml"))
    grant = sc.find_grant(cfg, "example-agent", "default", "hermes-generated")
    assert grant.project_id == PROJECT and grant.key_prefix == "HERMES_"


def test_worker_real_timeout_and_overflow_are_bounded():
    started = time.monotonic()
    assert sc.run_forked(lambda: time.sleep(2) or {}, 0.1, 4096) == ("timeout", b"")
    assert time.monotonic() - started < 1
    assert sc.run_forked(lambda: {"value": "x" * 8192}, 1, 128) == ("overflow", b"")
