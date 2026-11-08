import json
import os
import pwd
import shutil
import socket
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta

import bitwarden_sdk
import pytest

from keyholderd import cli, grafana_import as gi
from keyholderd.bitwarden import BwsResolver
from keyholderd.server import UnixHTTPServer
from bitwarden_sdk.schemas import SecretResponse
from test_bitwarden_import import FakeBitwardenInner, KEY, ORG, PROJECT, VALUE, create_commands

SOURCE_BYTES = (VALUE + "\n").encode()


class FileBackedInner(FakeBitwardenInner):
    """Keeps fake Bitwarden state in a file so it is shared with the forked worker."""

    def __init__(self, path):
        super().__init__()
        self.path = path
        self._save()

    def load(self):
        data = json.loads(open(self.path).read())
        self.secrets = {k: SecretResponse.from_dict(v) for k, v in data["secrets"].items()}
        self.commands = data["commands"]

    def _save(self):
        open(self.path, "w").write(json.dumps({"secrets": {k: v.to_dict() for k, v in self.secrets.items()}, "commands": self.commands}))

    def run_command(self, command_json):
        self.load()
        try:
            return super().run_command(command_json)
        finally:
            self._save()


@pytest.fixture
def env(tmp_path, monkeypatch):
    yield from build_env(tmp_path, monkeypatch, FakeBitwardenInner())


@pytest.fixture
def real_env(tmp_path, monkeypatch):
    monkeypatch.setattr(gi, "WORKER", gi._run_worker)
    yield from build_env(tmp_path, monkeypatch, FileBackedInner(str(tmp_path / "bw-state.json")))


def build_env(tmp_path, monkeypatch, inner):
    user = pwd.getpwuid(os.getuid()).pw_name
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("matrix-ubuntu ssh-ed25519 AAAA\n")
    os.chmod(known_hosts, 0o644)
    token_file = tmp_path / "token"
    token_file.write_text("0.fake:abc")
    sdk_client = bitwarden_sdk.BitwardenClient.__new__(bitwarden_sdk.BitwardenClient)
    sdk_client.inner = inner
    bws_calls, ssh_calls = [], []

    def bws_runner(cmd, **kwargs):
        bws_calls.append(cmd)
        assert cmd[:3] == ["bws", "project", "list"]
        return type("R", (), {"returncode": 0, "stdout": json.dumps([{"id": PROJECT, "name": "Grafana", "organizationId": ORG}]), "stderr": ""})()

    def ssh_runner(argv, env_, timeout, max_bytes):
        ssh_calls.append((argv, env_))
        return gi.BoundedResult(0, SOURCE_BYTES, False, False)

    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: BwsResolver(access_token_file=str(token_file), runner=bws_runner, sdk_login=lambda t: sdk_client))
    monkeypatch.setattr(gi, "SOURCE_FETCHER", lambda **kw: gi.fetch_source_password(runner=ssh_runner, known_hosts_file=str(known_hosts), trusted_uid=os.getuid(), **kw))
    expires = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    cfg = {
        "version": 1,
        "paths": {"leases_db": str(tmp_path / "leases.db"), "audit_log": str(tmp_path / "audit.jsonl")},
        "grafana_import": {"enabled": True, "project_id": PROJECT, "strip_single_trailing_newline": True},
        "callers": {"me": {"uid_name": user, "profiles": {"default": {"grants": [], "operations": [{"operation": "grafana_projects"}, {"operation": "grafana_import", "expires_at": expires}]}}}},
    }
    sock_dir = tempfile.mkdtemp(prefix="kh")  # pytest tmp paths can exceed the AF_UNIX limit
    sock = os.path.join(sock_dir, "s")
    httpd = UnixHTTPServer(sock, cfg)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield dict(sock=sock, cfg=cfg, inner=inner, bws_calls=bws_calls, ssh_calls=ssh_calls, audit=tmp_path / "audit.jsonl")
    httpd.shutdown()
    httpd.server_close()
    shutil.rmtree(sock_dir, ignore_errors=True)


def test_projects_then_import_then_idempotent_second_import(env, capsys):
    sock = env["sock"]
    assert cli.main(["--socket", sock, "grafana-projects"]) == 0
    assert capsys.readouterr().out == f"{PROJECT}  Grafana\n"
    assert not env["ssh_calls"]  # metadata never touches the source

    assert cli.main(["--socket", sock, "grafana-import"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert set(first) == {"id", "key", "project_id", "status_verified"}
    assert first["key"] == KEY and first["project_id"] == PROJECT and first["status_verified"] is True
    assert len(create_commands(env["inner"])) == 1
    assert env["inner"].secrets[first["id"]].value == VALUE  # trailing linefeed stripped (explicitly enabled)

    assert cli.main(["--socket", sock, "grafana-import"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert second == first
    assert len(create_commands(env["inner"])) == 1  # no duplicate

    argv, ssh_env = env["ssh_calls"][0]
    assert argv[0] == "/usr/bin/ssh" and "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv
    assert ssh_env == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    assert not any(VALUE in part for call in env["bws_calls"] for part in call)

    events = [json.loads(line) for line in env["audit"].read_text().splitlines()]
    assert [(e["operation"], e["phase"], e["reason"]) for e in events] == [
        ("grafana_projects", "attempt", "attempt"), ("grafana_projects", "completed", "listed"),
        ("grafana_import", "attempt", "attempt"), ("grafana_import", "completed", "created"),
        ("grafana_import", "attempt", "attempt"), ("grafana_import", "completed", "already_present"),
    ]
    assert VALUE not in env["audit"].read_text()
    out = capsys.readouterr()
    assert VALUE not in out.out + out.err


def test_hostile_requests_over_the_socket_are_rejected_without_echo(env):
    for payload in ({"value": "x"}, {"host": "evil.example", "path": "/etc/shadow"}, {"project_id": PROJECT}, {"command": ["id"]}, {"profile": "default", "key": "OTHER"}):
        with pytest.raises(RuntimeError, match="^invalid request$"):
            cli.request(env["sock"], "POST", "/v1/grafana-import", payload)
    assert not env["ssh_calls"] and not env["inner"].commands
    text = env["audit"].read_text()
    assert "evil.example" not in text and "/etc/shadow" not in text


def test_cli_rejects_extra_arguments_and_never_sends_them(env, capsys, monkeypatch):
    sent = []
    monkeypatch.setattr(cli, "request", lambda *a, **k: sent.append(a) or {})
    assert cli.main(["--socket", env["sock"], "grafana-import", "--value", "hunter2"]) == 2
    assert not sent and "takes no arguments" in capsys.readouterr().err


def test_unauthorized_caller_is_denied_and_audited(env, capsys):
    env["cfg"]["callers"]["me"]["profiles"]["default"]["operations"] = []
    assert cli.main(["--socket", env["sock"], "grafana-import"]) == 2
    assert "not authorized" in capsys.readouterr().err
    assert not env["ssh_calls"] and not env["inner"].commands
    assert json.loads(env["audit"].read_text())["reason"] == "not_authorized"


def test_issue_and_run_cannot_reach_the_operations(env):
    for route, body in (("/v1/issue", {"grant": "grafana_import", "reason": "x"}), ("/v1/run", {"grant": "grafana_import", "reason": "x", "command": ["id"], "env_var": "X"})):
        with pytest.raises(RuntimeError, match="not available"):
            cli.request(env["sock"], "POST", route, body)
    assert not env["ssh_calls"]


def test_differing_existing_value_surfaces_409_message_without_values(env, capsys):
    from test_bitwarden_import import secret_model
    existing = secret_model("55555555-5555-4555-8555-555555555555", value="someone-elses-value")
    env["inner"].secrets[str(existing.id)] = existing
    assert cli.main(["--socket", env["sock"], "grafana-import"]) == 2
    err = capsys.readouterr().err
    assert "explicit approval required" in err and "someone-elses-value" not in err and VALUE not in err
    assert not create_commands(env["inner"])


def test_full_path_through_a_real_forked_worker(real_env, capsys):
    sock, inner = real_env["sock"], real_env["inner"]
    assert cli.main(["--socket", sock, "grafana-projects"]) == 0
    assert capsys.readouterr().out == f"{PROJECT}  Grafana\n"
    assert cli.main(["--socket", sock, "grafana-import"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["key"] == KEY and first["status_verified"] is True
    inner.load()
    assert len(create_commands(inner)) == 1 and inner.secrets[first["id"]].value == VALUE
    assert cli.main(["--socket", sock, "grafana-import"]) == 0
    assert json.loads(capsys.readouterr().out) == first
    inner.load()
    assert len(create_commands(inner)) == 1  # second invocation: no create
    events = [json.loads(line) for line in real_env["audit"].read_text().splitlines()]
    assert [(e["operation"], e["phase"], e["reason"]) for e in events][-4:] == [
        ("grafana_import", "attempt", "attempt"), ("grafana_import", "completed", "created"),
        ("grafana_import", "attempt", "attempt"), ("grafana_import", "completed", "already_present"),
    ]
    assert VALUE not in real_env["audit"].read_text()


# --- raw-socket framing / body-deadline checks -------------------------------------------

def raw_exchange(sock_path, head, body=b"", *, trickle_to=None, trickle_gap=0.15, limit=5.0):
    """Send raw bytes over the Unix socket; return (status, json body, elapsed seconds)."""
    started = time.monotonic()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(limit)
    client.connect(sock_path)
    stop = threading.Event()

    def trickle():
        try:
            for _ in range(trickle_to or 0):
                if stop.is_set():
                    return
                client.sendall(b"x")
                time.sleep(trickle_gap)
        except OSError:
            pass

    client.sendall(head + body)
    worker = threading.Thread(target=trickle, daemon=True)
    worker.start()
    data = b""
    try:
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        stop.set()
        client.close()
    status_line, _, rest = data.partition(b"\r\n")
    payload = rest.partition(b"\r\n\r\n")[2]
    return int(status_line.split()[1]), json.loads(payload or b"{}"), time.monotonic() - started


def post(extra_headers, route="/v1/grafana-import"):
    return (f"POST {route} HTTP/1.1\r\nHost: localhost\r\n" + extra_headers + "\r\n").encode()


@pytest.mark.parametrize(
    "head,body",
    [
        (post("Content-Length: 2\r\nContent-Length: 2\r\n"), b"{}"),
        (post("Content-Length: 2\r\nContent-Length: 3\r\n"), b"{}"),
        (post("Transfer-Encoding: chunked\r\n"), b"2\r\n{}\r\n0\r\n\r\n"),
        (post("Content-Length: 2\r\nTransfer-Encoding: chunked\r\n"), b"{}"),
        (post("Content-Length: +2\r\n"), b"{}"),
        (post("Content-Length: -1\r\n"), b""),
        (post("Content-Length: 0x10\r\n"), b""),
        (post("Content-Length: 1e1\r\n"), b""),
        (post("Content-Length: 2, 2\r\n"), b"{}"),
        (post("Content-Length: 1025\r\n"), b""),
        (post("Content-Length: 99999999\r\n"), b""),
    ],
)
def test_malformed_framing_is_rejected_fixed_audited_and_triggers_nothing(env, head, body):
    status, payload, elapsed = raw_exchange(env["sock"], head, body)
    assert (status, payload) == (400, {"error": "invalid request"}) and elapsed < 3
    assert not env["ssh_calls"] and not env["inner"].commands and not env["bws_calls"]
    (event,) = [json.loads(line) for line in env["audit"].read_text().splitlines()]
    assert (event["phase"], event["reason"], event["profile"]) == ("denied", "invalid_request", "")


def test_missing_body_returns_within_the_body_deadline(env, monkeypatch):
    monkeypatch.setattr(gi, "BODY_READ_SECONDS", 0.4)
    status, payload, elapsed = raw_exchange(env["sock"], post("Content-Length: 10\r\n"))  # promised, never sent
    assert (status, payload) == (400, {"error": "invalid request"})
    assert 0.3 < elapsed < 3
    assert not env["ssh_calls"] and not env["inner"].commands
    assert json.loads(env["audit"].read_text())["reason"] == "invalid_request"


def test_trickled_body_hits_the_total_deadline_not_a_per_read_timeout(env, monkeypatch):
    monkeypatch.setattr(gi, "BODY_READ_SECONDS", 0.5)
    # one byte every 0.15s keeps any per-recv timeout alive; the total deadline must still fire
    status, payload, elapsed = raw_exchange(env["sock"], post("Content-Length: 100\r\n"), trickle_to=100)
    assert (status, payload) == (400, {"error": "invalid request"})
    assert elapsed < 3
    assert not env["ssh_calls"] and not env["inner"].commands


def test_well_framed_request_still_works_after_rejections(env):
    assert raw_exchange(env["sock"], post("Content-Length: 5\r\nContent-Length: 5\r\n"), b"{}")[0] == 400
    status, payload, _ = raw_exchange(env["sock"], post("Content-Length: 2\r\n", "/v1/grafana-projects"), b"{}")
    assert status == 200 and payload == {"projects": [{"id": PROJECT, "name": "Grafana"}]}
