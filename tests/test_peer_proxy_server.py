from __future__ import annotations

import http.client
import json
import os
import socket
import stat
import threading
from pathlib import Path

import pytest

from keyholderd import server
from keyholderd.proxy import ForwardResponse, forward_request


class FakeResolver:
    def __init__(self, secrets=None):
        self.secrets = secrets or {"upstream_api_key": "upstream-secret"}

    def resolve_refs(self, refs):
        return dict(self.secrets)


def policy(tmp_path, grants):
    return {
        "version": 1,
        "paths": {"audit_log": str(tmp_path / "audit.jsonl")},
        "proxy": {"request_timeout_seconds": 2, "unix_socket_mode": "0o640"},
        "callers": {"current": {"uid_name": "hermes", "profiles": {"default": {"grants": grants}}}},
    }


def grant(**overrides):
    value = {
        "name": "peer",
        "provider": "local_proxy",
        "authentication": "peercred",
        "upstream_base_url": "https://upstream.invalid",
        "allowed_routes": ["/v1/chat/completions"],
        "allowed_methods": ["POST"],
        "allowed_models": ["stealth/ox-alpha"],
        "bitwarden_refs": {},
    }
    value.update(overrides)
    return value


def request(socket_path: Path, body: bytes, headers=None):
    conn = http.client.HTTPConnection("localhost")
    conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.sock.connect(str(socket_path))
    conn.request("POST", "/v1/chat/completions", body=body, headers={"Content-Length": str(len(body)), **(headers or {})})
    response = conn.getresponse()
    payload = response.read()
    conn.close()
    return response.status, payload


def running_peer(tmp_path, grants, monkeypatch, sender=None):
    socket_path = tmp_path / "peer.sock"
    config = policy(tmp_path, grants)
    if sender is not None:
        def controlled(*args, **kwargs):
            kwargs["sender"] = sender
            return forward_request(*args, **kwargs)
        monkeypatch.setattr(server, "forward_request", controlled)
    srv = server.PeerProxyHTTPServer(str(socket_path), config, FakeResolver())
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread, socket_path, config


def stop(srv, thread):
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=2)


def test_peercred_unix_client_forwards_allowlisted_model(tmp_path, monkeypatch):
    seen = []
    class Response:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        content = b'{"ok":true}'
    def sender(**kwargs):
        seen.append(kwargs)
        return Response()
    srv, thread, path, config = running_peer(tmp_path, [grant()], monkeypatch, sender)
    try:
        status, body = request(path, b'{"model":"stealth/ox-alpha","messages":[]}')
        assert status == 200 and body == b'{"ok":true}'
        assert len(seen) == 1
        assert seen[0]["headers"]["Authorization"] == "Bearer upstream-secret"
    finally:
        stop(srv, thread)


def test_rejected_model_is_audited_once_and_not_forwarded(tmp_path, monkeypatch):
    sent = []
    def sender(**kwargs):
        sent.append(kwargs)
        pytest.fail("rejected request was forwarded")
    srv, thread, path, config = running_peer(tmp_path, [grant()], monkeypatch, sender)
    try:
        status, body = request(path, b'{"model":"other-model","capability":"capability-secret","secret":"secret-value"}')
        assert status == 400
        events = [json.loads(line) for line in Path(config["paths"]["audit_log"]).read_text().splitlines()]
        assert [event["event"] for event in events] == ["proxy_attempt", "proxy_rejected"]
        text = Path(config["paths"]["audit_log"]).read_text()
        assert all(value not in text for value in ("other-model", "stealth/ox-alpha", "capability-secret", "secret-value"))
        assert not sent
    finally:
        stop(srv, thread)


@pytest.mark.parametrize("grants", [[], [grant(authentication="capability")], [grant(), grant(name="peer-2")]])
def test_missing_or_ambiguous_peercred_grant_rejected(tmp_path, monkeypatch, grants):
    srv, thread, path, _ = running_peer(tmp_path, grants, monkeypatch)
    try:
        status, body = request(path, b'{"model":"stealth/ox-alpha"}')
        assert status == 403
        assert b"exactly one eligible" in body
    finally:
        stop(srv, thread)


def test_bearer_header_is_rejected(tmp_path, monkeypatch):
    srv, thread, path, _ = running_peer(tmp_path, [grant()], monkeypatch)
    try:
        status, body = request(path, b'{"model":"stealth/ox-alpha"}', {"Authorization": "Bearer leaked"})
        assert status == 403 and b"Authorization" in body
    finally:
        stop(srv, thread)


def test_socket_path_rejects_traversal_stale_and_non_socket(tmp_path):
    with pytest.raises(server.ServerError):
        server.PeerProxyHTTPServer(str(tmp_path / ".." / "bad.sock"), policy(tmp_path, []), FakeResolver())
    stale = tmp_path / "stale"
    stale.write_text("not a socket")
    with pytest.raises(server.ServerError):
        server.PeerProxyHTTPServer(str(stale), policy(tmp_path, []), FakeResolver())


def test_socket_mode_is_preserved(tmp_path):
    srv = server.PeerProxyHTTPServer(str(tmp_path / "peer.sock"), policy(tmp_path, []), FakeResolver())
    try:
        assert stat.S_IMODE(os.stat(srv.server_address).st_mode) == 0o640
    finally:
        srv.server_close()
        os.unlink(srv.server_address)


@pytest.mark.parametrize("value", [0o600, 0o660, "0600", "0o660"])
def test_socket_mode_accepts_safe_canonical_values(value):
    assert server.validate_unix_socket_mode(value) in {0o600, 0o660}


@pytest.mark.parametrize("value", [0o666, 0o777, "0666", "0777", "660", "0o66", "0O660", "garbage", True])
def test_socket_mode_rejects_unsafe_or_malformed_values(value):
    with pytest.raises(server.ServerError):
        server.validate_unix_socket_mode(value)


def test_socket_parent_rejects_group_writable_and_symlink_parents(tmp_path):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o700)
    unsafe.chmod(0o770)
    with pytest.raises(server.ServerError):
        server.PeerProxyHTTPServer(str(unsafe / "peer.sock"), policy(tmp_path, []), FakeResolver())
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(server.ServerError):
        server.PeerProxyHTTPServer(str(link / "peer.sock"), policy(tmp_path, []), FakeResolver())


def test_overlapping_requests_use_unique_internal_cleanup(tmp_path, monkeypatch):
    lease_ids = []
    entered = threading.Barrier(3)
    release = threading.Event()
    class Response:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        content = b"{}"
    def sender(**kwargs):
        entered.wait(timeout=2)
        release.wait(timeout=2)
        return Response()
    srv, thread, path, _ = running_peer(tmp_path, [grant()], monkeypatch, sender)
    original_register = server.PROVIDERS["local_proxy"].store.register
    def record_register(*args, **kwargs):
        lease_ids.append(kwargs["lease_id"])
        return original_register(*args, **kwargs)
    monkeypatch.setattr(server.PROVIDERS["local_proxy"].store, "register", record_register)
    try:
        results = []
        workers = [threading.Thread(target=lambda: results.append(request(path, b'{"model":"stealth/ox-alpha"}'))) for _ in range(2)]
        for worker in workers: worker.start()
        entered.wait(timeout=2)
        release.set()
        for worker in workers: worker.join(timeout=2)
        assert len(results) == len(lease_ids) == 2
        assert len(set(lease_ids)) == 2
    finally:
        stop(srv, thread)
