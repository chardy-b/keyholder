from __future__ import annotations

import json
import os
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import pytest
import requests

from keyholderd.server import handle_issue, handle_revoke


OAUTH = "oauth-access-sentinel"
CAPABILITY = "khcap_test-capability-sentinel"
CALLER_AUTH = "caller-auth-sentinel"
COOKIE = "caller-cookie-sentinel"
PROXY_AUTH = "caller-proxy-auth-sentinel"
FORWARDED = "caller-forwarded-sentinel"


class _GoogleHandler(BaseHTTPRequestHandler):
    requests_seen: list[dict[str, object]] = []

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.requests_seen.append({"path": self.path, "form": parse_qs(body.decode())})
        payload = json.dumps({"access_token": OAUTH, "token_type": "Bearer", "expires_in": 3600}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        self.requests_seen.append({"path": self.path, "headers": dict(self.headers)})
        payload = b'{"events":[{"id":"event-1"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def https_google_upstream(tmp_path: Path):
    cert, key = tmp_path / "localhost.pem", tmp_path / "localhost.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
        check=True,
        capture_output=True,
    )
    _GoogleHandler.requests_seen = []
    server = ThreadingHTTPServer(("localhost", 0), _GoogleHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, cert
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def _config(tmp_path: Path, token_endpoint: str) -> dict:
    return {"version": 1, "paths": {"leases_db": str(tmp_path / "leases.db"), "audit_log": str(tmp_path / "audit.jsonl")}, "callers": {"hermes": {"uid_name": os.environ.get("USER", "hermes"), "profiles": {"default": {"grants": [{"name": "calendar-proxy", "provider": "google_calendar_proxy", "template": "google-calendar-events-read", "token_endpoint": token_endpoint, "bitwarden_refs": {"client_id": "client-ref", "client_secret": "secret-ref", "refresh_token": "refresh-ref"}, "ttl_seconds": 60, "max_ttl_seconds": 120}]}}}}}


def _lifecycle(*args, **kwargs):
    from keyholderd.proxy import ProxyLifecycle
    return ProxyLifecycle(*args, **kwargs)


def test_real_proxy_lifecycle_issues_opaque_capability_and_exchanges_oauth_only_on_forward(tmp_path, https_google_upstream, monkeypatch):
    upstream, cert = https_google_upstream
    cfg = _config(tmp_path, f"https://localhost:{upstream.server_port}/token")
    from keyholderd import server
    monkeypatch.setattr(server, "_resolver", lambda _cfg: type("R", (), {"resolve_refs": lambda self, refs: {"client_id": "client-sentinel", "client_secret": "secret-sentinel", "refresh_token": "refresh-sentinel"}})())
    lifecycle = _lifecycle(cfg, upstream_origin=f"https://localhost:{upstream.server_port}", upstream_verify=str(cert))
    lifecycle.start()
    try:
        issued = handle_issue(cfg, "hermes", {"grant": "calendar-proxy", "ttl_seconds": 60, "reason": "e2e calendar read"})
        assert issued["token_type"] == "capability"
        assert issued["capability"].startswith("khcap_") and issued["capability"] != CAPABILITY
        assert not _GoogleHandler.requests_seen
        response = requests.get(f"http://{lifecycle.host}:{lifecycle.port}/calendar/v3/calendars/primary/events?maxResults=5", headers={"Authorization": f"Bearer {issued['capability']}"}, timeout=5)
        assert response.status_code == 200 and response.json()["events"][0]["id"] == "event-1"
        assert _GoogleHandler.requests_seen[-1]["headers"]["Authorization"] == f"Bearer {OAUTH}"
    finally:
        lifecycle.stop()


def test_proxy_strips_caller_credentials_and_forwarded_headers(tmp_path, https_google_upstream):
    upstream, cert = https_google_upstream
    cfg = _config(tmp_path, f"https://localhost:{upstream.server_port}/token")
    lifecycle = _lifecycle(cfg, upstream_origin=f"https://localhost:{upstream.server_port}", upstream_verify=str(cert), token_resolver=lambda _item: OAUTH)
    lifecycle.start()
    try:
        capability = lifecycle.issue_for_test("hermes", "calendar-proxy", 60)
        response = requests.get(f"http://{lifecycle.host}:{lifecycle.port}/calendar/v3/calendars/primary/events", headers={"Authorization": f"Bearer {capability}", "Cookie": COOKIE, "Proxy-Authorization": PROXY_AUTH, "X-Forwarded-For": FORWARDED, "X-Forwarded-Host": FORWARDED, "X-Forwarded-Proto": FORWARDED}, timeout=5)
        assert response.status_code == 200
        headers = _GoogleHandler.requests_seen[-1]["headers"]
        assert headers["Authorization"] == f"Bearer {OAUTH}"
        for name in ("Cookie", "Proxy-Authorization", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"):
            assert name not in headers
    finally:
        lifecycle.stop()


@pytest.mark.parametrize("method,path", [("POST", "/calendar/v3/calendars/primary/events"), ("GET", "/wrong"), ("GET", "/calendar/v3/calendars/primary/events?bad=1")])
def test_proxy_denies_wrong_method_route_and_query(tmp_path, https_google_upstream, method, path):
    upstream, cert = https_google_upstream
    lifecycle = _lifecycle(_config(tmp_path, f"https://localhost:{upstream.server_port}/token"), upstream_origin=f"https://localhost:{upstream.server_port}", upstream_verify=str(cert), token_resolver=lambda _item: OAUTH)
    lifecycle.start()
    try:
        token = lifecycle.issue_for_test("hermes", "calendar-proxy", 60)
        response = requests.request(method, f"http://{lifecycle.host}:{lifecycle.port}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=5)
        assert response.status_code in (403, 405)
    finally:
        lifecycle.stop()


def test_revoke_denies_existing_capability_and_audit_has_metadata_only(tmp_path, https_google_upstream):
    upstream, cert = https_google_upstream
    cfg = _config(tmp_path, f"https://localhost:{upstream.server_port}/token")
    lifecycle = _lifecycle(cfg, upstream_origin=f"https://localhost:{upstream.server_port}", upstream_verify=str(cert), token_resolver=lambda _item: OAUTH)
    lifecycle.start()
    try:
        token, lease_id = lifecycle.issue_for_test("hermes", "calendar-proxy", 60, with_lease=True)
        assert handle_revoke(cfg, "hermes", {"lease_id": lease_id, "reason": "done"})["revoked"]
        denied = requests.get(f"http://{lifecycle.host}:{lifecycle.port}{'/calendar/v3/calendars/primary/events'}", headers={"Authorization": f"Bearer {token}"}, timeout=5)
        assert denied.status_code == 403
        audit = (tmp_path / "audit.jsonl").read_text()
        assert "issue" in audit and "revoke" in audit
        for sentinel in (OAUTH, CAPABILITY, CALLER_AUTH, COOKIE, PROXY_AUTH, FORWARDED):
            assert sentinel not in audit
    finally:
        lifecycle.stop()


def test_proxy_rejects_non_loopback_bind_and_shutdown_releases_listener(tmp_path, https_google_upstream):
    upstream, cert = https_google_upstream
    with pytest.raises(ValueError):
        _lifecycle(_config(tmp_path, f"https://localhost:{upstream.server_port}/token"), bind="0.0.0.0", upstream_origin=f"https://localhost:{upstream.server_port}", upstream_verify=str(cert))
    lifecycle = _lifecycle(_config(tmp_path, f"https://localhost:{upstream.server_port}/token"), upstream_origin=f"https://localhost:{upstream.server_port}", upstream_verify=str(cert))
    lifecycle.start(); port = lifecycle.port; lifecycle.stop()
    with pytest.raises((ConnectionError, requests.RequestException)):
        requests.get(f"http://127.0.0.1:{port}/", timeout=1)


def test_handle_revoke_waits_for_inflight_forward_before_returning(tmp_path, https_google_upstream):
    upstream, cert = https_google_upstream
    cfg = _config(tmp_path, f"https://localhost:{upstream.server_port}/token")
    entered = threading.Event(); release = threading.Event()

    def resolver(_item):
        entered.set(); assert release.wait(5); return OAUTH

    lifecycle = _lifecycle(cfg, upstream_origin=f"https://localhost:{upstream.server_port}", upstream_verify=str(cert), token_resolver=resolver)
    lifecycle.start()
    try:
        token, lease_id = lifecycle.issue_for_test("hermes", "calendar-proxy", 60, with_lease=True)
        forward = threading.Thread(target=lambda: requests.get(f"http://{lifecycle.host}:{lifecycle.port}/calendar/v3/calendars/primary/events", headers={"Authorization": f"Bearer {token}"}, timeout=5))
        forward.start(); assert entered.wait(5)
        result: list[dict] = []
        revoke = threading.Thread(target=lambda: result.append(handle_revoke(cfg, "hermes", {"lease_id": lease_id, "reason": "race-test"})))
        revoke.start(); assert revoke.is_alive()
        release.set(); forward.join(5); revoke.join(5)
        assert not forward.is_alive() and not revoke.is_alive() and result == [{"revoked": True, "lease_id": lease_id}]
        denied = requests.get(f"http://{lifecycle.host}:{lifecycle.port}/calendar/v3/calendars/primary/events", headers={"Authorization": f"Bearer {token}"}, timeout=5)
        assert denied.status_code == 403 and len(_GoogleHandler.requests_seen) == 1
    finally:
        lifecycle.stop()



def test_real_listener_denies_expired_capability_without_resolver_or_upstream(tmp_path, https_google_upstream):
    upstream, cert = https_google_upstream
    resolver_calls = []
    cfg = _config(tmp_path, f"https://localhost:{upstream.server_port}/token")
    lifecycle = _lifecycle(cfg, upstream_origin=f"https://localhost:{upstream.server_port}", upstream_verify=str(cert), token_resolver=lambda item: resolver_calls.append(item) or OAUTH)
    lifecycle.start()
    try:
        token = lifecycle.issue_for_test("hermes", "calendar-proxy", 1)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and lifecycle.store.lookup(token)["expires"].timestamp() > time.time():
            time.sleep(0.01)
        assert lifecycle.store.lookup(token)["expires"].timestamp() <= time.time()
        response = requests.get(f"http://{lifecycle.host}:{lifecycle.port}/calendar/v3/calendars/primary/events", headers={"Authorization": f"Bearer {token}"}, timeout=5)
        assert response.status_code == 403 and resolver_calls == [] and _GoogleHandler.requests_seen == []
    finally:
        lifecycle.stop()


def test_serve_wires_production_lifecycle_and_closes_it_on_shutdown(tmp_path, https_google_upstream, monkeypatch):
    upstream, cert = https_google_upstream
    cfg = _config(tmp_path, f"https://localhost:{upstream.server_port}/token")
    cfg["google_calendar_proxy"] = {"enabled": True, "bind": "127.0.0.1", "port": 0}
    config_path = tmp_path / "policy.yaml"
    config_path.write_text(json.dumps(cfg))
    from keyholderd import server
    monkeypatch.setattr(server, "_resolver", lambda _cfg: type("R", (), {"resolve_refs": lambda self, refs: {"client_id": "client-sentinel", "client_secret": "secret-sentinel", "refresh_token": "refresh-sentinel"}})())
    made = []
    def factory(config, proxy_cfg):
        lifecycle = _lifecycle(config, bind=proxy_cfg["bind"], port=proxy_cfg["port"], upstream_origin=f"https://localhost:{upstream.server_port}", upstream_verify=str(cert), token_resolver=lambda _item: OAUTH)
        made.append(lifecycle)
        return lifecycle
    monkeypatch.setattr(server, "_create_proxy_lifecycle", factory)
    ready, stop = threading.Event(), threading.Event()
    thread = threading.Thread(target=server.serve, args=(str(config_path), str(tmp_path / "keyholder.sock")), kwargs={"_ready": ready, "_stop": stop}, daemon=True)
    thread.start(); assert ready.wait(5) and made
    lifecycle = made[0]
    try:
        issued = handle_issue(cfg, "hermes", {"grant": "calendar-proxy", "ttl_seconds": 60, "reason": "serve integration"})
        response = requests.get(f"http://{lifecycle.host}:{lifecycle.port}/calendar/v3/calendars/primary/events", headers={"Authorization": f"Bearer {issued['capability']}"}, timeout=5)
        assert response.status_code == 200
        assert handle_revoke(cfg, "hermes", {"lease_id": issued["lease_id"], "reason": "done"})["revoked"]
        assert requests.get(f"http://{lifecycle.host}:{lifecycle.port}/calendar/v3/calendars/primary/events", headers={"Authorization": f"Bearer {issued['capability']}"}, timeout=5).status_code == 403
    finally:
        stop.set(); thread.join(5)
    assert not thread.is_alive() and lifecycle.server is None
    with pytest.raises((ConnectionError, requests.RequestException)):
        requests.get(f"http://{lifecycle.host}:{lifecycle.port}/", timeout=1)
