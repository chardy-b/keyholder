from __future__ import annotations

from datetime import UTC, datetime
import http.server
import json
import ssl
import subprocess
import threading

import pytest

from keyholderd.providers.google_oauth import GoogleOAuthProvider
from keyholderd.server import PROVIDERS, ServerError, _issue_credential


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload
        self.text = "response-body"

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeSession:
    instances = []
    def __init__(self):
        self.trust_env = True
        self.calls = []
        self.closed = False
        self.response = FakeResponse(payload={"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 3600})
        self.__class__.instances.append(self)

    def post(self, **kwargs):
        self.calls.append(kwargs)
        return self.response

    def close(self):
        self.closed = True


def grant(**overrides):
    value = {"name": "calendar-read", "token_endpoint": "https://oauth2.googleapis.com/token"}
    value.update(overrides)
    return value


def secrets():
    return {"client_id": "client-sentinel", "client_secret": "secret-sentinel", "refresh_token": "refresh-sentinel"}


def test_successful_exchange_uses_bearer_environment_contract_and_closes(monkeypatch):
    FakeSession.instances.clear()
    monkeypatch.setattr("keyholderd.providers.google_oauth.requests.Session", FakeSession)
    cred = GoogleOAuthProvider().issue(grant(), secrets(), 900)
    session = FakeSession.instances[0]
    assert session.trust_env is False
    assert session.closed
    assert session.calls[0]["data"] == {"client_id":"client-sentinel", "client_secret":"secret-sentinel", "refresh_token":"refresh-sentinel", "grant_type":"refresh_token"}
    assert session.calls[0]["timeout"] == 15
    assert cred.env == {"GOOGLE_WORKSPACE_CLI_TOKEN": "test-access-token"}
    assert cred.token_type == "Bearer"
    assert cred.display_token == "test-access-token"
    remaining = (cred.expires_at - datetime.now(UTC)).total_seconds()
    assert 3500 < remaining < 3600


@pytest.mark.parametrize("payload", [ {}, {"access_token": 3}, {"access_token": ""}, {"access_token":"x", "token_type": "Basic", "expires_in":3600}, {"access_token":"x", "token_type":"Bearer"}, {"access_token":"x", "token_type":"Bearer", "expires_in": True}, {"access_token":"x", "token_type":"Bearer", "expires_in": float("nan")}, {"access_token":"x", "token_type":"Bearer", "expires_in": 1}, {"access_token":"x", "token_type":"Bearer", "expires_in": 999999999} ])
def test_malformed_response_is_rejected(monkeypatch, payload):
    session = FakeSession(); session.response = FakeResponse(payload=payload)
    monkeypatch.setattr("keyholderd.providers.google_oauth.requests.Session", lambda: session)
    with pytest.raises(ValueError):
        GoogleOAuthProvider().issue(grant(), secrets(), 900)
    assert session.closed


def test_http_failure_closes(monkeypatch):
    session = FakeSession(); session.response = FakeResponse(status=500, payload={})
    monkeypatch.setattr("keyholderd.providers.google_oauth.requests.Session", lambda: session)
    with pytest.raises(Exception):
        GoogleOAuthProvider().issue(grant(), secrets(), 900)
    assert session.closed


def test_provider_registered_and_invalid_endpoint_fails_before_secret_resolution(monkeypatch):
    assert isinstance(PROVIDERS["google_oauth"], GoogleOAuthProvider)
    called = False
    class Resolver:
        def resolve_refs(self, refs):
            nonlocal called
            called = True
            return secrets()
    monkeypatch.setattr("keyholderd.server._resolver", lambda config: Resolver())
    config = {"callers":{"hermes":{"uid_name":"hermes", "profiles":{"default":{"grants":[grant(provider="google_oauth", token_endpoint="http://proxy.invalid/token")]}}}}}
    with pytest.raises(ServerError, match="strict HTTPS"):
        _issue_credential(config, "hermes", "default", "calendar-read", None, "test")
    assert not called


@pytest.mark.parametrize("expires_in,accepted", [(119, False), (120, True)])
def test_adjusted_lifetime_has_meaningful_usable_boundary(monkeypatch, expires_in, accepted):
    session = FakeSession()
    session.response = FakeResponse(payload={"access_token": "x", "token_type": "Bearer", "expires_in": expires_in})
    monkeypatch.setattr("keyholderd.providers.google_oauth.requests.Session", lambda: session)
    if accepted:
        assert GoogleOAuthProvider().issue(grant(), secrets(), 900).env == {"GOOGLE_WORKSPACE_CLI_TOKEN": "x"}
    else:
        with pytest.raises(ValueError, match="usable"):
            GoogleOAuthProvider().issue(grant(), secrets(), 900)


@pytest.mark.parametrize("refs", [None, [], {}, {"client_id": "x"}, {"client_id": "x", "client_secret": " ", "refresh_token": "r"}, {"client_id": 1, "client_secret": "s", "refresh_token": "r"}])
def test_invalid_google_refs_fail_before_resolver(monkeypatch, refs):
    called = False
    class Resolver:
        def resolve_refs(self, _refs):
            nonlocal called
            called = True
            raise AssertionError("resolver must not be called")
    monkeypatch.setattr("keyholderd.server._resolver", lambda _config: Resolver())
    cfg = {"callers": {"hermes": {"uid_name": "hermes", "profiles": {"default": {"grants": [grant(provider="google_oauth", bitwarden_refs=refs)]}}}}}
    with pytest.raises(ServerError, match="bitwarden_refs"):
        _issue_credential(cfg, "hermes", "default", "calendar-read", None, "test")
    assert not called


@pytest.mark.parametrize("endpoint", [None, 3, "https://user:pass@example.test/token", "https://example.test/token?x=1", "https://example.test/token#x"])
def test_malformed_endpoint_fails_closed(endpoint):
    with pytest.raises(ValueError, match="strict HTTPS"):
        GoogleOAuthProvider.validate(grant(token_endpoint=endpoint))


def test_public_issue_path_uses_verified_https_and_audits_without_secrets(monkeypatch, tmp_path):
    cert = tmp_path / "localhost-ca.pem"
    key = tmp_path / "localhost-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
    received = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            from urllib.parse import parse_qs
            received.update(parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()))
            body = b'{"access_token":"access-sentinel","token_type":"Bearer","expires_in":3600}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    upstream = http.server.ThreadingHTTPServer(("localhost", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    upstream.socket = context.wrap_socket(upstream.socket, server_side=True)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()

    refs = {"client_id": "client-ref", "client_secret": "secret-ref", "refresh_token": "refresh-ref"}
    values = {"client_id": "client-sentinel", "client_secret": "secret-sentinel", "refresh_token": "refresh-sentinel"}

    class Resolver:
        def resolve_refs(self, actual):
            assert actual == refs
            return values

    def verified_session():
        session = requests.Session()
        session.verify = str(cert)
        return session

    import requests
    from keyholderd.server import handle_issue
    provider = GoogleOAuthProvider(session_factory=verified_session)
    monkeypatch.setattr("keyholderd.server._resolver", lambda _config: Resolver())
    monkeypatch.setitem(PROVIDERS, "google_oauth", provider)
    cfg = {"version": 1, "paths": {"leases_db": str(tmp_path / "leases.db"), "audit_log": str(tmp_path / "audit.jsonl")}, "callers": {"hermes": {"uid_name": "hermes", "profiles": {"default": {"grants": [grant(token_endpoint=f"https://localhost:{upstream.server_port}/token", provider="google_oauth", bitwarden_refs=refs, ttl_seconds=300, max_ttl_seconds=600)]}}}}}
    try:
        result = handle_issue(cfg, "hermes", {"grant": "calendar-read", "ttl_seconds": 300, "reason": "integration test"})
        assert result["provider"] == "google_oauth"
        assert result["token_type"] == "Bearer"
        assert result["access_token"] == "access-sentinel"
        assert result["lease_id"]
        assert result["scope_summary"] == "Google OAuth refresh-token grant"
        assert received == {"client_id": ["client-sentinel"], "client_secret": ["secret-sentinel"], "refresh_token": ["refresh-sentinel"], "grant_type": ["refresh_token"]}
        audit = (tmp_path / "audit.jsonl").read_text()
        events = [json.loads(line) for line in audit.splitlines()]
        issuance = next(event for event in events if event["event"] == "issue")
        assert issuance["provider"] == "google_oauth"
        assert issuance["grant"] == "calendar-read"
        assert issuance["lease_id"] == result["lease_id"]
        assert issuance["scope_summary"] == "Google OAuth refresh-token grant"
        for sentinel in (*values.values(), "access-sentinel"):
            assert sentinel not in audit
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
