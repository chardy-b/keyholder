from __future__ import annotations

from datetime import UTC, datetime
import http.server
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


@pytest.mark.parametrize("expires_in,accepted", [(60, False), (61, True)])
def test_adjusted_lifetime_has_strictly_usable_boundary(monkeypatch, expires_in, accepted):
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


def test_real_https_session_exchange_and_form_parameters(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
    received = {}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            from urllib.parse import parse_qs
            received.update(parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()))
            body = b'{"access_token":"https-access","token_type":"Bearer","expires_in":3600}'
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *_args): pass
    server = http.server.ThreadingHTTPServer(("localhost", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        provider = GoogleOAuthProvider()
        original = provider
        import keyholderd.providers.google_oauth as module
        real_session = module.requests.Session
        def session():
            s = real_session(); s.verify = str(cert); return s
        module.requests.Session = session
        try:
            cred = original.issue(grant(token_endpoint=f"https://localhost:{server.server_port}/token"), secrets(), 900)
        finally:
            module.requests.Session = real_session
        assert received == {"client_id": ["client-sentinel"], "client_secret": ["secret-sentinel"], "refresh_token": ["refresh-sentinel"], "grant_type": ["refresh_token"]}
        assert cred.display_token == "https-access"
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def test_server_google_issue_audit_contains_no_secret_sentinels(monkeypatch, tmp_path):
    refs = {"client_id": "client-ref", "client_secret": "secret-ref", "refresh_token": "refresh-ref"}
    values = {"client_id": "client-sentinel", "client_secret": "secret-sentinel", "refresh_token": "refresh-sentinel"}
    class Resolver:
        def resolve_refs(self, actual):
            assert actual == refs
            return values
    class Session(FakeSession):
        def __init__(self):
            super().__init__(); self.response = FakeResponse(payload={"access_token": "access-sentinel", "token_type": "Bearer", "expires_in": 3600})
    monkeypatch.setattr("keyholderd.server._resolver", lambda _config: Resolver())
    monkeypatch.setattr("keyholderd.providers.google_oauth.requests.Session", Session)
    cfg = {"paths": {"leases_db": str(tmp_path / "leases.db"), "audit_log": str(tmp_path / "audit.jsonl")}, "callers": {"hermes": {"uid_name": "hermes", "profiles": {"default": {"grants": [grant(provider="google_oauth", bitwarden_refs=refs)]}}}}}
    _issue_credential(cfg, "hermes", "default", "calendar-read", None, "test")
    text = (tmp_path / "audit.jsonl").read_text()
    for sentinel in (*values.values(), "access-sentinel"):
        assert sentinel not in text
