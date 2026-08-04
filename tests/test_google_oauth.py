from __future__ import annotations

from datetime import UTC, datetime

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
