from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import io
import json
import socket
import threading
import time

import pytest

from keyholderd import server
from keyholderd.leases import LeaseStore
from keyholderd.providers.local_proxy import LocalProxyProvider
from keyholderd.proxy import (
    CapabilityStore,
    ProxyAuthorizationError,
    ProxyConfigurationError,
    ProxyHTTPServer,
    ProxyRequestError,
    ProxyUpstreamError,
    _forward_headers,
    address_family_for_host,
    forward_request,
    read_exact_body,
    validated_content_length,
    validated_header_items,
    validate_peercred_chat_body,
)


def test_capability_authorizes_configured_method_and_route():
    store = CapabilityStore()
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    store.register(
        token="khcap_test",
        lease_id="lease_test",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_methods": ["POST"],
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=expires_at,
    )

    capability = store.authorize("khcap_test", "POST", "/v1/chat/completions")

    assert capability.lease_id == "lease_test"
    assert capability.upstream_base_url == "https://api.example.test"
    assert capability.upstream_api_key == "real-secret"
    assert capability.expires_at == expires_at


@pytest.mark.parametrize("body", [b"{}", b'{"model": 1}', b'{"model": "other"}'])
def test_peercred_chat_body_rejects_missing_non_string_or_disallowed_model(body):
    with pytest.raises(ProxyRequestError, match="model"):
        validate_peercred_chat_body(body, ["stealth/ox-alpha"])


def test_peercred_chat_body_permits_exactly_configured_model():
    validate_peercred_chat_body(
        b'{"model":"stealth/ox-alpha","messages":[]}',
        ["stealth/ox-alpha"],
    )


@pytest.mark.parametrize("allowed_models", [None, [], "stealth/ox-alpha", ["stealth/ox-alpha", 1]])
def test_peercred_grant_requires_non_empty_string_model_allowlist(allowed_models):
    grant = {
        "authentication": "peercred",
        "upstream_base_url": "https://api.example.test",
        "allowed_routes": ["/v1/chat/completions"],
        "allowed_models": allowed_models,
    }
    with pytest.raises(ProxyConfigurationError, match="allowed_models"):
        CapabilityStore().register(
            token="khcap_peercred_bad_models",
            lease_id="lease_peercred_bad_models",
            grant=grant,
            secrets={"upstream_api_key": "real-secret"},
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


def test_peercred_grant_rejects_disallowed_model_before_forwarding():
    store = CapabilityStore()
    store.register(
        token="khcap_peercred_forward",
        lease_id="lease_peercred_forward",
        grant={
            "authentication": "peercred",
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
            "allowed_models": ["stealth/ox-alpha"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    sender_called = False

    def sender(**kwargs):
        nonlocal sender_called
        sender_called = True
        return None

    with pytest.raises(ProxyRequestError, match="model"):
        forward_request(
            store,
            token="khcap_peercred_forward",
            method="POST",
            target="/v1/chat/completions",
            headers={"Content-Type": "application/json"},
            body=b'{"model":"other"}',
            sender=sender,
        )
    assert sender_called is False


def test_existing_capability_grant_does_not_require_model_allowlist():
    CapabilityStore().register(
        token="khcap_existing",
        lease_id="lease_existing",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def test_unknown_capability_is_rejected():
    with pytest.raises(ProxyAuthorizationError, match="invalid capability"):
        CapabilityStore().authorize("khcap_missing", "POST", "/v1/chat/completions")


def test_plain_http_upstream_requires_explicit_opt_in():
    with pytest.raises(ProxyConfigurationError, match="HTTPS"):
        CapabilityStore().register(
            token="khcap_http_upstream",
            lease_id="lease_http_upstream",
            grant={
                "upstream_base_url": "http://api.example.test",
                "allowed_routes": ["/v1/chat/completions"],
            },
            secrets={"upstream_api_key": "real-secret"},
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


def test_plain_http_upstream_requires_exact_boolean_opt_in():
    for opt_in in (False, "false", 1, None):
        with pytest.raises(ProxyConfigurationError, match="allow_insecure_http|HTTPS"):
            CapabilityStore().register(
                token="khcap_http_upstream_typed",
                lease_id="lease_http_upstream_typed",
                grant={
                    "upstream_base_url": "http://api.example.test",
                    "allow_insecure_http": opt_in,
                    "allowed_routes": ["/v1/chat/completions"],
                },
                secrets={"upstream_api_key": "real-secret"},
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )


@pytest.mark.parametrize(
    ("content_lengths", "transfer_encoding", "message"),
    [
        (["-1"], None, "non-negative"),
        (["1", "1"], None, "exactly one"),
        (["abc"], None, "decimal"),
        (["1"], "chunked", "Transfer-Encoding"),
    ],
)
def test_request_body_framing_rejects_ambiguous_or_unsafe_lengths(
    content_lengths, transfer_encoding, message
):
    with pytest.raises(ProxyRequestError, match=message):
        validated_content_length(
            content_lengths,
            transfer_encoding=transfer_encoding,
            max_body_bytes=1024,
        )


def test_request_body_framing_accepts_one_bounded_decimal_length():
    assert validated_content_length(
        ["12"], transfer_encoding=None, max_body_bytes=1024
    ) == 12
    assert validated_content_length(
        [], transfer_encoding=None, max_body_bytes=1024
    ) == 0


def test_request_body_must_match_declared_length():
    assert read_exact_body(io.BytesIO(b"abc"), 3) == b"abc"
    with pytest.raises(ProxyRequestError, match="shorter"):
        read_exact_body(io.BytesIO(b"ab"), 3)


def test_connection_nominated_headers_are_not_forwarded():
    assert _forward_headers(
        {
            "Connection": "X-Remove, keep-alive",
            "X-Remove": "attacker-controlled",
            "X-Keep": "safe",
        }
    ) == {"X-Keep": "safe"}


def test_duplicate_request_headers_are_rejected_before_collapsing():
    with pytest.raises(ProxyRequestError, match="duplicate Authorization"):
        validated_header_items(
            [("Authorization", "Bearer one"), ("authorization", "Bearer two")]
        )


@pytest.mark.parametrize(
    "grant",
    [
        {"upstream_base_url": "https:///missing-host", "allowed_routes": ["/v1"]},
        {"upstream_base_url": "https://user@api.example/v1", "allowed_routes": ["/v1"]},
        {"upstream_base_url": "https://api.example/v1?q=1", "allowed_routes": ["/v1"]},
        {"upstream_base_url": "https://api.example:99999", "allowed_routes": ["/v1"]},
        {"upstream_base_url": "https://api.example", "allowed_routes": []},
        {"upstream_base_url": "https://api.example", "allowed_routes": "v1"},
        {"upstream_base_url": "https://api.example", "allowed_routes": ["relative"]},
        {"upstream_base_url": "https://api.example", "allowed_routes": ["/v1?q=1"]},
        {"upstream_base_url": "https://api.example", "allowed_routes": ["//evil"]},
        {"upstream_base_url": "https://api.example", "allowed_routes": ["/v1"], "allowed_methods": "POST"},
        {"upstream_base_url": "https://api.example", "allowed_routes": ["/v1"], "allowed_methods": ["HEAD"]},
    ],
)
def test_unsafe_proxy_grant_configuration_is_rejected(grant):
    with pytest.raises(ProxyConfigurationError):
        CapabilityStore().register(
            token="khcap_bad_config",
            lease_id="lease_bad_config",
            grant=grant,
            secrets={"upstream_api_key": "real-secret"},
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


def test_non_http_upstream_scheme_is_rejected_even_with_insecure_opt_in():
    with pytest.raises(ProxyConfigurationError, match="HTTP or HTTPS"):
        CapabilityStore().register(
            token="khcap_file_upstream",
            lease_id="lease_file_upstream",
            grant={
                "upstream_base_url": "file:///etc/passwd",
                "allow_insecure_http": True,
                "allowed_routes": ["/v1/chat/completions"],
            },
            secrets={"upstream_api_key": "real-secret"},
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


def test_capability_rejects_unconfigured_method_or_route():
    store = CapabilityStore()
    store.register(
        token="khcap_test",
        lease_id="lease_test",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_methods": ["POST"],
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    with pytest.raises(ProxyAuthorizationError, match="method is not allowed"):
        store.authorize("khcap_test", "DELETE", "/v1/chat/completions")
    with pytest.raises(ProxyAuthorizationError, match="route is not allowed"):
        store.authorize("khcap_test", "POST", "/v1/models")


def test_expired_capability_is_rejected_and_removed():
    store = CapabilityStore()
    store.register(
        token="khcap_expired",
        lease_id="lease_expired",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )

    with pytest.raises(ProxyAuthorizationError, match="capability expired"):
        store.authorize("khcap_expired", "POST", "/v1/chat/completions")
    with pytest.raises(ProxyAuthorizationError, match="invalid capability"):
        store.authorize("khcap_expired", "POST", "/v1/chat/completions")


def test_expired_capabilities_can_be_swept_without_a_request():
    store = CapabilityStore()
    store.register(
        token="khcap_sweep",
        lease_id="lease_sweep",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )

    assert store.purge_expired() == 1
    with pytest.raises(ProxyAuthorizationError, match="invalid capability"):
        store.authorize("khcap_sweep", "POST", "/v1/chat/completions")


def test_revoking_lease_removes_its_capability():
    store = CapabilityStore()
    store.register(
        token="khcap_revoked",
        lease_id="lease_revoked",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    store.revoke_lease("lease_revoked")

    with pytest.raises(ProxyAuthorizationError, match="invalid capability"):
        store.authorize("khcap_revoked", "POST", "/v1/chat/completions")


def test_forward_request_replaces_capability_with_upstream_authorization():
    store = CapabilityStore()
    store.register(
        token="khcap_forward",
        lease_id="lease_forward",
        grant={
            "upstream_base_url": "https://api.example.test/base",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    captured = {}

    class Response:
        status_code = 201
        headers = {"Content-Type": "application/json", "Connection": "close"}
        content = b'{"ok":true}'

    def sender(**kwargs):
        captured.update(kwargs)
        return Response()

    response = forward_request(
        store,
        token="khcap_forward",
        method="POST",
        target="/v1/chat/completions?stream=false",
        headers={
            "Authorization": "Bearer khcap_forward",
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Host": "127.0.0.1:8787",
        },
        body=b'{"model":"test"}',
        sender=sender,
    )

    assert captured == {
        "method": "POST",
        "url": "https://api.example.test/base/v1/chat/completions?stream=false",
        "headers": {
            "Content-Type": "application/json",
            "Authorization": "Bearer real-secret",
        },
        "data": b'{"model":"test"}',
        "timeout": 30,
        "allow_redirects": False,
        "stream": True,
    }
    assert response.status == 201
    assert response.headers == {"Content-Type": "application/json"}
    assert response.body == b'{"ok":true}'


def test_default_upstream_sender_ignores_ambient_proxy_environment(monkeypatch):
    observed: dict[str, str] = {}

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            del format, args

        def do_POST(self):
            observed["authorization"] = self.headers.get("Authorization", "")
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    store = CapabilityStore()
    store.register(
        token="khcap_no_env_proxy",
        lease_id="lease_no_env_proxy",
        grant={
            "upstream_base_url": f"http://127.0.0.1:{upstream.server_address[1]}",
            "allow_insecure_http": True,
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")

    try:
        response = forward_request(
            store,
            token="khcap_no_env_proxy",
            method="POST",
            target="/v1/chat/completions",
            headers={},
            body=b"{}",
        )
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)

    assert response.status == 200
    assert response.body == b'{"ok":true}'
    assert observed["authorization"] == "Bearer real-secret"


def test_real_trickling_upstream_is_interrupted_at_total_deadline():
    class SlowUpstream(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            del format, args

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(200)
            self.send_header("Content-Length", "10")
            self.end_headers()
            try:
                for _ in range(10):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.1)
            except OSError:
                pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), SlowUpstream)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    store = CapabilityStore()
    store.register(
        token="khcap_real_deadline",
        lease_id="lease_real_deadline",
        grant={
            "upstream_base_url": f"http://127.0.0.1:{upstream.server_address[1]}",
            "allow_insecure_http": True,
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    started = time.monotonic()
    try:
        with pytest.raises(ProxyUpstreamError, match="deadline"):
            forward_request(
                store,
                token="khcap_real_deadline",
                method="POST",
                target="/v1/chat/completions",
                headers={},
                body=b"{}",
                upstream_timeout_seconds=0.2,
            )
    finally:
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=5)

    assert time.monotonic() - started < 0.7


def test_forward_request_rejects_oversized_upstream_response():
    store = CapabilityStore()
    store.register(
        token="khcap_large_response",
        lease_id="lease_large_response",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    class Response:
        status_code = 200
        headers = {"Content-Length": "5"}
        content = b"12345"

        def close(self):
            pass

    with pytest.raises(ProxyUpstreamError, match="too large"):
        forward_request(
            store,
            token="khcap_large_response",
            method="POST",
            target="/v1/chat/completions",
            headers={},
            body=b"{}",
            sender=lambda **_kwargs: Response(),
            max_response_bytes=4,
        )


def test_forward_request_audits_upstream_failure(tmp_path):
    store = CapabilityStore()
    store.register(
        token="khcap_failure",
        lease_id="lease_failure",
        grant={
            "name": "proxy-failure",
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        caller="hermes",
        profile="default",
    )
    audit_path = tmp_path / "audit.jsonl"

    with pytest.raises(OSError, match="offline"):
        forward_request(
            store,
            token="khcap_failure",
            method="POST",
            target="/v1/chat/completions",
            headers={},
            body=b"{}",
            sender=lambda **_kwargs: (_ for _ in ()).throw(OSError("offline")),
            audit_path=str(audit_path),
        )

    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert [event["event"] for event in events] == ["proxy_attempt", "proxy_failed"]
    assert events[0]["caller"] == "hermes"
    assert events[0]["grant"] == "proxy-failure"
    assert "real-secret" not in audit_path.read_text()
    assert "khcap_failure" not in audit_path.read_text()


def test_absolute_form_request_target_is_rejected_before_dispatch():
    store = CapabilityStore()
    store.register(
        token="khcap_target",
        lease_id="lease_target",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    called = False

    def sender(**_kwargs):
        nonlocal called
        called = True

    with pytest.raises(ProxyRequestError, match="origin-form"):
        forward_request(
            store,
            token="khcap_target",
            method="POST",
            target="https://evil.example/v1/chat/completions",
            headers={},
            body=b"{}",
            sender=sender,
        )
    assert called is False


def test_revoke_waits_until_an_authorized_dispatch_finishes():
    store = CapabilityStore()
    store.register(
        token="khcap_race",
        lease_id="lease_race",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    entered_sender = threading.Event()
    release_sender = threading.Event()
    revoke_done = threading.Event()

    class Response:
        status_code = 200
        headers = {}
        content = b"{}"

    def sender(**_kwargs):
        entered_sender.set()
        assert release_sender.wait(2)
        return Response()

    forward_thread = threading.Thread(
        target=lambda: forward_request(
            store,
            token="khcap_race",
            method="POST",
            target="/v1/chat/completions",
            headers={},
            body=b"{}",
            sender=sender,
        )
    )
    forward_thread.start()
    assert entered_sender.wait(2)
    revoke_thread = threading.Thread(
        target=lambda: (store.revoke_lease("lease_race"), revoke_done.set())
    )
    revoke_thread.start()
    assert not revoke_done.wait(0.1)
    release_sender.set()
    forward_thread.join(timeout=2)
    revoke_thread.join(timeout=2)
    assert revoke_done.is_set()
    with pytest.raises(ProxyAuthorizationError, match="invalid capability"):
        store.authorize("khcap_race", "POST", "/v1/chat/completions")


def test_slow_dispatch_does_not_block_unrelated_capability():
    store = CapabilityStore()
    for token, lease_id in (("khcap_slow", "lease_slow"), ("khcap_other", "lease_other")):
        store.register(
            token=token,
            lease_id=lease_id,
            grant={
                "upstream_base_url": "https://api.example.test",
                "allowed_routes": ["/v1/chat/completions"],
            },
            secrets={"upstream_api_key": "real-secret"},
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    entered_sender = threading.Event()
    release_sender = threading.Event()

    class Response:
        status_code = 200
        headers = {}
        content = b"{}"

    def slow_sender(**_kwargs):
        entered_sender.set()
        assert release_sender.wait(2)
        return Response()

    forward_thread = threading.Thread(
        target=lambda: forward_request(
            store,
            token="khcap_slow",
            method="POST",
            target="/v1/chat/completions",
            headers={},
            body=b"{}",
            sender=slow_sender,
        )
    )
    forward_thread.start()
    assert entered_sender.wait(2)
    unrelated_done = threading.Event()
    unrelated_thread = threading.Thread(
        target=lambda: (
            store.authorize("khcap_other", "POST", "/v1/chat/completions"),
            unrelated_done.set(),
        )
    )
    unrelated_thread.start()
    try:
        assert unrelated_done.wait(0.2)
    finally:
        release_sender.set()
        forward_thread.join(timeout=2)
        unrelated_thread.join(timeout=2)


def test_issuing_local_proxy_grant_activates_capability(tmp_path, monkeypatch):
    provider = LocalProxyProvider()
    monkeypatch.setitem(server.PROVIDERS, "local_proxy", provider)

    class Resolver:
        def resolve_refs(self, refs):
            assert refs == {"upstream_api_key": "secret-ref"}
            return {"upstream_api_key": "real-secret"}

    monkeypatch.setattr(server, "_resolver", lambda config: Resolver())
    config = {
        "version": 1,
        "paths": {
            "leases_db": str(tmp_path / "leases.db"),
            "audit_log": str(tmp_path / "audit.jsonl"),
        },
        "callers": {
            "hermes": {
                "uid_name": "hermes",
                "profiles": {
                    "default": {
                        "grants": [
                            {
                                "name": "openrouter-proxy",
                                "provider": "local_proxy",
                                "ttl_seconds": 60,
                                "max_ttl_seconds": 60,
                                "upstream_base_url": "https://api.example.test",
                                "allowed_routes": ["/v1/chat/completions"],
                                "bitwarden_refs": {"upstream_api_key": "secret-ref"},
                            }
                        ]
                    }
                },
            }
        },
    }

    issued = server.handle_issue(
        config,
        "hermes",
        {"grant": "openrouter-proxy", "reason": "proxy test"},
    )
    capability = provider.store.authorize(
        issued["access_token"], "POST", "/v1/chat/completions"
    )

    assert capability.lease_id == issued["lease_id"]
    assert capability.upstream_api_key == "real-secret"


def test_invalid_local_proxy_grant_does_not_create_orphan_lease(tmp_path, monkeypatch):
    provider = LocalProxyProvider()
    monkeypatch.setitem(server.PROVIDERS, "local_proxy", provider)

    class Resolver:
        def resolve_refs(self, _refs):
            return {"upstream_api_key": "real-secret"}

    monkeypatch.setattr(server, "_resolver", lambda _config: Resolver())
    lease_db = tmp_path / "leases.db"
    config = {
        "version": 1,
        "paths": {
            "leases_db": str(lease_db),
            "audit_log": str(tmp_path / "audit.jsonl"),
        },
        "callers": {
            "hermes": {
                "uid_name": "hermes",
                "profiles": {
                    "default": {
                        "grants": [
                            {
                                "name": "broken-proxy",
                                "provider": "local_proxy",
                                "ttl_seconds": 60,
                                "max_ttl_seconds": 60,
                                "allowed_routes": ["/v1/chat/completions"],
                                "bitwarden_refs": {"upstream_api_key": "secret-ref"},
                            }
                        ]
                    }
                },
            }
        },
    }

    with pytest.raises(ProxyConfigurationError):
        server.handle_issue(
            config,
            "hermes",
            {"grant": "broken-proxy", "reason": "must fail safely"},
        )

    assert not lease_db.exists()


def test_server_revoke_deactivates_local_proxy_capability(tmp_path, monkeypatch):
    provider = LocalProxyProvider()
    monkeypatch.setitem(server.PROVIDERS, "local_proxy", provider)
    config = {
        "paths": {
            "leases_db": str(tmp_path / "leases.db"),
            "audit_log": str(tmp_path / "audit.jsonl"),
        }
    }
    lease = LeaseStore(config["paths"]["leases_db"]).create_lease(
        "hermes", "default", "proxy", "local_proxy", 60, "proxy test"
    )
    provider.store.register(
        token="khcap_server_revoke",
        lease_id=lease.lease_id,
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=lease.expires_at,
    )

    server.handle_revoke(
        config,
        "hermes",
        {"lease_id": lease.lease_id, "reason": "done"},
    )

    with pytest.raises(ProxyAuthorizationError, match="invalid capability"):
        provider.store.authorize(
            "khcap_server_revoke", "POST", "/v1/chat/completions"
        )


def test_server_revoke_rejects_a_different_caller(tmp_path):
    config = {
        "paths": {
            "leases_db": str(tmp_path / "leases.db"),
            "audit_log": str(tmp_path / "audit.jsonl"),
        }
    }
    lease = LeaseStore(config["paths"]["leases_db"]).create_lease(
        "hermes", "default", "proxy", "local_proxy", 60, "proxy test"
    )

    with pytest.raises(server.ServerError, match="does not belong to caller"):
        server.handle_revoke(
            config,
            "other-user",
            {"lease_id": lease.lease_id, "reason": "not mine"},
        )

    assert LeaseStore(config["paths"]["leases_db"]).get_lease(lease.lease_id).revoked_at is None


def test_proxy_http_server_forwards_authorized_request_and_audits(tmp_path):
    store = CapabilityStore()
    store.register(
        token="khcap_http",
        lease_id="lease_http",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    captured = {}
    audit_path = tmp_path / "audit.jsonl"

    class UpstreamResponse:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        content = b'{"forwarded":true}'

    def sender(**kwargs):
        attempt = json.loads(audit_path.read_text().splitlines()[0])
        assert attempt["event"] == "proxy_attempt"
        captured.update(kwargs)
        return UpstreamResponse()

    proxy_server = ProxyHTTPServer(
        ("127.0.0.1", 0),
        store=store,
        audit_path=str(audit_path),
        sender=sender,
    )
    thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(
            "127.0.0.1", proxy_server.server_address[1], timeout=5
        )
        connection.request(
            "POST",
            "/v1/chat/completions",
            body=b'{"model":"test"}',
            headers={
                "Authorization": "Bearer khcap_http",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        response_body = response.read()
    finally:
        proxy_server.shutdown()
        proxy_server.server_close()
        thread.join(timeout=5)

    assert response.status == 200
    assert response_body == b'{"forwarded":true}'
    assert captured["headers"]["Authorization"] == "Bearer real-secret"
    audit_events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert [event["event"] for event in audit_events] == [
        "proxy_attempt",
        "proxy_complete",
    ]
    assert audit_events[0]["lease_id"] == "lease_http"
    assert audit_events[0]["route"] == "/v1/chat/completions"
    assert "real-secret" not in audit_path.read_text()
    assert "khcap_http" not in audit_path.read_text()


def test_proxy_http_server_audits_denied_request(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    proxy_server = ProxyHTTPServer(
        ("127.0.0.1", 0),
        store=CapabilityStore(),
        audit_path=str(audit_path),
    )
    thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    thread.start()
    try:
        for method in ("POST", "OPTIONS", "PROPFIND", "post"):
            connection = http.client.HTTPConnection(
                "127.0.0.1", proxy_server.server_address[1], timeout=5
            )
            connection.request(method, "/v1/chat/completions", body=b"{}")
            response = connection.getresponse()
            response.read()
            assert response.status == 401
            connection.close()
    finally:
        proxy_server.shutdown()
        proxy_server.server_close()
        thread.join(timeout=5)

    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert [event["event"] for event in events] == ["proxy_denied"] * 4
    assert all(event["route"] == "/v1/chat/completions" for event in events)


def test_proxy_http_server_emits_one_terminal_failure_event(tmp_path):
    store = CapabilityStore()
    store.register(
        token="khcap_http_failure",
        lease_id="lease_http_failure",
        grant={
            "upstream_base_url": "https://api.example.test",
            "allowed_routes": ["/v1/chat/completions"],
        },
        secrets={"upstream_api_key": "real-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    audit_path = tmp_path / "audit.jsonl"
    proxy_server = ProxyHTTPServer(
        ("127.0.0.1", 0),
        store=store,
        audit_path=str(audit_path),
        sender=lambda **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(
            "127.0.0.1", proxy_server.server_address[1], timeout=5
        )
        connection.request(
            "POST",
            "/v1/chat/completions",
            body=b"{}",
            headers={"Authorization": "Bearer khcap_http_failure"},
        )
        response = connection.getresponse()
        response.read()
    finally:
        proxy_server.shutdown()
        proxy_server.server_close()
        thread.join(timeout=5)

    assert response.status == 502
    events = [json.loads(line)["event"] for line in audit_path.read_text().splitlines()]
    assert events == ["proxy_attempt", "proxy_failed"]


def test_proxy_listener_requires_explicit_enablement():
    assert server.proxy_listener_enabled({}) is False
    assert server.proxy_listener_enabled({"proxy": {}}) is False
    assert server.proxy_listener_enabled({"proxy": {"enabled": False}}) is False
    assert server.proxy_listener_enabled({"proxy": {"enabled": True}}) is True


def test_proxy_listener_selects_address_family_for_loopback_host():
    assert address_family_for_host("127.0.0.1") == socket.AF_INET
    assert address_family_for_host("::1") == socket.AF_INET6


def test_downstream_request_has_total_deadline(tmp_path):
    proxy_server = ProxyHTTPServer(
        ("127.0.0.1", 0),
        store=CapabilityStore(),
        audit_path=str(tmp_path / "audit.jsonl"),
        request_timeout_seconds=0.3,
    )
    thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    thread.start()
    client = socket.create_connection(("127.0.0.1", proxy_server.server_address[1]), timeout=2)
    closed = False
    try:
        client.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nX-Slow: ")
        for _ in range(10):
            time.sleep(0.05)
            try:
                client.sendall(b"x")
            except OSError:
                closed = True
                break
        if not closed:
            client.settimeout(0.1)
            try:
                closed = client.recv(1) == b""
            except OSError:
                closed = False
    finally:
        client.close()
        proxy_server.shutdown()
        proxy_server.server_close()
        thread.join(timeout=5)

    assert closed is True


def test_daemon_builds_proxy_listener_from_policy(tmp_path, monkeypatch):
    provider = LocalProxyProvider()
    monkeypatch.setitem(server.PROVIDERS, "local_proxy", provider)
    config = {
        "proxy": {
            "host": "127.0.0.1",
            "port": 0,
            "max_body_bytes": 4096,
            "max_response_bytes": 8192,
            "max_workers": 3,
            "request_timeout_seconds": 7,
            "upstream_timeout_seconds": 9,
        },
        "paths": {"audit_log": str(tmp_path / "audit.jsonl")},
    }

    proxy_server = server.create_proxy_server(config)
    try:
        assert proxy_server.server_address[0] == "127.0.0.1"
        assert proxy_server.server_address[1] > 0
        assert proxy_server.store is provider.store
        assert proxy_server.max_body_bytes == 4096
        assert proxy_server.max_response_bytes == 8192
        assert proxy_server.max_workers == 3
        assert proxy_server.request_timeout_seconds == 7
        assert proxy_server.upstream_timeout_seconds == 9
    finally:
        proxy_server.server_close()
