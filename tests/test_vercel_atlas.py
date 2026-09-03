from __future__ import annotations

import http.client
import json
import threading
from datetime import UTC, datetime, timedelta

import pytest

from keyholderd import server
from keyholderd.providers.local_proxy import LocalProxyProvider
from keyholderd.proxy import (
    CapabilityStore,
    ForwardResponse,
    ProxyConfigurationError,
    ProxyHTTPServer,
    ProxyRequestError,
    ProxyUpstreamError,
    _bind_vercel_project_id,
    _normalize_vercel_response,
    _vercel_operation,
    forward_request,
    validated_proxy_grant,
)


def vercel_grant() -> dict:
    return {
        "name": "vercel-atlas-control",
        "provider": "local_proxy",
        "upstream_base_url": "https://api.vercel.com",
        "operation_profile": "vercel_atlas",
        "allowed_methods": ["POST"],
        "allowed_routes": ["/v1/vercel"],
        "bitwarden_refs": {"upstream_api_key": "key:vercel-team-token"},
    }


def registered_store() -> CapabilityStore:
    store = CapabilityStore()
    store.register(
        token="khcap_vercel",
        lease_id="lease_vercel",
        grant=vercel_grant(),
        secrets={"upstream_api_key": "parent-secret"},
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        caller="hermes",
        profile="default",
        grant_name="vercel-atlas-control",
    )
    return store


def operation(payload: dict):
    return _vercel_operation(json.dumps(payload).encode())


def test_vercel_profile_requires_exact_origin_route_method_and_secret_ref() -> None:
    for field, value in (
        ("upstream_base_url", "https://evil.example"),
        ("allowed_methods", ["GET", "POST"]),
        ("allowed_routes", ["/v1/vercel", "/v1/extra"]),
        ("bitwarden_refs", {"upstream_api_key": "key:x", "other": "key:y"}),
    ):
        grant = vercel_grant()
        grant[field] = value
        with pytest.raises(ProxyConfigurationError, match="vercel_atlas"):
            validated_proxy_grant(grant, {"upstream_api_key": "placeholder"})


def test_create_project_derives_fixed_safe_payload() -> None:
    translated = operation({"operation": "create_project", "project_name": "atlas-rally-notes"})
    assert translated.method == "POST"
    assert translated.target == "/v11/projects"
    assert json.loads(translated.body) == {
        "name": "atlas-rally-notes",
        "framework": "nextjs",
        "gitRepository": {"type": "github", "repo": "chardy-b/atlas-rally-notes"},
    }
    assert translated.operation == "create_project"
    assert translated.resource == "atlas-rally-notes"


def test_each_operation_maps_to_a_fixed_endpoint() -> None:
    assert operation({"operation": "get_project", "project_name": "atlas-x"}).target == "/v10/projects?search=atlas-x"
    assert operation({"operation": "add_domain", "project_name": "atlas-x", "domain": "x.chezchardin.com"}).target == "/v10/projects/atlas-x/domains"
    assert operation({"operation": "list_domains", "project_name": "atlas-x"}).target == "/v9/projects/atlas-x/domains"
    assert operation({"operation": "list_deployments", "project_name": "atlas-x", "limit": 4, "target": "production"}).target == "/v7/deployments?projectId=atlas-x&limit=4&target=production"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [],
        {"operation": "delete_project", "project_name": "atlas-x"},
        {"operation": "get_project", "project_name": "other-x"},
        {"operation": "get_project", "project_name": "atlas-x/../evil"},
        {"operation": "get_project", "project_name": "atlas-x", "teamId": "other"},
        {"operation": "add_domain", "project_name": "atlas-x", "domain": "chezchardin.com"},
        {"operation": "add_domain", "project_name": "atlas-x", "domain": "a.b.chezchardin.com"},
        {"operation": "add_domain", "project_name": "atlas-x", "domain": "evil.example"},
        {"operation": "list_deployments", "project_name": "atlas-x", "limit": True},
        {"operation": "list_deployments", "project_name": "atlas-x", "limit": 101},
        {"operation": "list_deployments", "project_name": "atlas-x", "target": "all"},
    ],
)
def test_invalid_or_injected_operation_payloads_are_rejected(payload: object) -> None:
    with pytest.raises(ProxyRequestError):
        _vercel_operation(json.dumps(payload).encode())


def test_operation_profile_rejects_query_and_caller_headers_and_derives_auth() -> None:
    captured: dict = {}

    class Response:
        status_code = 201
        headers = {"Content-Type": "application/json", "Set-Cookie": "unsafe=1"}
        content = b'{"id":"prj_1","name":"atlas-x"}'

        def close(self) -> None:
            captured["closed"] = True

    def sender(**kwargs):
        captured.update(kwargs)
        return Response()

    response = forward_request(
        registered_store(),
        token="khcap_vercel",
        method="POST",
        target="/v1/vercel",
        headers={"Authorization": "Bearer khcap_vercel", "X-Evil": "forward-me"},
        body=b'{"operation":"create_project","project_name":"atlas-x"}',
        sender=sender,
    )
    assert captured["method"] == "POST"
    assert captured["url"] == "https://api.vercel.com/v11/projects"
    assert captured["headers"] == {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Bearer parent-secret",
    }
    assert captured["allow_redirects"] is False
    assert captured["closed"] is True
    assert response.headers == {"Content-Type": "application/json"}
    assert json.loads(response.body) == {"id": "prj_1", "name": "atlas-x"}

    with pytest.raises(ProxyRequestError, match="route"):
        forward_request(
            registered_store(),
            token="khcap_vercel",
            method="POST",
            target="/v1/vercel?teamId=other",
            headers={},
            body=b'{}',
            sender=sender,
        )


def test_response_normalization_is_operation_and_resource_bound() -> None:
    create = operation({"operation": "create_project", "project_name": "atlas-x"})
    assert _normalize_vercel_response(create, ForwardResponse(200, {}, b'{"id":"prj_1","name":"atlas-x","secret":"drop"}')).body == b'{"id":"prj_1","name":"atlas-x"}'
    with pytest.raises(ProxyUpstreamError):
        _normalize_vercel_response(create, ForwardResponse(200, {}, b'{"id":"prj_1","name":"atlas-other"}'))

    get = operation({"operation": "get_project", "project_name": "atlas-x"})
    normalized = _normalize_vercel_response(
        get,
        ForwardResponse(200, {}, b'{"projects":[{"id":"prj_other","name":"atlas-y"},{"id":"prj_1","name":"atlas-x","env":"drop"}]}'),
    )
    assert json.loads(normalized.body) == {"id": "prj_1", "name": "atlas-x"}
    with pytest.raises(ProxyUpstreamError):
        _normalize_vercel_response(get, ForwardResponse(200, {}, b'{"projects":[]}'))
    with pytest.raises(ProxyUpstreamError):
        _normalize_vercel_response(get, ForwardResponse(200, {}, b'{"projects":[{"id":"1","name":"atlas-x"},{"id":"2","name":"atlas-x"}]}'))


def test_domain_and_deployment_responses_are_bounded_and_normalized() -> None:
    add = _bind_vercel_project_id(
        operation(
            {
                "operation": "add_domain",
                "project_name": "atlas-x",
                "domain": "x.chezchardin.com",
            }
        ),
        "prj_1",
    )
    assert json.loads(
        _normalize_vercel_response(
            add,
            ForwardResponse(
                200,
                {},
                b'{"name":"x.chezchardin.com","projectId":"prj_1","verified":false,"verification":[{"token":"drop"}]}',
            ),
        ).body
    ) == {"name": "x.chezchardin.com", "project_id": "prj_1", "verified": False}
    with pytest.raises(ProxyUpstreamError):
        _normalize_vercel_response(
            add, ForwardResponse(200, {}, b'{"name":"evil.example"}')
        )

    domains = _bind_vercel_project_id(
        operation({"operation": "list_domains", "project_name": "atlas-x"}),
        "prj_1",
    )
    assert json.loads(
        _normalize_vercel_response(
            domains,
            ForwardResponse(
                200,
                {},
                b'{"domains":[{"name":"x.chezchardin.com","projectId":"prj_1","verified":true,"token":"drop"}]}',
            ),
        ).body
    ) == {
        "domains": [
            {"name": "x.chezchardin.com", "project_id": "prj_1", "verified": True}
        ]
    }

    deployments = _bind_vercel_project_id(
        operation({"operation": "list_deployments", "project_name": "atlas-x"}),
        "prj_1",
    )
    raw = b'{"deployments":[{"uid":"dpl_1","name":"atlas-x","projectId":"prj_1","url":"atlas-x.vercel.app","readyState":"READY","meta":{"secret":"drop"}}]}'
    assert json.loads(
        _normalize_vercel_response(deployments, ForwardResponse(200, {}, raw)).body
    ) == {
        "deployments": [
            {
                "uid": "dpl_1",
                "name": "atlas-x",
                "project_id": "prj_1",
                "url": "atlas-x.vercel.app",
                "ready_state": "READY",
            }
        ]
    }


def test_domain_and_deployment_responses_reject_foreign_resources() -> None:
    domain_operation = _bind_vercel_project_id(
        operation({"operation": "list_domains", "project_name": "atlas-x"}),
        "prj_expected",
    )
    for body in (
        b'{"domains":[{"name":"evil.example","projectId":"prj_expected","verified":true}]}',
        b'{"domains":[{"name":"x.chezchardin.com","projectId":"prj_foreign","verified":true}]}',
    ):
        with pytest.raises(ProxyUpstreamError):
            _normalize_vercel_response(
                domain_operation, ForwardResponse(200, {}, body)
            )

    deployment_operation = _bind_vercel_project_id(
        operation({"operation": "list_deployments", "project_name": "atlas-x"}),
        "prj_expected",
    )
    with pytest.raises(ProxyUpstreamError):
        _normalize_vercel_response(
            deployment_operation,
            ForwardResponse(
                200,
                {},
                b'{"deployments":[{"uid":"dpl_1","name":"atlas-x","projectId":"prj_foreign","url":"atlas-x.vercel.app","readyState":"READY"}]}',
            ),
        )

    add_operation = _bind_vercel_project_id(
        operation(
            {
                "operation": "add_domain",
                "project_name": "atlas-x",
                "domain": "x.chezchardin.com",
            }
        ),
        "prj_expected",
    )
    with pytest.raises(ProxyUpstreamError):
        _normalize_vercel_response(
            add_operation,
            ForwardResponse(
                200,
                {},
                b'{"name":"x.chezchardin.com","projectId":"prj_foreign","verified":false}',
            ),
        )


def test_malformed_success_and_non_success_are_sanitized() -> None:
    get = operation({"operation": "get_project", "project_name": "atlas-x"})
    for body in (b"not-json", b"[]", b'{"projects":"wrong"}'):
        with pytest.raises(ProxyUpstreamError):
            _normalize_vercel_response(get, ForwardResponse(200, {}, body))
    response = _normalize_vercel_response(get, ForwardResponse(403, {"Set-Cookie": "x"}, b'{"error":{"message":"possibly sensitive"}}'))
    assert response.status == 403
    assert response.headers == {"Content-Type": "application/json"}
    assert response.body == b'{"error":"vercel request failed"}'


def test_invalid_vercel_profile_fails_before_secret_resolution(
    tmp_path, monkeypatch
) -> None:
    provider = LocalProxyProvider()
    monkeypatch.setitem(server.PROVIDERS, "local_proxy", provider)

    class Resolver:
        def resolve_refs(self, _refs):
            raise AssertionError("secret resolver must not run")

    monkeypatch.setattr(server, "_resolver", lambda _config: Resolver())
    grant = vercel_grant()
    grant["upstream_base_url"] = "https://evil.example"
    config = {
        "version": 1,
        "paths": {
            "leases_db": str(tmp_path / "leases.db"),
            "audit_log": str(tmp_path / "audit.jsonl"),
        },
        "callers": {
            "hermes": {
                "uid_name": "hermes",
                "profiles": {"default": {"grants": [grant]}},
            }
        },
    }

    with pytest.raises(ProxyConfigurationError, match="vercel_atlas"):
        server.handle_issue(
            config,
            "hermes",
            {"grant": "vercel-atlas-control", "reason": "validation test"},
        )
    assert not (tmp_path / "leases.db").exists()


def test_domain_operation_preflights_exact_project_and_binds_response_id() -> None:
    store = registered_store()
    observed_urls: list[str] = []
    response_bodies = iter(
        [
            b'{"projects":[{"id":"prj_exact","name":"atlas-x"}]}',
            b'{"domains":[{"name":"x.chezchardin.com","projectId":"prj_exact","verified":true}]}',
        ]
    )

    class Response:
        status_code = 200
        headers = {"Content-Type": "application/json"}

        def __init__(self) -> None:
            self.content = next(response_bodies)

        def close(self) -> None:
            pass

    def sender(**kwargs):
        observed_urls.append(kwargs["url"])
        return Response()

    response = forward_request(
        store=store,
        token="khcap_vercel",
        method="POST",
        target="/v1/vercel",
        headers={"Content-Type": "application/json"},
        body=b'{"operation":"list_domains","project_name":"atlas-x"}',
        sender=sender,
    )

    assert observed_urls == [
        "https://api.vercel.com/v10/projects?search=atlas-x",
        "https://api.vercel.com/v9/projects/prj_exact/domains",
    ]
    assert json.loads(response.body) == {
        "domains": [
            {
                "name": "x.chezchardin.com",
                "project_id": "prj_exact",
                "verified": True,
            }
        ]
    }


def test_public_issue_proxy_and_revoke_flow_is_bounded_and_audited(
    tmp_path, monkeypatch
) -> None:
    provider = LocalProxyProvider()
    monkeypatch.setitem(server.PROVIDERS, "local_proxy", provider)

    class Resolver:
        def resolve_refs(self, refs):
            assert refs == {"upstream_api_key": "key:vercel-team-token"}
            return {"upstream_api_key": "parent-secret"}

    monkeypatch.setattr(server, "_resolver", lambda _config: Resolver())
    config = {
        "version": 1,
        "paths": {
            "leases_db": str(tmp_path / "leases.db"),
            "audit_log": str(tmp_path / "audit.jsonl"),
        },
        "callers": {
            "hermes": {
                "uid_name": "hermes",
                "profiles": {"default": {"grants": [vercel_grant()]}},
            }
        },
    }
    issued = server.handle_issue(
        config,
        "hermes",
        {"grant": "vercel-atlas-control", "reason": "create Atlas project"},
    )
    observed: dict = {}

    class UpstreamResponse:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        content = b'{"projects":[{"id":"prj_1","name":"atlas-x"}]}'

        def close(self) -> None:
            observed["closed"] = True

    def sender(**kwargs):
        observed.update(kwargs)
        return UpstreamResponse()

    proxy = ProxyHTTPServer(
        ("127.0.0.1", 0),
        store=provider.store,
        audit_path=str(tmp_path / "audit.jsonl"),
        sender=sender,
    )
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    body = b'{"operation":"get_project","project_name":"atlas-x"}'
    try:
        connection = http.client.HTTPConnection("127.0.0.1", proxy.server_port)
        connection.request(
            "POST",
            "/v1/vercel",
            body=body,
            headers={
                "Authorization": f"Bearer {issued['access_token']}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read()) == {"id": "prj_1", "name": "atlas-x"}
        connection.close()

        server.handle_revoke(
            config,
            "hermes",
            {"lease_id": issued["lease_id"], "reason": "operation complete"},
        )
        connection = http.client.HTTPConnection("127.0.0.1", proxy.server_port)
        connection.request(
            "POST",
            "/v1/vercel",
            body=body,
            headers={
                "Authorization": f"Bearer {issued['access_token']}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        denied = connection.getresponse()
        assert denied.status == 401
        denied.read()
        connection.close()
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=5)

    assert observed["url"] == "https://api.vercel.com/v10/projects?search=atlas-x"
    assert observed["closed"] is True
    audit_text = (tmp_path / "audit.jsonl").read_text()
    assert '"operation":"get_project"' in audit_text
    assert '"resource":"atlas-x"' in audit_text
    assert "parent-secret" not in audit_text
    assert issued["access_token"] not in audit_text
