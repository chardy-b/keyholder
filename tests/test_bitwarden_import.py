import json
import logging
import uuid
from datetime import UTC, datetime

import pytest
import bitwarden_sdk
from bitwarden_sdk.schemas import (
    AccessTokenLoginResponse,
    ProjectResponse,
    ResponseForAccessTokenLoginResponse,
    ResponseForProjectResponse,
    ResponseForSecretIdentifiersResponse,
    ResponseForSecretResponse,
    SecretIdentifierResponse,
    SecretIdentifiersResponse,
    SecretResponse,
)

from keyholderd import bitwarden
from keyholderd.bitwarden import BitwardenImportError, BwsResolver

ORG = "11111111-1111-4111-8111-111111111111"
PROJECT = "22222222-2222-4222-8222-222222222222"
OTHER_PROJECT = "33333333-3333-4333-8333-333333333333"
KEY = "GRAFANA_FLEET_ADMIN_PASSWORD"
VALUE = "s3cret-VALUE-for-tests"
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def secret_model(secret_id, *, key=KEY, value=VALUE, project=PROJECT, org=ORG):
    return SecretResponse(NOW, uuid.UUID(secret_id), key, "", uuid.UUID(org), NOW, value, uuid.UUID(project) if project else None)


class FakeBitwardenInner:
    """Stands in for the native bitwarden_py client: speaks the real SDK JSON protocol."""

    def __init__(self, *, secrets=None, fail=(), org=ORG, project_org=None):
        self.secrets = dict(secrets or {})  # id -> SecretResponse
        self.fail = set(fail)
        self.org = org
        self.project_org = project_org or org
        self.commands = []
        self.create_override = None
        self.get_override = None

    def run_command(self, command_json):
        command = json.loads(command_json)
        self.commands.append(command)
        (area, body), = command.items()
        if area == "loginAccessToken":
            return json.dumps(ResponseForAccessTokenLoginResponse(True, AccessTokenLoginResponse(True, False, False)).to_dict())
        (name, args), = body.items()
        if name in self.fail:
            return json.dumps({"success": False, "errorMessage": f"boom {VALUE} {args}"})
        if area == "projects" and name == "get":
            project = ProjectResponse(NOW, uuid.UUID(args["id"]), "grafana", uuid.UUID(self.project_org), NOW)
            return json.dumps(ResponseForProjectResponse(True, project).to_dict())
        if area == "secrets" and name == "list":
            items = [SecretIdentifierResponse(s.id, s.key, s.organization_id, [s.project_id] if s.project_id else []) for s in self.secrets.values()]
            return json.dumps(ResponseForSecretIdentifiersResponse(True, SecretIdentifiersResponse(items)).to_dict())
        if area == "secrets" and name == "get":
            found = self.get_override or self.secrets.get(args["id"])
            if found is None:
                return json.dumps({"success": False, "errorMessage": "not found"})
            return json.dumps(ResponseForSecretResponse(True, found).to_dict())
        if area == "secrets" and name == "create":
            created = self.create_override or secret_model("44444444-4444-4444-8444-444444444444", key=args["key"], value=args["value"], project=args["projectIds"][0], org=args["organizationId"])
            self.secrets[str(created.id)] = created
            return json.dumps(ResponseForSecretResponse(True, created).to_dict())
        raise AssertionError(f"unexpected command {command}")


def make_resolver(inner, tmp_path, tokens=None):
    token_file = tmp_path / "token"
    token_file.write_text("0.fake-token-value:abc\n")
    client = bitwarden_sdk.BitwardenClient.__new__(bitwarden_sdk.BitwardenClient)
    client.inner = inner

    def login(token):
        if tokens is not None:
            tokens.append(token)
        return client

    return BwsResolver(access_token_file=str(token_file), sdk_login=login)


def do_import(resolver, **kw):
    return resolver.import_secret(project_id=PROJECT, key=KEY, value=VALUE, note="n", **kw)


def create_commands(inner):
    return [c for c in inner.commands if "create" in c.get("secrets", {})]


def test_creates_new_secret_with_real_sdk_protocol_and_verifies_readback(tmp_path):
    inner = FakeBitwardenInner()
    tokens = []
    result = do_import(make_resolver(inner, tmp_path, tokens), organization_id=ORG)
    assert result.created and result.key == KEY and result.project_id == PROJECT
    (create,) = create_commands(inner)
    assert create["secrets"]["create"] == {"key": KEY, "note": "n", "organizationId": ORG, "value": VALUE, "projectIds": [PROJECT]}
    assert inner.commands[-1] == {"secrets": {"get": {"id": result.id}}}
    assert tokens == ["0.fake-token-value:abc"]


def test_second_invocation_returns_existing_without_create_or_update(tmp_path):
    inner = FakeBitwardenInner()
    resolver = make_resolver(inner, tmp_path)
    first = do_import(resolver)
    inner.commands.clear()
    second = do_import(resolver)
    assert not second.created and second.id == first.id
    assert not create_commands(inner)
    assert not [c for c in inner.commands if set(c.get("secrets", {})) & {"update", "delete"}]


def test_existing_with_different_value_is_rejected_without_overwrite(tmp_path):
    existing = secret_model("55555555-5555-4555-8555-555555555555", value="different")
    inner = FakeBitwardenInner(secrets={str(existing.id): existing})
    with pytest.raises(BitwardenImportError) as err:
        do_import(make_resolver(inner, tmp_path))
    assert err.value.code == "value_differs"
    assert not create_commands(inner)
    assert inner.secrets[str(existing.id)].value == "different"


def test_multiple_exact_key_records_fail_closed(tmp_path):
    a = secret_model("55555555-5555-4555-8555-555555555555")
    b = secret_model("66666666-6666-4666-8666-666666666666")
    inner = FakeBitwardenInner(secrets={str(a.id): a, str(b.id): b})
    with pytest.raises(BitwardenImportError) as err:
        do_import(make_resolver(inner, tmp_path))
    assert err.value.code == "duplicate_records"
    assert not create_commands(inner)


def test_same_key_in_unrelated_project_is_not_a_match_and_not_touched(tmp_path):
    other = secret_model("55555555-5555-4555-8555-555555555555", project=OTHER_PROJECT, value="other")
    inner = FakeBitwardenInner(secrets={str(other.id): other})
    result = do_import(make_resolver(inner, tmp_path))
    assert result.created and result.id != str(other.id)
    assert inner.secrets[str(other.id)].value == "other"


def test_existing_readback_with_wrong_project_is_rejected(tmp_path):
    existing = secret_model("55555555-5555-4555-8555-555555555555")
    inner = FakeBitwardenInner(secrets={str(existing.id): existing})
    inner.get_override = secret_model(str(existing.id), project=OTHER_PROJECT)
    with pytest.raises(BitwardenImportError) as err:
        do_import(make_resolver(inner, tmp_path))
    assert err.value.code == "lookup_failed"


@pytest.mark.parametrize(
    "override",
    [
        dict(secret_id="44444444-4444-4444-8444-444444444444", value="tampered"),
        dict(secret_id="44444444-4444-4444-8444-444444444444", key="OTHER_KEY"),
        dict(secret_id="44444444-4444-4444-8444-444444444444", project=OTHER_PROJECT),
        dict(secret_id="44444444-4444-4444-8444-444444444444", project=None),
        dict(secret_id="77777777-7777-4777-8777-777777777777"),
    ],
)
def test_new_create_with_mismatched_readback_is_reported_ambiguous_and_not_rolled_back(tmp_path, override):
    inner = FakeBitwardenInner()
    override = dict(override)
    secret_id = override.pop("secret_id")
    created = secret_model("44444444-4444-4444-8444-444444444444")
    inner.create_override = created
    inner.get_override = secret_model(secret_id, **override)
    with pytest.raises(BitwardenImportError) as err:
        do_import(make_resolver(inner, tmp_path))
    assert err.value.code == "write_ambiguous"
    assert not [c for c in inner.commands if "delete" in c.get("secrets", {})]
    assert str(created.id) in inner.secrets  # no rollback


def test_project_org_mismatch_with_pinned_org_is_rejected_before_any_secret_call(tmp_path):
    inner = FakeBitwardenInner(project_org="99999999-9999-4999-8999-999999999999")
    with pytest.raises(BitwardenImportError) as err:
        do_import(make_resolver(inner, tmp_path), organization_id=ORG)
    assert err.value.code == "project_mismatch"
    assert not [c for c in inner.commands if "secrets" in c]


def test_org_is_inferred_from_the_project_when_not_pinned(tmp_path):
    inner = FakeBitwardenInner()
    do_import(make_resolver(inner, tmp_path))
    assert {"secrets": {"list": {"organizationId": ORG}}} in inner.commands


@pytest.mark.parametrize("failing", ["get", "list", "create"])
def test_sdk_errors_are_redacted_and_chain_free(tmp_path, caplog, failing):
    inner = FakeBitwardenInner(fail={failing})
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(BitwardenImportError) as err:
            do_import(make_resolver(inner, tmp_path))
    exc = err.value
    assert exc.__cause__ is None and exc.__context__ is None
    assert VALUE not in str(exc) and VALUE not in caplog.text and "boom" not in str(exc)


def test_login_and_token_file_failures_are_redacted(tmp_path):
    token_file = tmp_path / "t"
    token_file.write_text("0.token-secret-text:k")

    def bad_login(token):
        raise RuntimeError(f"login failed for {token}")

    resolver = BwsResolver(access_token_file=str(token_file), sdk_login=bad_login)
    with pytest.raises(BitwardenImportError) as err:
        do_import(resolver)
    assert err.value.code == "auth_failed" and "token-secret-text" not in str(err.value)
    assert err.value.__context__ is None
    with pytest.raises(BitwardenImportError) as err2:
        do_import(BwsResolver(access_token_file=str(tmp_path / "missing"), sdk_login=bad_login))
    assert err2.value.code == "auth_failed"


def test_default_login_keeps_no_state_file_and_checks_authenticated(monkeypatch, tmp_path):
    inner = FakeBitwardenInner()
    monkeypatch.setattr(bitwarden_sdk.bitwarden_client.bitwarden_py, "BitwardenClient", lambda settings: inner)
    monkeypatch.setenv("RUST_LOG", "debug")
    bitwarden._default_sdk_login("0.tok:k")
    assert inner.commands == [{"loginAccessToken": {"accessToken": "0.tok:k"}}]
    import os
    assert "RUST_LOG" not in os.environ


def test_list_projects_returns_only_id_and_name_via_bws_cli():
    calls = []
    payload = [
        {"id": PROJECT, "name": "Grafana", "organizationId": ORG, "creationDate": "x"},
        {"id": "not-a-uuid", "name": "bad"},
        {"id": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "name": "noncanonical"},
        {"id": OTHER_PROJECT, "name": "Zeta\x1b[31m"},
        "junk",
    ]

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": json.dumps(payload), "stderr": ""})()

    out = BwsResolver(runner=runner).list_projects()
    assert calls == [["bws", "project", "list", "--output", "json"]]
    assert out == [{"id": PROJECT, "name": "Grafana"}, {"id": OTHER_PROJECT, "name": "Zeta[31m"}]


def test_list_projects_failures_are_redacted():
    def runner(cmd, **kwargs):
        raise OSError("/very/secret/path token=abc")

    with pytest.raises(BitwardenImportError) as err:
        BwsResolver(runner=runner).list_projects()
    assert err.value.code == "projects_unavailable" and "abc" not in str(err.value) and err.value.__context__ is None
