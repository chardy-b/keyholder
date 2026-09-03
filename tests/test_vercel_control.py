from __future__ import annotations

import pytest
from keyholderd.providers.vercel_control import VercelControlError, VercelControlProvider, translate


def test_create_is_fixed_and_derives_repo() -> None:
    method, path, body = translate("create_project", {"project_name": "atlas-demo-1"})
    assert method == "POST" and path == "/v10/projects"
    assert body["name"] == "atlas-demo-1"
    assert body["gitRepository"]["repo"] == "chardy-b/atlas-demo-1"
    assert body["framework"] == "nextjs" and body["productionBranch"] == "main"


def test_operations_pair_with_fixed_methods_and_reject_injection() -> None:
    assert translate("get_project", {"project_name": "atlas-x"})[0] == "GET"
    assert translate("add_domain", {"project_name": "atlas-x", "domain": "www.chezchardin.com"})[0] == "POST"
    assert translate("list_deployments", {"project_name": "atlas-x", "limit": 4, "target": "production"})[0] == "GET"
    for req in ({"project_name": "atlas-x/evil"}, {"project_name": "atlas-x", "domain": "evil.example"}, {"project_name": "atlas-x", "headers": {"Authorization": "x"}}):
        with pytest.raises(VercelControlError): translate("get_project", req)


def test_unknown_ops_and_unbounded_queries_rejected() -> None:
    with pytest.raises(VercelControlError): translate("delete_project", {"project_name": "atlas-x"})
    with pytest.raises(VercelControlError): translate("list_deployments", {"project_name": "atlas-x", "limit": 101})
    with pytest.raises(VercelControlError): translate("list_deployments", {"project_name": "atlas-x", "target": "all"})


def test_capability_is_opaque_and_revocable() -> None:
    provider = VercelControlProvider()
    cred = provider.issue({}, {"vercel_api_token": "parent-secret"}, 60)
    assert cred.display_token.startswith("khcap_")
    provider.activate(cred, "lease-1", {"vercel_api_token": "parent-secret"}, 60)
    assert provider.store.resolve(cred.display_token).api_token == "parent-secret"
    provider.store.revoke_lease("lease-1")
    with pytest.raises(PermissionError): provider.store.resolve(cred.display_token)
