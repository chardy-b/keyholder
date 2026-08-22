import json
import os
import sys

import pytest

from keyholderd import server
from keyholderd.proxy import ProxyConfigurationError


def config(tmp_path):
    return {"version":1, "paths":{"leases_db":str(tmp_path/"leases.db"), "audit_log":str(tmp_path/"audit.jsonl")}, "callers":{"hermes":{"uid_name":"hermes", "profiles":{"default":{"grants":[{"name":"fake", "provider":"fake", "ttl_seconds":30, "max_ttl_seconds":60, "bitwarden_refs":{}}]}}}}}


def test_unknown_caller_denied(tmp_path):
    assert server.handle_grants(config(tmp_path), "nobody")["grants"] == []


def test_known_caller_can_list_grants(tmp_path):
    grants = server.handle_grants(config(tmp_path), "hermes")["grants"]
    assert grants == [{"name":"fake", "provider":"fake", "max_ttl_seconds":60, "default_ttl_seconds":30}]


def test_issue_creates_lease_and_audit(tmp_path):
    out = server.handle_issue(config(tmp_path), "hermes", {"grant":"fake", "ttl_seconds":30, "reason":"test", "profile":"default"})
    assert out["access_token"] == "fake-temporary-token"
    assert out["lease_id"].startswith("lease_")
    assert (tmp_path/"leases.db").exists()
    assert "fake-temporary-token" not in (tmp_path/"audit.jsonl").read_text()


def test_run_injects_env_but_does_not_print_token(tmp_path):
    out = server.handle_run(config(tmp_path), "hermes", {"grant":"fake", "env_var":"FAKE_TOKEN", "ttl_seconds":30, "reason":"test", "profile":"default", "command":[sys.executable, "-c", "import os; print(os.environ['FAKE_TOKEN'] == 'fake-temporary-token')"]})
    assert out["exit_code"] == 0
    assert out["stdout"].strip() == "True"
    assert "fake-temporary-token" not in (tmp_path/"audit.jsonl").read_text()


def test_ttl_above_max_fails(tmp_path):
    try:
        server.handle_issue(config(tmp_path), "hermes", {"grant":"fake", "ttl_seconds":61, "reason":"test"})
    except Exception as exc:
        assert "exceeds max" in str(exc)
    else:
        raise AssertionError("expected failure")


def proxy_config(tmp_path, **overrides):
    values = {
        "host": "127.0.0.1", "port": 0, "max_body_bytes": 4096,
        "max_response_bytes": 8192, "max_workers": 3,
        "request_timeout_seconds": 7, "upstream_timeout_seconds": 9,
    }
    values.update(overrides)
    return {"proxy": values, "paths": {"audit_log": str(tmp_path / "audit.jsonl")}}


@pytest.mark.parametrize("field", ["max_body_bytes", "max_response_bytes", "max_workers"])
@pytest.mark.parametrize("value", ["4096", "not-a-number"])
def test_tcp_proxy_factory_rejects_non_numeric_integer_limits_before_listening(tmp_path, field, value):
    with pytest.raises(ProxyConfigurationError):
        server.create_proxy_server(proxy_config(tmp_path, **{field: value}))


@pytest.mark.parametrize("field", ["request_timeout_seconds", "upstream_timeout_seconds"])
@pytest.mark.parametrize("value", ["7", "not-a-number", float("nan"), float("inf"), -1, 0])
def test_tcp_proxy_factory_rejects_invalid_timeout_limits_before_listening(tmp_path, field, value):
    with pytest.raises(ProxyConfigurationError):
        server.create_proxy_server(proxy_config(tmp_path, **{field: value}))


@pytest.mark.parametrize("field", ["max_body_bytes", "max_response_bytes", "max_workers"])
def test_tcp_proxy_factory_rejects_invalid_positive_constraints_before_listening(tmp_path, field):
    with pytest.raises(ProxyConfigurationError):
        server.create_proxy_server(proxy_config(tmp_path, **{field: 0}))


def test_tcp_proxy_factory_accepts_normal_numeric_config(tmp_path):
    proxy_server = server.create_proxy_server(proxy_config(tmp_path))
    try:
        assert proxy_server.server_address[1] > 0
        assert proxy_server.max_body_bytes == 4096
        assert proxy_server.max_response_bytes == 8192
        assert proxy_server.max_workers == 3
        assert proxy_server.request_timeout_seconds == 7
        assert proxy_server.upstream_timeout_seconds == 9
    finally:
        proxy_server.server_close()
