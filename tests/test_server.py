import json
import os
import sys
from keyholderd import server


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
