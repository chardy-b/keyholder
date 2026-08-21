import json
import logging
import pytest
from keyholderd.bitwarden import BitwardenError, BwsResolver

def test_bws_secret_get_called_and_json_parsed():
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        return type("R", (), {"returncode":0, "stdout":json.dumps({"value":"secret-value"}), "stderr":""})()
    r = BwsResolver(runner=runner)
    assert r.resolve_refs({"token":"secret-name"}) == {"token":"secret-value"}
    assert calls[0][:3] == ["bws", "secret", "get"] and "secret-name" in calls[0]

def test_missing_secret_clear_error():
    def runner(cmd, **kwargs):
        return type("R", (), {"returncode":1, "stdout":"", "stderr":"not found"})()
    with pytest.raises(BitwardenError, match="failed resolving"):
        BwsResolver(runner=runner).resolve_refs({"token":"missing"})

def test_cache_respects_cache_seconds():
    n = {"count":0}
    def runner(cmd, **kwargs):
        n["count"] += 1
        return type("R", (), {"returncode":0, "stdout":json.dumps({"value":"v"}), "stderr":""})()
    r = BwsResolver(runner=runner, cache_seconds=60)
    assert r.resolve_refs({"a":"x"}) == {"a":"v"}
    assert r.resolve_refs({"a":"x"}) == {"a":"v"}
    assert n["count"] == 1

def test_secret_values_are_never_logged(caplog):
    def runner(cmd, **kwargs):
        return type("R", (), {"returncode":0, "stdout":json.dumps({"value":"super-secret"}), "stderr":""})()
    with caplog.at_level(logging.DEBUG):
        BwsResolver(runner=runner).resolve_refs({"token":"name"})
    assert "super-secret" not in caplog.text


def test_named_key_lists_project_then_fetches_exact_uuid():
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["bws", "secret", "list"]:
            return type("R", (), {"returncode": 0, "stdout": json.dumps([{"id": "uuid-1", "key": "openrouter"}]), "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": json.dumps({"value": "secret-value"}), "stderr": ""})()
    assert BwsResolver(project_id="project-1", runner=runner).resolve_refs({"token": "key:openrouter"}) == {"token": "secret-value"}
    assert calls == [["bws", "secret", "list", "project-1", "--output", "json"], ["bws", "secret", "get", "uuid-1", "--output", "json"]]

def test_named_key_missing_or_duplicate_rejects_without_get():
    for entries in ([], [{"id": "a", "key": "same"}, {"id": "b", "key": "same"}]):
        calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd)
            return type("R", (), {"returncode": 0, "stdout": json.dumps(entries), "stderr": ""})()
        with pytest.raises(BitwardenError):
            BwsResolver(project_id="project-1", runner=runner).resolve_refs({"token": "key:same"})
        assert len(calls) == 1

def test_named_key_requires_project_before_runner():
    def runner(*args, **kwargs):
        raise AssertionError("runner must not execute")
    with pytest.raises(BitwardenError, match="project"):
        BwsResolver(runner=runner).resolve_refs({"token": "key:openrouter"})

def test_secret_values_never_enter_errors_or_logs():
    secret = "super-secret"
    def runner(cmd, **kwargs):
        return type("R", (), {"returncode": 1, "stdout": "", "stderr": secret})()
    with pytest.raises(BitwardenError) as exc:
        BwsResolver(runner=runner).resolve_refs({"token": "name"})
    assert secret not in str(exc.value)
