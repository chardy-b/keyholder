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
    ref = "123e4567-e89b-12d3-a456-426614174000"
    assert r.resolve_refs({"token":ref}) == {"token":"secret-value"}
    assert calls[0][:3] == ["bws", "secret", "get"] and ref in calls[0]

def test_missing_secret_clear_error():
    def runner(cmd, **kwargs):
        return type("R", (), {"returncode":1, "stdout":"", "stderr":"not found"})()
    with pytest.raises(BitwardenError, match="failed resolving"):
        BwsResolver(runner=runner).resolve_refs({"token":"123e4567-e89b-12d3-a456-426614174000"})

def test_cache_respects_cache_seconds():
    n = {"count":0}
    def runner(cmd, **kwargs):
        n["count"] += 1
        return type("R", (), {"returncode":0, "stdout":json.dumps({"value":"v"}), "stderr":""})()
    r = BwsResolver(runner=runner, cache_seconds=60)
    ref = "123e4567-e89b-12d3-a456-426614174000"
    assert r.resolve_refs({"a":ref}) == {"a":"v"}
    assert r.resolve_refs({"a":ref}) == {"a":"v"}
    assert n["count"] == 1

def test_secret_values_are_never_logged(caplog):
    def runner(cmd, **kwargs):
        return type("R", (), {"returncode":0, "stdout":json.dumps({"value":"super-secret"}), "stderr":""})()
    with caplog.at_level(logging.DEBUG):
        BwsResolver(runner=runner).resolve_refs({"token":"123e4567-e89b-12d3-a456-426614174000"})
    assert "super-secret" not in caplog.text


def test_named_key_lists_project_then_fetches_exact_uuid():
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["bws", "secret", "list"]:
            return type("R", (), {"returncode": 0, "stdout": json.dumps([{"id": "123e4567-e89b-12d3-a456-426614174000", "key": "openrouter"}]), "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": json.dumps({"value": "secret-value"}), "stderr": ""})()
    assert BwsResolver(project_id="project-1", runner=runner).resolve_refs({"token": "key:openrouter"}) == {"token": "secret-value"}
    assert calls == [["bws", "secret", "list", "project-1", "--output", "json"], ["bws", "secret", "get", "123e4567-e89b-12d3-a456-426614174000", "--output", "json"]]

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
        BwsResolver(runner=runner).resolve_refs({"token": "123e4567-e89b-12d3-a456-426614174000"})
    assert secret not in str(exc.value)

@pytest.mark.parametrize("ref", ["name", "", "key:", "key:   ", 42, None])
def test_invalid_refs_are_rejected_before_runner(ref):
    calls = []
    def runner(*args, **kwargs):
        calls.append(args)
        raise AssertionError("runner must not execute")
    with pytest.raises(BitwardenError):
        BwsResolver(runner=runner).resolve_refs({"token": ref})
    assert not calls

@pytest.mark.parametrize("payload", ["not-json", "null", "[]", '{"data": null}', '{"data": []}'])
def test_malformed_secret_responses_are_rejected(payload):
    def runner(cmd, **kwargs):
        return type("R", (), {"returncode": 0, "stdout": payload, "stderr": ""})()
    with pytest.raises(BitwardenError):
        BwsResolver(runner=runner).resolve_refs({"token": "123e4567-e89b-12d3-a456-426614174000"})

def test_key_lookup_rejects_noncanonical_selected_id():
    def runner(cmd, **kwargs):
        return type("R", (), {"returncode": 0, "stdout": json.dumps([{"id": "not-an-id", "key": "same"}]), "stderr": ""})()
    with pytest.raises(BitwardenError):
        BwsResolver(project_id="project-1", runner=runner).resolve_refs({"token": "key:same"})

@pytest.mark.parametrize("refs", [None, [], {"": "ref"}, {"token": ""}, {"token": None}, {1: "ref"}])
def test_invalid_reference_mapping_rejected_before_runner(refs):
    def runner(*args, **kwargs):
        raise AssertionError("runner must not execute")
    with pytest.raises(BitwardenError):
        BwsResolver(runner=runner).resolve_refs(refs)

@pytest.mark.parametrize("payload", [
    {"value": 42, "secret": "valid-secret"},
    {"value": "", "secret": "valid-secret"},
    {"secret": 42},
    {"data": "not-a-mapping"},
    {"data": {"value": ""}},
    {"data": {"value": 42}},
    {},
])
def test_present_malformed_secret_fields_reject_without_fallback(payload, caplog):
    marker = "marker-secret-value"

    def runner(cmd, **kwargs):
        return type("R", (), {"returncode": 0, "stdout": json.dumps(payload), "stderr": marker})()

    with caplog.at_level(logging.DEBUG), pytest.raises(BitwardenError) as exc:
        BwsResolver(runner=runner).resolve_refs({"token": "123e4567-e89b-12d3-a456-426614174000"})
    assert marker not in str(exc.value)
    assert marker not in caplog.text


def test_data_value_is_used_when_valid():
    def runner(cmd, **kwargs):
        return type("R", (), {"returncode": 0, "stdout": json.dumps({"data": {"value": "valid-secret"}}), "stderr": ""})()

    assert BwsResolver(runner=runner).resolve_refs({"token": "123e4567-e89b-12d3-a456-426614174000"}) == {"token": "valid-secret"}


@pytest.mark.parametrize("ref", ["key:", "key:   "])
def test_blank_key_reference_rejected_before_runner(ref):
    def runner(*args, **kwargs):
        raise AssertionError("runner must not execute")
    with pytest.raises(BitwardenError):
        BwsResolver(project_id="project-1", runner=runner).resolve_refs({"token": ref})
