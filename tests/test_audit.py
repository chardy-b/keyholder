import json
import pytest
from keyholderd.audit import SecretInAuditError, sanitize_event, write_audit_event

def test_one_event_writes_one_valid_json_line(tmp_path):
    p = tmp_path / "audit.jsonl"
    write_audit_event(str(p), {"event":"issue","caller":"hermes","grant":"g","provider":"fake","ttl_seconds":60,"lease_id":"l1","reason":"test"})
    lines = p.read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["event"] == "issue" and "timestamp" in rec

def test_token_fields_are_rejected():
    with pytest.raises(SecretInAuditError):
        sanitize_event({"event":"x", "access_token":"tok"})
    with pytest.raises(SecretInAuditError):
        sanitize_event({"event":"x", "nested":{"secret":"s"}})

def test_audit_record_includes_required_fields(tmp_path):
    p = tmp_path / "audit.jsonl"
    event = {"event":"run","caller":"hermes","grant":"g","provider":"fake","ttl_seconds":30,"lease_id":"l2","reason":"needed"}
    write_audit_event(str(p), event)
    rec = json.loads(p.read_text())
    for key in ["timestamp", *event.keys()]:
        assert key in rec
