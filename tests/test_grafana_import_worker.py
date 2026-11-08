import json
import os
import subprocess
import time
from datetime import UTC, datetime, timedelta

import pytest

from keyholderd import grafana_import as gi
from keyholderd.bitwarden import BitwardenImportError, ImportedSecret
from test_grafana_import import FakeResolver, PROJECT, VALUE, audit_lines, call, policy


@pytest.fixture(autouse=True)
def real_worker(monkeypatch):
    monkeypatch.setattr(gi, "WORKER", gi._run_worker)


class FileResolver(FakeResolver):
    """Records what the (forked) worker passed to Bitwarden in a file the parent can read."""

    def __init__(self, marker, **kw):
        super().__init__(**kw)
        self.marker = marker

    def import_secret(self, **kw):
        self.marker.write_text(json.dumps({"value": kw["value"], "project_id": kw["project_id"], "key": kw["key"]}))
        return super().import_secret(**kw)


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def wait_gone(pid, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return not alive(pid)


def test_value_stays_in_the_worker_and_only_metadata_returns(tmp_path, monkeypatch):
    marker = tmp_path / "marker"
    replies = []
    real_decode = gi._decode_payload
    monkeypatch.setattr(gi, "_decode_payload", lambda op, raw, cfg: replies.append(raw) or real_decode(op, raw, cfg))
    monkeypatch.setattr(gi, "SOURCE_FETCHER", lambda **kw: VALUE)
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FileResolver(marker))
    status, payload = call(policy(tmp_path), tmp_path)
    assert status == 200 and set(payload) == {"id", "key", "project_id", "status_verified"}
    assert json.loads(marker.read_text())["value"] == VALUE  # the child really handled the value
    (raw,) = replies
    assert VALUE.encode() not in raw and set(json.loads(raw)["result"]) == {"id", "key", "project_id", "status_verified", "created"}
    assert VALUE not in (tmp_path / "audit.jsonl").read_text()


def test_deadline_kills_worker_so_no_late_write_and_lock_is_released(tmp_path, monkeypatch):
    late_source, late_write = tmp_path / "late_source", tmp_path / "late_write"

    def slow_fetch(**kw):
        time.sleep(1.5)
        late_source.write_text("ran")
        return VALUE

    monkeypatch.setattr(gi, "SOURCE_FETCHER", slow_fetch)
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FileResolver(late_write))
    monkeypatch.setattr(gi, "OPERATION_TIMEOUT_SECONDS", 0.5)
    started = time.monotonic()
    status, payload = call(policy(tmp_path), tmp_path)
    assert time.monotonic() - started < 3
    assert status == 504 and "a write may already exist, retry to resolve" in payload["error"]
    assert gi._LOCK.acquire(blocking=False)  # lock released immediately, nothing still running
    gi._LOCK.release()
    time.sleep(2)
    assert not late_source.exists() and not late_write.exists()
    events = audit_lines(tmp_path)
    assert [(e["phase"], e["reason"]) for e in events] == [("attempt", "attempt"), ("failed", "timeout")]  # one failure, no late completion
    # the next operation is accepted and completes normally
    monkeypatch.setattr(gi, "SOURCE_FETCHER", lambda **kw: VALUE)
    monkeypatch.setattr(gi, "OPERATION_TIMEOUT_SECONDS", 10)
    assert call(policy(tmp_path), tmp_path)[0] == 200


def test_deadline_also_kills_owned_descendants_such_as_ssh(tmp_path, monkeypatch):
    pidfile = tmp_path / "child.pid"

    def spawn_then_hang(**kw):
        proc = subprocess.Popen(["sleep", "60"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pidfile.write_text(str(proc.pid))
        time.sleep(60)

    monkeypatch.setattr(gi, "SOURCE_FETCHER", spawn_then_hang)
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FakeResolver())
    monkeypatch.setattr(gi, "OPERATION_TIMEOUT_SECONDS", 0.6)
    assert call(policy(tmp_path), tmp_path)[0] == 504
    pid = int(pidfile.read_text())
    assert wait_gone(pid), "descendant survived the group kill"


def test_worker_stdout_stderr_and_native_output_are_suppressed(tmp_path, monkeypatch, capfd):
    def noisy(**kw):
        os.write(1, b"NATIVE-STDOUT-NOISE\n")
        os.write(2, b"NATIVE-STDERR-NOISE\n")
        return VALUE

    monkeypatch.setattr(gi, "SOURCE_FETCHER", noisy)
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FakeResolver())
    assert call(policy(tmp_path), tmp_path)[0] == 200
    captured = capfd.readouterr()
    assert "NOISE" not in captured.out + captured.err


def test_worker_has_no_inherited_descriptors_and_rust_log_is_cleared(tmp_path, monkeypatch):
    report = tmp_path / "report"
    monkeypatch.setenv("RUST_LOG", "debug")
    keep_open = open(tmp_path / "inherited", "w")  # stands in for the HTTP socket / audit handles

    def inspect(**kw):
        report.write_text(json.dumps({"fds": sorted(int(f) for f in os.listdir("/proc/self/fd")), "rust_log": os.environ.get("RUST_LOG"), "inherited": keep_open.fileno()}))
        return VALUE

    monkeypatch.setattr(gi, "SOURCE_FETCHER", inspect)
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FakeResolver())
    try:
        assert call(policy(tmp_path), tmp_path)[0] == 200
    finally:
        keep_open.close()
    seen = json.loads(report.read_text())
    assert seen["rust_log"] is None
    assert seen["inherited"] not in seen["fds"] and len(seen["fds"]) <= 5  # 0,1,2, reply pipe, the listdir fd


def test_worker_crash_is_a_fixed_error_and_does_not_hang(tmp_path, monkeypatch):
    monkeypatch.setattr(gi, "SOURCE_FETCHER", lambda **kw: os._exit(3))
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FakeResolver())
    status, payload = call(policy(tmp_path), tmp_path)
    assert (status, payload) == (502, {"error": gi.ERRORS["worker_failed"][1]})
    assert audit_lines(tmp_path)[-1]["reason"] == "worker_failed"


def test_error_codes_cross_the_process_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(gi, "SOURCE_FETCHER", lambda **kw: VALUE)
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FakeResolver(error="value_differs"))
    assert call(policy(tmp_path), tmp_path)[0] == 409
    monkeypatch.setattr(gi, "SOURCE_FETCHER", lambda **kw: (_ for _ in ()).throw(RuntimeError(f"leak {VALUE}")))
    status, payload = call(policy(tmp_path), tmp_path)
    assert (status, payload) == (500, {"error": "internal error"})
    assert VALUE not in (tmp_path / "audit.jsonl").read_text()


def test_projects_operation_runs_through_the_worker(tmp_path, monkeypatch):
    monkeypatch.setattr(gi, "RESOLVER_FACTORY", lambda: FakeResolver())
    assert call(policy(tmp_path, grafana=None), tmp_path, operation=gi.OP_PROJECTS) == (200, {"projects": [{"id": PROJECT, "name": "Grafana"}]})


CFG = gi.ImportConfig(PROJECT, None, False)
GOOD = {"id": "44444444-4444-4444-8444-444444444444", "key": gi.DEST_KEY, "project_id": PROJECT, "status_verified": True, "created": True}


def decode(obj, cfg=CFG, op=gi.OP_IMPORT):
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return gi._decode_payload(op, raw, cfg)


def test_parent_accepts_only_the_exact_reply_shape():
    assert decode({"ok": True, "result": GOOD}) == GOOD
    bad = [
        b"", b"not json", b"[]", {"ok": True}, {"ok": True, "result": GOOD, "value": VALUE},
        {"ok": True, "result": {**GOOD, "value": VALUE}}, {"ok": True, "result": {**GOOD, "project_id": "99999999-9999-4999-8999-999999999999"}},
        {"ok": True, "result": {**GOOD, "key": "OTHER"}}, {"ok": True, "result": {**GOOD, "status_verified": "yes"}},
        {"ok": True, "result": {**GOOD, "created": "no"}}, {"ok": True, "result": {**GOOD, "id": "nope"}}, {"ok": False, "code": "x", "value": VALUE},
        {"ok": "true", "result": GOOD},
    ]
    for item in bad:
        with pytest.raises(gi.GrafanaImportError) as err:
            decode(item)
        assert err.value.code == "worker_failed", item
    with pytest.raises(gi.GrafanaImportError) as err:
        decode({"ok": False, "code": "value_differs"})
    assert err.value.code == "value_differs"
    with pytest.raises(gi.GrafanaImportError) as err:
        decode({"ok": False, "code": "invented"})
    assert err.value.code == "worker_failed"
    with pytest.raises(gi.GrafanaImportError):
        decode({"ok": True, "result": GOOD}, cfg=None)


def test_projects_reply_shape_is_validated():
    ok = {"ok": True, "result": {"projects": [{"id": PROJECT, "name": "G"}]}}
    assert decode(ok, op=gi.OP_PROJECTS) == ok["result"]
    for result in ({"projects": [{"id": PROJECT, "name": "G", "organizationId": "x"}]}, {"projects": "x"}, {"projects": [], "extra": 1}):
        with pytest.raises(gi.GrafanaImportError):
            decode({"ok": True, "result": result}, op=gi.OP_PROJECTS)
