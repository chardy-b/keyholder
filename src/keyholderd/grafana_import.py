from __future__ import annotations

import json
import logging
import os
import re
import select
import signal
import sys
import stat
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable

from .audit import write_audit_event
from .bitwarden import BwsResolver
from .policy import operations_for_caller

LOG = logging.getLogger(__name__)

OP_PROJECTS = "grafana_projects"
OP_IMPORT = "grafana_import"
ROUTES = {"/v1/grafana-projects": OP_PROJECTS, "/v1/grafana-import": OP_IMPORT}

# Everything the import touches is fixed here; callers cannot influence any of it.
SOURCE_USER = "root"
SOURCE_HOST = "matrix-ubuntu"
SOURCE_PATH = "/opt/fleet-observability/secrets/grafana_password"
DEST_KEY = "GRAFANA_FLEET_ADMIN_PASSWORD"
DEST_NOTE = "Imported by keyholder grafana-import"
KNOWN_HOSTS_FILE = "/etc/keyholder/grafana-import-known_hosts"
SSH_BIN = "/usr/bin/ssh"
SSH_TIMEOUT_SECONDS = 20.0
MAX_SOURCE_BYTES = 4096
MAX_BODY_BYTES = 1024
OPERATION_TIMEOUT_SECONDS = 60.0
BODY_READ_SECONDS = 5.0
MAX_WORKER_REPLY_BYTES = 16384
BUSY_WAIT_SECONDS = 1.0

_PROFILE_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_NIL_UUID = "00000000-0000-0000-0000-000000000000"
_CONFIG_KEYS = {"enabled", "project_id", "organization_id", "strip_single_trailing_newline"}

ERRORS: dict[str, tuple[int, str]] = {
    "invalid_request": (400, "invalid request"),
    "not_authorized": (403, "not authorized"),
    "not_configured": (503, "grafana import is not configured"),
    "busy": (429, "another keyholder operation is in progress"),
    "timeout": (504, "operation timed out and was stopped; a write may already exist, retry to resolve"),
    "worker_failed": (502, "worker failed; a write may already exist, retry to resolve"),
    "audit_unavailable": (503, "audit log unavailable; no action taken"),
    "source_unconfigured": (503, "source host key file is missing or unsafe"),
    "source_timeout": (504, "source read timed out"),
    "source_unavailable": (502, "source read failed"),
    "source_too_large": (502, "source value exceeds the size limit"),
    "source_invalid": (502, "source value is empty or not valid text"),
    "auth_failed": (502, "bitwarden authentication failed"),
    "projects_unavailable": (502, "bitwarden project listing failed"),
    "project_unavailable": (502, "destination project is not accessible"),
    "project_mismatch": (503, "destination project does not match policy"),
    "lookup_failed": (502, "bitwarden lookup failed"),
    "duplicate_records": (409, "multiple records with the destination key exist; refusing to continue"),
    "value_differs": (409, "an existing record has a different value; explicit approval required"),
    "write_ambiguous": (502, "write outcome could not be verified; the record may exist, retry to resolve"),
    "internal_error": (500, "internal error"),
}


class GrafanaImportError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code if code in ERRORS else "internal_error"


@dataclass(frozen=True)
class ImportConfig:
    project_id: str
    organization_id: str | None
    strip_single_trailing_newline: bool


def _canonical_uuid(value: object) -> bool:
    if not isinstance(value, str) or value == _NIL_UUID:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def parse_import_config(config: dict[str, Any]) -> ImportConfig:
    raw = config.get("grafana_import")
    if not isinstance(raw, dict) or set(raw) - _CONFIG_KEYS or raw.get("enabled") is not True:
        raise GrafanaImportError("not_configured")
    if not _canonical_uuid(raw.get("project_id")):
        raise GrafanaImportError("not_configured")
    org = raw.get("organization_id")
    if org is not None and not _canonical_uuid(org):
        raise GrafanaImportError("not_configured")
    strip = raw.get("strip_single_trailing_newline", False)
    if not isinstance(strip, bool):
        raise GrafanaImportError("not_configured")
    return ImportConfig(raw["project_id"], org, strip)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def parse_request(raw: bytes | None) -> str:
    """Strict request schema: an optional ``profile`` and nothing else. Returns the profile."""
    if raw is None or len(raw) > MAX_BODY_BYTES:
        raise GrafanaImportError("invalid_request")
    try:
        data = json.loads(raw.decode("utf-8") or "{}", object_pairs_hook=_no_duplicate_keys)
    except ValueError:
        raise GrafanaImportError("invalid_request") from None
    if not isinstance(data, dict) or set(data) - {"profile"}:
        raise GrafanaImportError("invalid_request")
    profile = data.get("profile", "default")
    if not isinstance(profile, str) or not _PROFILE_RE.fullmatch(profile):
        raise GrafanaImportError("invalid_request")
    return profile


def _entry_allows(entry: Any, operation: str, now: datetime) -> bool:
    if not isinstance(entry, dict) or set(entry) - {"operation", "expires_at"} or entry.get("operation") != operation:
        return False
    expires = entry.get("expires_at")
    if expires is None:
        return operation != OP_IMPORT  # the one-shot import must carry an operator deadline
    if isinstance(expires, str):
        try:
            expires = datetime.fromisoformat(expires)
        except ValueError:
            return False
    if not isinstance(expires, datetime) or expires.tzinfo is None:
        return False
    return now < expires


def is_authorized(config: dict[str, Any], caller: str, profile: str, operation: str, now: datetime) -> bool:
    try:
        entries = operations_for_caller(config, caller, profile)
    except Exception:
        return False
    return any(_entry_allows(entry, operation, now) for entry in entries)


# --- fixed SSH source read --------------------------------------------------


def build_ssh_argv(known_hosts_file: str = KNOWN_HOSTS_FILE) -> list[str]:
    return [
        SSH_BIN,
        "-F", "/dev/null",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts_file}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"HostKeyAlias={SOURCE_HOST}",
        "-o", "CheckHostIP=no",
        "-o", "ConnectTimeout=10",
        "-o", "ConnectionAttempts=1",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "GSSAPIAuthentication=no",
        "-o", "IdentityAgent=none",
        "-o", "ForwardAgent=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none",
        "-o", "ProxyCommand=none",
        "-o", "PermitLocalCommand=no",
        "-o", "LogLevel=ERROR",
        "-T",
        "-l", SOURCE_USER,
        "--", SOURCE_HOST,
        f"head -c {MAX_SOURCE_BYTES + 1} -- {SOURCE_PATH}",
    ]


def ssh_env() -> dict[str, str]:
    # Deliberately not derived from os.environ: no BWS token, credential paths, or agent socket.
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


@dataclass
class BoundedResult:
    returncode: int | None
    data: bytes
    timed_out: bool
    exceeded: bool


def run_bounded(argv: list[str], env: dict[str, str], timeout: float, max_bytes: int) -> BoundedResult:
    """Run argv, keeping at most max_bytes of stdout in memory; kill on deadline or overflow."""
    deadline = time.monotonic() + timeout
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, close_fds=True)
    buf = bytearray()
    timed_out = exceeded = False
    fd = proc.stdout.fileno()  # type: ignore[union-attr]
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(fd, min(4096, max_bytes + 1 - len(buf)))
            if not chunk:
                break
            buf += chunk
            if len(buf) > max_bytes:
                exceeded = True
                break
        if timed_out or exceeded:
            _kill(proc)
        try:
            returncode = proc.wait(timeout=max(deadline - time.monotonic(), 1.0))
        except subprocess.TimeoutExpired:
            _kill(proc)
            proc.wait()
            returncode, timed_out = None, True
    finally:
        proc.stdout.close()  # type: ignore[union-attr]
        if proc.poll() is None:
            _kill(proc)
            proc.wait()
    return BoundedResult(returncode, bytes(buf), timed_out, exceeded)


def _kill(proc: subprocess.Popen[bytes]) -> None:
    # No new session/group on purpose: inside the import worker this keeps ssh in
    # the worker's process group, so one group kill reaches both.
    try:
        proc.kill()
    except ProcessLookupError:
        pass


def check_known_hosts(path: str, trusted_uid: int = 0) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        raise GrafanaImportError("source_unconfigured") from None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != trusted_uid or st.st_mode & 0o022 or st.st_size == 0:
        raise GrafanaImportError("source_unconfigured")


def fetch_source_password(
    *,
    strip_single_trailing_newline: bool = False,
    known_hosts_file: str = KNOWN_HOSTS_FILE,
    trusted_uid: int = 0,
    runner: Callable[..., BoundedResult] = run_bounded,
) -> str:
    check_known_hosts(known_hosts_file, trusted_uid)
    try:
        result = runner(build_ssh_argv(known_hosts_file), ssh_env(), SSH_TIMEOUT_SECONDS, MAX_SOURCE_BYTES)
    except Exception:
        result = None
    if result is None:
        raise GrafanaImportError("source_unavailable")
    if result.timed_out:
        raise GrafanaImportError("source_timeout")
    if result.exceeded or len(result.data) > MAX_SOURCE_BYTES:
        raise GrafanaImportError("source_too_large")
    if result.returncode != 0:
        raise GrafanaImportError("source_unavailable")
    data = result.data
    if strip_single_trailing_newline and data.endswith(b"\n"):
        data = data[:-1]
    if not data or b"\x00" in data:
        raise GrafanaImportError("source_invalid")
    text: str | None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:  # the error object would carry the raw bytes
        text = None
    if text is None:
        raise GrafanaImportError("source_invalid")
    return text


# --- request handling -------------------------------------------------------

# Hooks so tests (and only tests) can swap the network-facing pieces.
RESOLVER_FACTORY: Callable[[], BwsResolver] = BwsResolver
SOURCE_FETCHER: Callable[..., str] = fetch_source_password

_LOCK = threading.Lock()


def _event(caller: str, profile: str, operation: str, phase: str, reason: str, **extra: Any) -> dict[str, Any]:
    event = {"event": operation, "caller": caller, "profile": profile, "grant": operation, "provider": "bws", "ttl_seconds": 0, "lease_id": "", "operation": operation, "phase": phase, "reason": reason}
    event.update(extra)
    return event


def _code_of(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and code in ERRORS else "internal_error"


def _failure(code: str) -> tuple[int, dict[str, Any]]:
    status, message = ERRORS[code]
    return status, {"error": message}


def _audit_best_effort(path: str, event: dict[str, Any]) -> None:
    try:
        write_audit_event(path, event)
    except Exception:
        LOG.error("audit write failed for %s", event.get("phase"))


def _execute(operation: str, cfg: ImportConfig | None) -> dict[str, Any]:
    if operation == OP_PROJECTS:
        return {"projects": RESOLVER_FACTORY().list_projects()}
    assert cfg is not None
    value = SOURCE_FETCHER(strip_single_trailing_newline=cfg.strip_single_trailing_newline)
    imported = RESOLVER_FACTORY().import_secret(project_id=cfg.project_id, key=DEST_KEY, value=value, note=DEST_NOTE, organization_id=cfg.organization_id)
    return {"id": imported.id, "key": imported.key, "project_id": imported.project_id, "status_verified": True, "created": imported.created}


def _worker_payload(operation: str, cfg: ImportConfig | None) -> dict[str, Any]:
    """What the worker sends back: sanitized metadata or a fixed error code. Never a value."""
    try:
        return {"ok": True, "result": _execute(operation, cfg)}
    except BaseException as exc:  # noqa: BLE001 - only a fixed code survives
        return {"ok": False, "code": _code_of(exc)}


def _decode_payload(operation: str, raw: bytes, cfg: ImportConfig | None) -> dict[str, Any]:
    """Parent-side strict validation of the worker's reply; anything unexpected is ``worker_failed``."""
    data: Any = None
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError:
        data = None
    if not isinstance(data, dict):
        raise GrafanaImportError("worker_failed")
    if data.get("ok") is False and set(data) == {"ok", "code"}:
        code = data["code"]
        raise GrafanaImportError(code if isinstance(code, str) and code in ERRORS else "worker_failed")
    result = data.get("result")
    if data.get("ok") is not True or set(data) != {"ok", "result"} or not isinstance(result, dict):
        raise GrafanaImportError("worker_failed")
    if operation == OP_PROJECTS:
        projects = result.get("projects")
        if set(result) != {"projects"} or not isinstance(projects, list) or len(projects) > 200:
            raise GrafanaImportError("worker_failed")
        for item in projects:
            if not isinstance(item, dict) or set(item) != {"id", "name"} or not _canonical_uuid(item["id"]) or not isinstance(item["name"], str):
                raise GrafanaImportError("worker_failed")
        return result
    if (
        cfg is None
        or set(result) != {"id", "key", "project_id", "status_verified", "created"}
        or not _canonical_uuid(result["id"])
        or result["key"] != DEST_KEY
        or result["project_id"] != cfg.project_id
        or result["status_verified"] is not True
        or not isinstance(result["created"], bool)
    ):
        raise GrafanaImportError("worker_failed")
    return result


def _kill_group(pid: int) -> None:
    for kill in (lambda: os.killpg(pid, signal.SIGKILL), lambda: os.kill(pid, signal.SIGKILL)):
        try:
            kill()
        except (ProcessLookupError, PermissionError):
            pass


def _worker_child(read_fd: int, write_fd: int, operation: str, cfg: ImportConfig | None) -> None:
    status = 70
    try:
        try:
            os.setpgid(0, 0)  # own group (not a new session) so the parent can kill ssh with us
            signal.alarm(int(OPERATION_TIMEOUT_SECONDS) + 5)  # self-limit even if the parent vanishes
            null = os.open(os.devnull, os.O_RDWR)
            for fd in (0, 1, 2):
                os.dup2(null, fd)
            os.closerange(3, write_fd)
            os.closerange(write_fd + 1, 1 << 20)
            os.environ.pop("RUST_LOG", None)
            payload = _worker_payload(operation, cfg)
        except BaseException:  # noqa: BLE001
            payload = {"ok": False, "code": "internal_error"}
        data = json.dumps(payload).encode()
        while data:
            data = data[os.write(write_fd, data):]
        status = 0
    finally:
        os._exit(status)


def _run_worker(operation: str, cfg: ImportConfig | None, timeout: float) -> dict[str, Any]:
    """Run the operation in a forked, killable child; only sanitized metadata comes back."""
    read_fd, write_fd = os.pipe()
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        _worker_child(read_fd, write_fd, operation, cfg)
    os.close(write_fd)
    try:
        os.setpgid(pid, pid)
    except OSError:
        pass  # the child already did it
    deadline = time.monotonic() + timeout
    buf = bytearray()
    timed_out = overflow = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if not select.select([read_fd], [], [], remaining)[0]:
                continue
            chunk = os.read(read_fd, 4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_WORKER_REPLY_BYTES:
                overflow = True
                break
    finally:
        os.close(read_fd)
        _kill_group(pid)  # also sweeps any ssh left behind
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    if timed_out:
        raise GrafanaImportError("timeout")
    if overflow:
        raise GrafanaImportError("worker_failed")
    return _decode_payload(operation, bytes(buf), cfg)


WORKER: Callable[[str, ImportConfig | None, float], dict[str, Any]] = _run_worker


def handle(config: dict[str, Any], audit_path: str, caller: str, operation: str, raw_body: bytes | None, *, now: datetime | None = None) -> tuple[int, dict[str, Any]]:
    """Run one fixed operation. Never raises; the response carries only fixed messages."""
    profile = ""
    try:
        try:
            profile = parse_request(raw_body)
        except GrafanaImportError as exc:
            _audit_best_effort(audit_path, _event(caller, "", operation, "denied", exc.code))
            return _failure(exc.code)
        if not is_authorized(config, caller, profile, operation, now or datetime.now(UTC)):
            _audit_best_effort(audit_path, _event(caller, profile, operation, "denied", "not_authorized"))
            return _failure("not_authorized")
        cfg = None
        if operation == OP_IMPORT:
            try:
                cfg = parse_import_config(config)
            except GrafanaImportError as exc:
                _audit_best_effort(audit_path, _event(caller, profile, operation, "denied", exc.code))
                return _failure(exc.code)
        extra = {"project_id": cfg.project_id} if cfg else {}
        return _run_serialized(audit_path, caller, profile, operation, cfg, extra)
    except Exception:
        LOG.error("grafana operation failed unexpectedly")
        _audit_best_effort(audit_path, _event(caller, profile, operation, "failed", "internal_error"))
        return _failure("internal_error")


def _run_serialized(audit_path: str, caller: str, profile: str, operation: str, cfg: ImportConfig | None, extra: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    if not _LOCK.acquire(timeout=BUSY_WAIT_SECONDS):
        _audit_best_effort(audit_path, _event(caller, profile, operation, "denied", "busy", **extra))
        return _failure("busy")
    try:
        try:
            write_audit_event(audit_path, _event(caller, profile, operation, "attempt", "attempt", **extra), durable=True)
        except Exception:
            LOG.error("attempt audit write failed; operation not started")
            return _failure("audit_unavailable")
        code = None
        result: dict[str, Any] = {}
        try:
            result = WORKER(operation, cfg, OPERATION_TIMEOUT_SECONDS)
        except GrafanaImportError as exc:
            code = exc.code
        except Exception:
            code = "internal_error"
        # Exactly one completion/failure event; the worker is already dead and reaped here.
        if code is not None:
            _audit_best_effort(audit_path, _event(caller, profile, operation, "failed", code, **extra))
            return _failure(code)
        if operation == OP_IMPORT:
            result = dict(result)
            created = result.pop("created")
            _audit_best_effort(audit_path, _event(caller, profile, operation, "completed", "created" if created else "already_present", record_id=result["id"], **extra))
        else:
            _audit_best_effort(audit_path, _event(caller, profile, operation, "completed", "listed", project_count=len(result["projects"])))
        return 200, result
    finally:
        _LOCK.release()
