from __future__ import annotations

import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from typing import Any, Callable

from .audit import write_audit_event
from .bitwarden import BwsResolver, ImportedSecret
from .grafana_import import _canonical_uuid, _no_duplicate_keys
from .policy import secret_creates_for_caller
from .worker import run_forked

LOG = logging.getLogger(__name__)

ROUTE = "/v1/create-secret"
OPERATION = "secret_create"
# Separately named systemd credential; there is deliberately no fallback to the
# read-path ``bws-access-token`` / BWS_ACCESS_TOKEN_FILE.
CREDENTIAL_NAME = "bws-create-access-token"
MAX_VALUE_BYTES = 4096
MAX_REASON_CHARS = 200
# A 4 KiB value JSON-escapes to at most ~24 KiB (\u00XX per byte) plus the other fields.
MAX_BODY_BYTES = 32768
BODY_READ_SECONDS = 5.0
OPERATION_TIMEOUT_SECONDS = 60.0
MAX_WORKER_REPLY_BYTES = 4096
BUSY_WAIT_SECONDS = 1.0
NOTE = "Created by keyholder create-secret"

PROFILE_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
GRANT_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}")
KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_PREFIX_RE = re.compile(r"[A-Z][A-Z0-9_]{0,62}_")
_ENTRY_KEYS = {"name", "project_id", "key_prefix", "organization_id"}

# code -> (HTTP status, fixed message, write state). "not_written" codes are
# definite: they happen before the create call is made.
ERRORS: dict[str, tuple[int, str, str]] = {
    "invalid_request": (400, "invalid request", "not_written"),
    "not_authorized": (403, "not authorized", "not_written"),
    "key_not_allowed": (403, "key is outside the allowed namespace; nothing was written", "not_written"),
    "not_configured": (503, "secret creation is not configured; nothing was written", "not_written"),
    "busy": (429, "another keyholder operation is in progress; nothing was written", "not_written"),
    "audit_unavailable": (503, "audit log unavailable; nothing was written", "not_written"),
    "auth_failed": (502, "bitwarden authentication failed; nothing was written", "not_written"),
    "project_unavailable": (502, "destination project is not accessible; nothing was written", "not_written"),
    "project_mismatch": (503, "destination project does not match policy; nothing was written", "not_written"),
    "lookup_failed": (502, "bitwarden lookup failed; nothing was written", "not_written"),
    "already_exists": (409, "a secret with this key already exists; nothing was written", "not_written"),
    "write_ambiguous": (502, "write outcome unknown; the secret may exist, check before retrying", "unknown"),
    "timeout": (504, "operation timed out; the secret may exist, check before retrying", "unknown"),
    "worker_failed": (502, "worker failed; the secret may exist, check before retrying", "unknown"),
    "internal_error": (500, "internal error; nothing was written", "not_written"),
}
# Codes the worker may report back; anything else from the worker is worker_failed.
_WORKER_CODES = {"auth_failed", "project_unavailable", "project_mismatch", "lookup_failed", "already_exists", "write_ambiguous"}


class SecretCreateError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code if code in ERRORS else "internal_error"


@dataclass(frozen=True)
class CreateRequest:
    profile: str
    grant: str
    key: str
    value: str
    reason: str


@dataclass(frozen=True)
class CreateGrant:
    name: str
    project_id: str
    key_prefix: str
    organization_id: str | None


def parse_request(raw: bytes | None) -> CreateRequest:
    """Strict schema: grant, key, value, reason and optional profile; nothing else."""
    if raw is None or len(raw) > MAX_BODY_BYTES:
        raise SecretCreateError("invalid_request")
    data: Any = None
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except ValueError:  # raised outside the handler below so no chain keeps the body
        data = None
    if not isinstance(data, dict) or not {"grant", "key", "value", "reason"} <= set(data) <= {"grant", "key", "value", "reason", "profile"}:
        raise SecretCreateError("invalid_request")
    profile, grant, key, value, reason = data.get("profile", "default"), data["grant"], data["key"], data["value"], data["reason"]
    if not (
        isinstance(profile, str) and PROFILE_RE.fullmatch(profile)
        and isinstance(grant, str) and GRANT_RE.fullmatch(grant)
        and isinstance(key, str) and KEY_RE.fullmatch(key)
        and valid_reason(reason)
        and valid_value(value)
    ):
        raise SecretCreateError("invalid_request")
    return CreateRequest(profile, grant, key, value, reason)


def valid_reason(reason: object) -> bool:
    return isinstance(reason, str) and 0 < len(reason) <= MAX_REASON_CHARS and reason.strip() != "" and reason.isprintable()


def valid_value(value: object) -> bool:
    """Non-empty UTF-8 text without NUL, at most MAX_VALUE_BYTES encoded."""
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    size = -1
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:  # lone surrogates; the error object would hold the value
        size = -1
    return 0 < size <= MAX_VALUE_BYTES


def find_grant(config: dict[str, Any], caller: str, profile: str, name: str) -> CreateGrant:
    if caller == "keyholder":  # generic run children have this identity too
        raise SecretCreateError("not_authorized")
    entries: list[Any] = []
    try:
        entries = [e for e in secret_creates_for_caller(config, caller, profile) if isinstance(e, dict) and e.get("name") == name]
    except Exception:
        entries = []
    if not entries:
        raise SecretCreateError("not_authorized")
    entry = entries[0] if len(entries) == 1 else None  # duplicate names fail closed
    if (
        not isinstance(entry, dict)
        or set(entry) - _ENTRY_KEYS
        or not _canonical_uuid(entry.get("project_id"))
        or not isinstance(entry.get("key_prefix"), str)
        or not _PREFIX_RE.fullmatch(entry["key_prefix"])
        or (entry.get("organization_id") is not None and not _canonical_uuid(entry["organization_id"]))
    ):
        raise SecretCreateError("not_configured")
    return CreateGrant(name, entry["project_id"], entry["key_prefix"], entry.get("organization_id"))


def credential_path() -> str:
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    path = os.path.join(directory, CREDENTIAL_NAME)
    if not os.path.isabs(directory) or not os.path.isfile(path):
        raise SecretCreateError("not_configured")
    return path


# --- worker -----------------------------------------------------------------

# Hooks so tests (and only tests) can swap the network-facing pieces.
RESOLVER_FACTORY: Callable[[str], BwsResolver] = lambda token_file: BwsResolver(access_token_file=token_file)
LAUNCHER: Callable[[Callable[[], dict[str, Any]], float, int], tuple[str, bytes]] = run_forked

_LOCK = threading.Lock()


def _worker_payload(grant: CreateGrant, request: CreateRequest, token_file: str) -> dict[str, Any]:
    """Runs in the worker: sanitized metadata or a fixed code, never the value."""
    try:
        created: ImportedSecret = RESOLVER_FACTORY(token_file).import_secret(
            project_id=grant.project_id,
            key=request.key,
            value=request.value,
            note=NOTE,
            organization_id=grant.organization_id,
            create_only=True,
        )
        return {"ok": True, "result": {"id": created.id, "key": created.key, "created": created.created}}
    except BaseException as exc:  # noqa: BLE001 - only a fixed code survives
        code = getattr(exc, "code", None)
        return {"ok": False, "code": code if code in _WORKER_CODES else "worker_failed"}


def decode_reply(raw: bytes, key: str) -> str:
    """Parent-side strict validation; returns the new record id."""
    data: Any = None
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except ValueError:
        data = None
    if isinstance(data, dict) and data.get("ok") is False and set(data) == {"ok", "code"}:
        code = data["code"]
        raise SecretCreateError(code if isinstance(code, str) and code in _WORKER_CODES else "worker_failed")
    result = data.get("result") if isinstance(data, dict) else None
    if (
        not isinstance(data, dict)
        or data.get("ok") is not True
        or set(data) != {"ok", "result"}
        or not isinstance(result, dict)
        or set(result) != {"id", "key", "created"}
        or not _canonical_uuid(result["id"])
        or result["key"] != key
        or result["created"] is not True
    ):
        raise SecretCreateError("worker_failed")
    return result["id"]


# --- request handling -------------------------------------------------------


def _event(caller: str, profile: str, grant: str, phase: str, code: str, **extra: Any) -> dict[str, Any]:
    # Only policy-matched names, policy IDs, and fixed codes: never the key, value, or reason.
    event = {"event": OPERATION, "caller": caller, "profile": profile, "grant": grant, "provider": "bws", "ttl_seconds": 0, "lease_id": "", "operation": OPERATION, "phase": phase, "reason": code}
    if phase in ("denied", "failed"):
        event["write_state"] = ERRORS[code][2]
    event.update(extra)
    return event


def _failure(code: str) -> tuple[int, dict[str, Any]]:
    status, message, _state = ERRORS[code]
    return status, {"error": message}


def _audit_best_effort(path: str, event: dict[str, Any]) -> None:
    try:
        write_audit_event(path, event)
    except Exception:
        LOG.error("audit write failed for %s", event.get("phase"))


def handle(config: dict[str, Any], audit_path: str, caller: str, raw_body: bytes | None) -> tuple[int, dict[str, Any]]:
    """One create-only request. Never raises; responses carry only fixed messages or id/key."""
    profile = grant_name = ""
    try:
        request: CreateRequest | None = None
        code = None
        try:
            request = parse_request(raw_body)
        except SecretCreateError as exc:
            code = exc.code
        if request is None:
            _audit_best_effort(audit_path, _event(caller, "", "", "denied", code or "invalid_request"))
            return _failure(code or "invalid_request")
        grant: CreateGrant | None = None
        try:
            grant = find_grant(config, caller, request.profile, request.grant)
            profile, grant_name = request.profile, grant.name
            if not request.key.startswith(grant.key_prefix) or request.key == grant.key_prefix:
                raise SecretCreateError("key_not_allowed")
            token_file = credential_path()
        except SecretCreateError as exc:
            _audit_best_effort(audit_path, _event(caller, profile, grant_name, "denied", exc.code))
            return _failure(exc.code)
        return _run_serialized(audit_path, caller, grant, request, token_file)
    except Exception:
        # Only reachable before the attempt: _run_serialized handles everything after it.
        LOG.error("secret create failed unexpectedly")
        _audit_best_effort(audit_path, _event(caller, profile, grant_name, "failed", "internal_error"))
        return _failure("internal_error")


def _run_serialized(audit_path: str, caller: str, grant: CreateGrant, request: CreateRequest, token_file: str) -> tuple[int, dict[str, Any]]:
    extra = {"project_id": grant.project_id}
    if not _LOCK.acquire(timeout=BUSY_WAIT_SECONDS):
        _audit_best_effort(audit_path, _event(caller, request.profile, grant.name, "denied", "busy", **extra))
        return _failure("busy")
    try:
        try:
            write_audit_event(audit_path, _event(caller, request.profile, grant.name, "attempt", "attempt", **extra), durable=True)
        except Exception:
            LOG.error("attempt audit write failed; secret create not started")
            return _failure("audit_unavailable")
        code = None
        record_id = ""
        try:
            outcome, raw = LAUNCHER(lambda: _worker_payload(grant, request, token_file), OPERATION_TIMEOUT_SECONDS, MAX_WORKER_REPLY_BYTES)
            if outcome == "timeout":
                code = "timeout"
            elif outcome != "ok":
                code = "worker_failed"
            else:
                record_id = decode_reply(raw, request.key)
        except SecretCreateError as exc:
            code = exc.code
        except Exception:
            code = "worker_failed"
        if code is not None:
            _audit_best_effort(audit_path, _event(caller, request.profile, grant.name, "failed", code, **extra))
            return _failure(code)
        _audit_best_effort(audit_path, _event(caller, request.profile, grant.name, "completed", "created", write_state="written", record_id=record_id, **extra))
        return 200, {"id": record_id, "key": request.key}
    finally:
        _LOCK.release()
