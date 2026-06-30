from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FORBIDDEN_KEYS = {"access_token", "refresh_token", "secret", "private_key", "upstream_api_key"}


class SecretInAuditError(ValueError):
    """Raised when an audit record attempts to include a secret value."""


def _check_no_secret_keys(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in FORBIDDEN_KEYS or key_text.endswith("_secret") or key_text.endswith("_token") and key_text not in {"capability_token_hash"}:
                raise SecretInAuditError(f"audit event contains forbidden secret-like key: {path + str(key)}")
            _check_no_secret_keys(child, f"{path}{key}.")
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            _check_no_secret_keys(child, f"{path}{idx}.")


def sanitize_event(event: dict[str, Any]) -> dict[str, Any]:
    _check_no_secret_keys(event)
    clean = dict(event)
    clean.setdefault("timestamp", datetime.now(UTC).isoformat())
    return clean


def write_audit_event(path: str, event: dict[str, Any]) -> None:
    clean = sanitize_event(event)
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(clean, sort_keys=True, separators=(",", ":")) + "\n")
