from __future__ import annotations

import json
import logging
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from collections.abc import Mapping
from typing import Callable

LOG = logging.getLogger(__name__)


class BitwardenError(RuntimeError):
    """Raised when bws cannot resolve a configured secret."""


@dataclass
class BwsResolver:
    project_id: str | None = None
    access_token_file: str | None = None
    cache_seconds: int = 0
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run
    _cache: dict[str, tuple[float, str]] = field(default_factory=dict)

    def resolve_refs(self, refs: dict[str, str]) -> dict[str, str]:
        if not isinstance(refs, Mapping):
            raise BitwardenError("Bitwarden references must be a mapping")
        for logical_name, secret_ref in refs.items():
            if not isinstance(logical_name, str) or not logical_name.strip():
                raise BitwardenError("Bitwarden reference names must be non-empty strings")
            self._validate_ref(secret_ref)
        resolved: dict[str, str] = {}
        for logical_name, secret_ref in refs.items():
            resolved[logical_name] = self._get_secret(secret_ref)
        return resolved

    @staticmethod
    def _validate_ref(secret_ref: object) -> None:
        if not isinstance(secret_ref, str):
            raise BitwardenError("Bitwarden secret references must be strings")
        if secret_ref.startswith("key:"):
            key = secret_ref[4:]
            if not key.strip() or len(key) > 256:
                raise BitwardenError("Bitwarden key reference is invalid")
            return
        try:
            parsed = uuid.UUID(secret_ref)
        except (ValueError, AttributeError):
            raise BitwardenError("Bitwarden secret reference is invalid") from None
        if str(parsed) != secret_ref:
            raise BitwardenError("Bitwarden secret reference is invalid")

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        token_file = self.access_token_file or env.get("BWS_ACCESS_TOKEN_FILE")
        if token_file:
            try:
                env["BWS_ACCESS_TOKEN"] = open(token_file, encoding="utf-8").read().strip()
            except OSError as exc:
                raise BitwardenError(f"failed to read BWS access token file: {exc}") from exc
        return env

    def _get_secret(self, secret_ref: str) -> str:
        now = time.monotonic()
        if self.cache_seconds > 0 and secret_ref in self._cache:
            expires_at, value = self._cache[secret_ref]
            if expires_at > now:
                LOG.debug("Bitwarden cache hit for configured secret reference")
                return value

        fetch_ref = secret_ref
        if secret_ref.startswith("key:"):
            key = secret_ref[4:]
            if not isinstance(self.project_id, str) or not self.project_id.strip():
                raise BitwardenError("Bitwarden project is required for key references")
            list_cmd = ["bws", "secret", "list", self.project_id, "--output", "json"]
            LOG.debug("Looking up Bitwarden secret key in configured project")
            listed = self.runner(list_cmd, capture_output=True, text=True, env=self._env(), timeout=30)
            if listed.returncode != 0:
                raise BitwardenError("bws failed listing secrets for key reference")
            try:
                entries = json.loads(listed.stdout)
            except json.JSONDecodeError as exc:
                raise BitwardenError("bws returned invalid JSON while listing key references") from exc
            if not isinstance(entries, list):
                raise BitwardenError("bws returned an invalid secret list")
            matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("key") == key]
            if len(matches) != 1 or not isinstance(matches[0].get("id"), str):
                raise BitwardenError("Bitwarden key reference did not resolve to exactly one secret")
            try:
                selected_id = uuid.UUID(matches[0]["id"])
            except (ValueError, AttributeError):
                raise BitwardenError("Bitwarden key reference returned an invalid secret id") from None
            if str(selected_id) != matches[0]["id"]:
                raise BitwardenError("Bitwarden key reference returned an invalid secret id")
            fetch_ref = matches[0]["id"]

        cmd = ["bws", "secret", "get", fetch_ref, "--output", "json"]
        LOG.debug("Resolving Bitwarden secret reference via bws")
        result = self.runner(cmd, capture_output=True, text=True, env=self._env(), timeout=30)
        if result.returncode != 0:
            raise BitwardenError("bws failed resolving Bitwarden secret reference")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise BitwardenError("bws returned invalid JSON for secret response") from exc
        if not isinstance(payload, dict):
            raise BitwardenError("bws returned an invalid secret response")
        data = payload.get("data", {})
        if not isinstance(data, dict):
            raise BitwardenError("bws returned an invalid secret response")
        value = payload.get("value") or payload.get("secret") or data.get("value")
        if not isinstance(value, str) or not value:
            raise BitwardenError("bws response did not include a secret value")
        if self.cache_seconds > 0:
            self._cache[secret_ref] = (now + self.cache_seconds, value)
        return value


def resolve_bitwarden_refs(refs: dict[str, str], *, project_id: str | None = None, cache_seconds: int = 0) -> dict[str, str]:
    return BwsResolver(project_id=project_id, cache_seconds=cache_seconds).resolve_refs(refs)
