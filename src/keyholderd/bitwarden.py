from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
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
        resolved: dict[str, str] = {}
        for logical_name, secret_ref in refs.items():
            resolved[logical_name] = self._get_secret(secret_ref)
        return resolved

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
                LOG.debug("Bitwarden cache hit for configured secret ref %s", secret_ref)
                return value
        cmd = ["bws", "secret", "get", secret_ref, "--output", "json"]
        LOG.debug("Resolving Bitwarden secret ref %s via bws", secret_ref)
        result = self.runner(cmd, capture_output=True, text=True, env=self._env(), timeout=30)
        if result.returncode != 0:
            raise BitwardenError(f"bws failed resolving {secret_ref!r}: {result.stderr.strip() or 'unknown error'}")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise BitwardenError(f"bws returned invalid JSON for {secret_ref!r}") from exc
        value = payload.get("value") or payload.get("secret") or payload.get("data", {}).get("value")
        if not isinstance(value, str) or not value:
            raise BitwardenError(f"bws response for {secret_ref!r} did not include a secret value")
        if self.cache_seconds > 0:
            self._cache[secret_ref] = (now + self.cache_seconds, value)
        return value


def resolve_bitwarden_refs(refs: dict[str, str], *, project_id: str | None = None, cache_seconds: int = 0) -> dict[str, str]:
    return BwsResolver(project_id=project_id, cache_seconds=cache_seconds).resolve_refs(refs)
