from __future__ import annotations

import hmac
import json
import logging
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from collections.abc import Mapping
from typing import Any, Callable

LOG = logging.getLogger(__name__)


class BitwardenError(RuntimeError):
    """Raised when bws cannot resolve a configured secret."""


class BitwardenImportError(BitwardenError):
    """Import/metadata failure carrying only a fixed, value-free code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ImportedSecret:
    id: str
    key: str
    project_id: str
    created: bool


def _default_sdk_login(access_token: str) -> Any:
    # Token stays in broker memory; no state_file means the SDK writes no disk state.
    os.environ.pop("RUST_LOG", None)
    import bitwarden_sdk

    client = bitwarden_sdk.BitwardenClient()
    login = client.auth().login_access_token(access_token)
    if not login.success or login.data is None or not login.data.authenticated:
        raise BitwardenError("sdk login rejected")
    return client


@dataclass
class BwsResolver:
    project_id: str | None = None
    access_token_file: str | None = None
    cache_seconds: int = 0
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run
    sdk_login: Callable[[str], Any] | None = None
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

    def list_projects(self) -> list[dict[str, str]]:
        """Return only id/name of projects the machine account can access."""
        entries: Any = None
        try:
            listed = self.runner(["bws", "project", "list", "--output", "json"], capture_output=True, text=True, env=self._env(), timeout=30)
            if listed.returncode == 0:
                entries = json.loads(listed.stdout)
        except Exception:
            entries = None
        if not isinstance(entries, list):
            raise BitwardenImportError("projects_unavailable")
        projects: list[dict[str, str]] = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or not isinstance(entry.get("id"), str):
                continue
            try:
                canonical = str(uuid.UUID(entry["id"])) == entry["id"]
            except ValueError:
                continue
            if canonical:
                projects.append({"id": entry["id"], "name": "".join(c for c in entry["name"] if c.isprintable())[:128]})
        return sorted(projects, key=lambda p: (p["name"], p["id"]))[:200]

    def _read_access_token(self) -> str:
        token_file = self.access_token_file or os.environ.get("BWS_ACCESS_TOKEN_FILE")
        if not token_file:
            raise BitwardenError("no token file")
        with open(token_file, encoding="utf-8") as fh:
            token = fh.read().strip()
        if not token:
            raise BitwardenError("empty token")
        return token

    @staticmethod
    def _sdk_call(code: str, fn: Callable[..., Any], *args: Any) -> Any:
        # Failure is raised outside the except block so the SDK's error text
        # (which may echo server responses) never enters an exception chain.
        data: Any = None
        try:
            response = fn(*args)
            if response.success is True:
                data = response.data
        except Exception:
            data = None
        if data is None:
            raise BitwardenImportError(code)
        return data

    @staticmethod
    def _check_secret(secret: Any, *, secret_id: str, key: str, project_id: str, organization_id: str, value: str, identity_code: str, value_code: str) -> None:
        if not (
            str(secret.id) == secret_id
            and secret.key == key
            and str(secret.project_id) == project_id
            and str(secret.organization_id) == organization_id
        ):
            raise BitwardenImportError(identity_code)
        if not hmac.compare_digest(secret.value.encode("utf-8"), value.encode("utf-8")):
            raise BitwardenImportError(value_code)

    def import_secret(self, *, project_id: str, key: str, value: str, note: str, organization_id: str | None = None) -> ImportedSecret:
        """Create ``key`` in ``project_id`` unless an identical record already exists.

        Never updates or deletes. Create and readback run through the Bitwarden
        SDK in memory; the value is never placed in argv, env, logs, or errors.
        """
        client: Any = None
        try:
            client = (self.sdk_login or _default_sdk_login)(self._read_access_token())
        except Exception:
            client = None
        if client is None:
            raise BitwardenImportError("auth_failed")
        project = self._sdk_call("project_unavailable", client.projects().get, project_id)
        if str(project.id) != project_id or (organization_id is not None and str(project.organization_id) != organization_id):
            raise BitwardenImportError("project_mismatch")
        org = str(project.organization_id)
        listed = self._sdk_call("lookup_failed", client.secrets().list, org)
        matches = [item for item in listed.data if item.key == key and project.id in item.project_ids]
        if len(matches) > 1:
            raise BitwardenImportError("duplicate_records")
        if matches:
            existing_id = str(matches[0].id)
            existing = self._sdk_call("lookup_failed", client.secrets().get, existing_id)
            self._check_secret(existing, secret_id=existing_id, key=key, project_id=project_id, organization_id=org, value=value, identity_code="lookup_failed", value_code="value_differs")
            return ImportedSecret(existing_id, key, project_id, created=False)
        created = self._sdk_call("write_ambiguous", client.secrets().create, project.organization_id, key, value, note, [project.id])
        created_id = str(created.id)
        readback = self._sdk_call("write_ambiguous", client.secrets().get, created_id)
        self._check_secret(readback, secret_id=created_id, key=key, project_id=project_id, organization_id=org, value=value, identity_code="write_ambiguous", value_code="write_ambiguous")
        return ImportedSecret(created_id, key, project_id, created=True)

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
        if not isinstance(payload, Mapping):
            raise BitwardenError("bws returned an invalid secret response")
        if "value" in payload:
            value = payload["value"]
            if not isinstance(value, str) or not value:
                raise BitwardenError("bws response contained an invalid secret value")
        elif "secret" in payload:
            value = payload["secret"]
            if not isinstance(value, str) or not value:
                raise BitwardenError("bws response contained an invalid secret value")
        elif "data" in payload:
            data = payload["data"]
            if not isinstance(data, Mapping) or "value" not in data:
                raise BitwardenError("bws response contained an invalid secret value")
            value = data["value"]
            if not isinstance(value, str) or not value:
                raise BitwardenError("bws response contained an invalid secret value")
        else:
            raise BitwardenError("bws response did not include a secret value")
        if self.cache_seconds > 0:
            self._cache[secret_ref] = (now + self.cache_seconds, value)
        return value


def resolve_bitwarden_refs(refs: dict[str, str], *, project_id: str | None = None, cache_seconds: int = 0) -> dict[str, str]:
    return BwsResolver(project_id=project_id, cache_seconds=cache_seconds).resolve_refs(refs)
