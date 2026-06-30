from __future__ import annotations

import hashlib
import secrets as secrets_mod
from datetime import UTC, datetime, timedelta

from .base import IssuedCredential


class LocalProxyProvider:
    name = "local_proxy"

    def issue(self, grant: dict, secrets: dict[str, str], ttl_seconds: int) -> IssuedCredential:
        # Deliberately ignore upstream_api_key for returned credential: callers get only
        # a local opaque capability that a future proxy can map server-side.
        token = "khcap_" + secrets_mod.token_urlsafe(32)
        routes = grant.get("allowed_routes", [])
        scope = " ".join(routes) if routes else "local_proxy"
        return IssuedCredential(
            provider=self.name,
            token_type="capability",
            env={"KEYHOLDER_CAPABILITY_TOKEN": token},
            display_token=token,
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            scope_summary=scope,
        )

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
