from __future__ import annotations

import hashlib
import secrets as secrets_mod
from datetime import UTC, datetime, timedelta

from .base import IssuedCredential
from ..proxy import CapabilityStore, validated_proxy_grant


class LocalProxyProvider:
    name = "local_proxy"

    def __init__(self, store: CapabilityStore | None = None) -> None:
        self.store = store or CapabilityStore()

    def issue(self, grant: dict, secrets: dict[str, str], ttl_seconds: int) -> IssuedCredential:
        # Callers receive only an opaque capability. activate() keeps the upstream
        # key in the daemon-side store for the lifetime of the corresponding lease.
        token = "khcap_" + secrets_mod.token_urlsafe(32)
        routes = grant.get("allowed_routes", [])
        scope = " ".join(routes) if routes else "local_proxy"
        return IssuedCredential(
            provider=self.name,
            token_type="capability",
            display_token=token,
            env={"KEYHOLDER_CAPABILITY_TOKEN": token},
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            scope_summary=scope,
        )

    @staticmethod
    def validate(grant: dict, secrets: dict[str, str]) -> None:
        validated_proxy_grant(grant, secrets)

    @staticmethod
    def validate_grant(grant: dict) -> None:
        validated_proxy_grant(grant, {"upstream_api_key": "placeholder"})

    def activate(
        self,
        credential: IssuedCredential,
        lease_id: str,
        grant: dict,
        secrets: dict[str, str],
        caller: str = "",
        profile: str = "",
        grant_name: str = "",
    ) -> None:
        if credential.display_token is None:
            raise ValueError("local proxy credential is missing its capability token")
        self.store.register(
            token=credential.display_token,
            lease_id=lease_id,
            grant=grant,
            secrets=secrets,
            expires_at=credential.expires_at,
            caller=caller,
            profile=profile,
            grant_name=grant_name,
        )

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
