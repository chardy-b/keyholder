from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .base import IssuedCredential


class FakeProvider:
    name = "fake"

    def issue(self, grant: dict, secrets: dict[str, str], ttl_seconds: int) -> IssuedCredential:
        return IssuedCredential(
            provider=self.name,
            token_type="bearer",
            env={"FAKE_TOKEN": "fake-temporary-token"},
            display_token="fake-temporary-token",
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            scope_summary="fake:read",
        )
