from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True)
class IssuedCredential:
    provider: str
    token_type: str
    env: dict[str, str]
    display_token: str | None
    expires_at: datetime
    scope_summary: str


class Provider(Protocol):
    name: str

    def issue(self, grant: dict, secrets: dict[str, str], ttl_seconds: int) -> IssuedCredential:
        ...
