from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import requests

from .base import IssuedCredential


class GoogleOAuthProvider:
    name = "google_oauth"
    timeout_seconds = 15
    clock_skew_seconds = 60
    min_expires_in = 60
    max_expires_in = 86_400

    def issue(self, grant: dict, secrets: dict[str, str], ttl_seconds: int) -> IssuedCredential:
        endpoint = grant.get("token_endpoint", "https://oauth2.googleapis.com/token")
        self.validate(grant)
        session = requests.Session()
        session.trust_env = False
        try:
            response = session.post(
                url=endpoint,
                data={
                    "client_id": secrets["client_id"],
                    "client_secret": secrets["client_secret"],
                    "refresh_token": secrets["refresh_token"],
                    "grant_type": "refresh_token",
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
        finally:
            session.close()
        if not isinstance(payload, dict):
            raise ValueError("Google OAuth response must be an object")
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise ValueError("Google OAuth response access_token must be a nonempty string")
        token_type = payload.get("token_type")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise ValueError("Google OAuth token_type must be Bearer")
        expires_in = payload.get("expires_in")
        if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)) or not math.isfinite(expires_in):
            raise ValueError("Google OAuth expires_in must be finite numeric")
        if not self.min_expires_in <= expires_in <= self.max_expires_in:
            raise ValueError("Google OAuth expires_in is outside safe bounds")
        expires_at = datetime.now(UTC) + timedelta(seconds=max(0, expires_in - self.clock_skew_seconds))
        return IssuedCredential(self.name, "Bearer", {"GOOGLE_WORKSPACE_CLI_TOKEN": token}, token, expires_at, "Google OAuth refresh-token grant")

    @classmethod
    def validate(cls, grant: dict) -> None:
        endpoint = grant.get("token_endpoint", "https://oauth2.googleapis.com/token")
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("google_oauth token_endpoint must be a strict HTTPS URL")
