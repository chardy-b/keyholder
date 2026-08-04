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
    min_usable_lifetime_seconds = 1
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
        adjusted_lifetime = expires_in - self.clock_skew_seconds
        if adjusted_lifetime < self.min_usable_lifetime_seconds:
            raise ValueError("Google OAuth expires_in leaves no usable credential lifetime")
        expires_at = datetime.now(UTC) + timedelta(seconds=adjusted_lifetime)
        return IssuedCredential(self.name, "Bearer", {"GOOGLE_WORKSPACE_CLI_TOKEN": token}, token, expires_at, "Google OAuth refresh-token grant")

    @classmethod
    def validate(cls, grant: dict) -> None:
        if not isinstance(grant, dict):
            raise ValueError("google_oauth grant must be an object")
        endpoint = grant.get("token_endpoint", "https://oauth2.googleapis.com/token")
        if not isinstance(endpoint, str) or not endpoint:
            raise ValueError("google_oauth token_endpoint must be a strict HTTPS URL")
        try:
            parsed = urlparse(endpoint)
        except ValueError as exc:
            raise ValueError("google_oauth token_endpoint must be a strict HTTPS URL") from exc
        try:
            hostname = parsed.hostname
        except ValueError as exc:
            raise ValueError("google_oauth token_endpoint must be a strict HTTPS URL") from exc
        if parsed.scheme != "https" or not hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("google_oauth token_endpoint must be a strict HTTPS URL")

    @classmethod
    def validate_secret_refs(cls, refs: object) -> None:
        if not isinstance(refs, dict):
            raise ValueError("google_oauth bitwarden_refs must be an object")
        required = ("client_id", "client_secret", "refresh_token")
        if any(not isinstance(refs.get(name), str) or not refs[name].strip() for name in required):
            raise ValueError("google_oauth bitwarden_refs must contain nonempty client_id, client_secret, and refresh_token strings")
