from __future__ import annotations

from datetime import UTC, datetime

import jwt
import requests

from .base import IssuedCredential


class GitHubAppProvider:
    name = "github_app"

    def issue(self, grant: dict, secrets: dict[str, str], ttl_seconds: int) -> IssuedCredential:
        now = int(datetime.now(UTC).timestamp())
        app_id = str(secrets["app_id"])
        payload = {"iat": now - 60, "exp": now + min(ttl_seconds, 600), "iss": app_id}
        signed = jwt.encode(payload, secrets["private_key_pem"], algorithm="RS256")
        installation_id = grant["installation_id"]
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        body = {"permissions": grant.get("permissions", {})}
        response = requests.post(
            url,
            headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {signed}", "X-GitHub-Api-Version": "2022-11-28"},
            json=body,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        expires = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        token = data["token"]
        perms = grant.get("permissions", {})
        scope = " ".join(f"{k}:{v}" for k, v in sorted(perms.items()))
        return IssuedCredential(self.name, "bearer", {"GITHUB_TOKEN": token}, token, expires, scope)
