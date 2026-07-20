from datetime import UTC, datetime
from keyholderd.providers.github_app import GitHubAppProvider


def test_github_app_posts_installation_token(monkeypatch):
    calls = []
    class Response:
        status_code = 201
        text = "ok"
        def json(self):
            return {"token":"ghs_token", "expires_at":"2030-01-01T00:00:00Z"}
        def raise_for_status(self): pass
    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append((url, headers, json, timeout)); return Response()
    monkeypatch.setattr("keyholderd.providers.github_app.jwt.encode", lambda payload, key, algorithm: "jwt-token")
    monkeypatch.setattr("keyholderd.providers.github_app.requests.post", fake_post)
    grant = {"app_id":"42", "installation_id":123, "permissions":{"metadata":"read", "contents":"read"}}
    cred = GitHubAppProvider().issue(grant, {"private_key_pem":"pem"}, 600)
    assert calls[0][0].endswith("/app/installations/123/access_tokens")
    assert calls[0][1]["Authorization"] == "Bearer jwt-token"
    assert calls[0][2]["permissions"] == grant["permissions"]
    assert cred.env["GITHUB_TOKEN"] == "ghs_token"
    assert cred.display_token == "ghs_token"
    assert cred.scope_summary == "contents:read metadata:read"
