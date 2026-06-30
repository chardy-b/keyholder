from datetime import UTC, datetime, timedelta
from keyholderd.providers.fake import FakeProvider
from keyholderd.providers.local_proxy import LocalProxyProvider


def test_fake_provider_issues_expected_env():
    cred = FakeProvider().issue({"name":"fake"}, {}, 30)
    assert cred.env["FAKE_TOKEN"] == "fake-temporary-token"
    assert cred.display_token == "fake-temporary-token"


def test_local_proxy_never_returns_upstream_static_key():
    cred = LocalProxyProvider().issue({"name":"proxy", "allowed_routes":["/v1/chat/completions"]}, {"upstream_api_key":"real-secret"}, 60)
    assert cred.display_token != "real-secret"
    assert cred.env["KEYHOLDER_CAPABILITY_TOKEN"] == cred.display_token
    assert cred.scope_summary == "/v1/chat/completions"
