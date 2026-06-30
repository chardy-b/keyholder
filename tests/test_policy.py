import pytest
from keyholderd.policy import PolicyError, get_grant, grants_for_caller, load_policy, validate_ttl

VALID = {
    "version": 1,
    "callers": {
        "hermes": {
            "uid_name": "hermes",
            "profiles": {
                "default": {
                    "grants": [
                        {"name": "g1", "provider": "fake", "ttl_seconds": 60, "max_ttl_seconds": 120, "bitwarden_refs": {"token": "fake-token"}}
                    ]
                }
            },
        }
    },
}

def test_valid_policy_loads(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("version: 1\ncallers: {}\n")
    assert load_policy(str(p))["version"] == 1

def test_missing_version_fails(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("callers: {}\n")
    with pytest.raises(PolicyError):
        load_policy(str(p))

def test_unknown_caller_gets_no_grants():
    assert grants_for_caller(VALID, "nobody", "default") == []

def test_grant_lookup_requires_caller_and_profile():
    assert get_grant(VALID, "hermes", "default", "g1")["provider"] == "fake"
    with pytest.raises(PolicyError):
        get_grant(VALID, "hermes", "other", "g1")

def test_ttl_above_max_is_rejected():
    grant = get_grant(VALID, "hermes", "default", "g1")
    assert validate_ttl(grant, None) == 60
    assert validate_ttl(grant, 120) == 120
    with pytest.raises(PolicyError):
        validate_ttl(grant, 121)
