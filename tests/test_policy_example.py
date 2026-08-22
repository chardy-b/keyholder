from pathlib import Path

import yaml


POLICY_PATH = Path(__file__).parents[1] / "packaging" / "policy.example.yaml"


def _grants():
    policy = yaml.safe_load(POLICY_PATH.read_text())
    return policy["callers"]["hermes"]["profiles"]["default"]["grants"]


def test_example_keeps_distinct_tcp_and_peercred_openrouter_grants():
    grants = {grant["name"]: grant for grant in _grants()}

    tcp = grants["openrouter-chat-proxy"]
    assert tcp["provider"] == "local_proxy"
    assert tcp.get("authentication", "capability") == "capability"
    assert tcp["allowed_methods"] == ["POST"]
    assert tcp["allowed_routes"] == ["/v1/chat/completions"]
    assert "allowed_models" not in tcp

    peer = grants["openrouter-chat-peer-proxy"]
    assert peer["provider"] == "local_proxy"
    assert peer["authentication"] == "peercred"
    assert peer["allowed_methods"] == ["POST"]
    assert peer["allowed_routes"] == ["/v1/chat/completions"]
    assert peer["allowed_models"] == ["stealth/ox-alpha"]
