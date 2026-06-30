import json
from keyholderd import cli


def test_keyholder_grants(monkeypatch, capsys):
    monkeypatch.setattr(cli, "request", lambda *a, **k: {"grants":[{"name":"fake", "provider":"fake", "max_ttl_seconds":60}]})
    assert cli.main(["grants"]) == 0
    assert "fake" in capsys.readouterr().out


def test_keyholder_issue_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "request", lambda *a, **k: {"access_token":"tok", "lease_id":"l1"})
    assert cli.main(["issue", "fake", "--ttl", "30", "--reason", "test", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["lease_id"] == "l1"


def test_keyholder_run(monkeypatch, capsys):
    def fake_request(sock, method, path, payload=None):
        assert payload["command"] == ["echo", "hi"]
        return {"exit_code":0, "stdout":"hi\n", "stderr":""}
    monkeypatch.setattr(cli, "request", fake_request)
    assert cli.main(["run", "fake", "--env", "FAKE_TOKEN", "--ttl", "30", "--reason", "test", "--", "echo", "hi"]) == 0
    assert capsys.readouterr().out == "hi\n"


def test_cli_refuses_without_reason():
    assert cli.main(["issue", "fake", "--ttl", "30"]) != 0
