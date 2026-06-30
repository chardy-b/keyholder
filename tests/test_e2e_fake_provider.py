import json
import os
import sys
import threading
import time
from pathlib import Path

from keyholderd.cli import main as cli_main
from keyholderd.server import UnixHTTPServer


def test_e2e_fake_provider(tmp_path, capsys):
    sock = str(tmp_path/"keyholder.sock")
    current_user = os.environ.get("USER", "hermes")
    cfg = {"version":1, "paths":{"leases_db":str(tmp_path/"leases.db"), "audit_log":str(tmp_path/"audit.jsonl")}, "callers":{"me":{"uid_name":current_user, "profiles":{"default":{"grants":[{"name":"fake", "provider":"fake", "ttl_seconds":30, "max_ttl_seconds":60, "bitwarden_refs":{}}]}}}}}
    httpd = UnixHTTPServer(sock, cfg)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        assert cli_main(["--socket", sock, "grants"]) == 0
        assert "fake" in capsys.readouterr().out
        assert cli_main(["--socket", sock, "issue", "fake", "--ttl", "30", "--reason", "e2e", "--format", "json"]) == 0
        issued = json.loads(capsys.readouterr().out)
        assert issued["access_token"] == "fake-temporary-token"
        assert cli_main(["--socket", sock, "run", "fake", "--env", "FAKE_TOKEN", "--ttl", "30", "--reason", "e2e", "--", sys.executable, "-c", "import os; print(os.environ['FAKE_TOKEN'])"]) == 0
        assert "fake-temporary-token" in capsys.readouterr().out
        assert (tmp_path/"audit.jsonl").exists()
        assert (tmp_path/"leases.db").exists()
    finally:
        httpd.shutdown(); httpd.server_close()
