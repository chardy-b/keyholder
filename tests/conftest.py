import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


import json

import pytest


@pytest.fixture
def short_socket():
    # Deep checkout/pytest paths may exceed Linux's 108-byte AF_UNIX limit.
    with tempfile.TemporaryDirectory(prefix="kh") as directory:
        yield str(Path(directory) / "s")


@pytest.fixture(autouse=True)
def inline_grafana_worker(monkeypatch):
    """Run the Grafana worker in-process so mocks and recorded state stay visible.

    The forked worker has its own tests (test_grafana_import_worker.py and the
    real-process case in test_grafana_import_e2e.py), which restore gi._run_worker.
    """
    from keyholderd import grafana_import as gi

    monkeypatch.setattr(gi, "WORKER", lambda op, cfg, timeout: gi._decode_payload(op, json.dumps(gi._worker_payload(op, cfg)).encode(), cfg))
