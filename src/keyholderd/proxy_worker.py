from __future__ import annotations

import base64
import json
import sys
from typing import Any

from .proxy import _direct_upstream_request


def main() -> int:
    try:
        payload: dict[str, Any] = json.load(sys.stdin.buffer)
        response = _direct_upstream_request(
            method=str(payload["method"]),
            url=str(payload["url"]),
            headers={str(name): str(value) for name, value in payload["headers"].items()},
            body=base64.b64decode(payload["body"], validate=True),
            max_response_bytes=int(payload["max_response_bytes"]),
            timeout_seconds=float(payload["timeout_seconds"]),
        )
        output = {
            "ok": True,
            "status": response.status,
            "headers": response.headers,
            "body": base64.b64encode(response.body).decode("ascii"),
        }
    except Exception as exc:
        output = {"ok": False, "failure_type": type(exc).__name__}
    sys.stdout.write(json.dumps(output, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
