from __future__ import annotations

import argparse
import http.client
import json
import socket
import sys
from typing import Any

DEFAULT_SOCKET = "/run/keyholder/keyholder.sock"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str):
        super().__init__("localhost")
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)


def request(socket_path: str, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    conn = UnixHTTPConnection(socket_path)
    body = None if payload is None else json.dumps(payload)
    conn.request(method, path, body=body, headers={"Content-Type":"application/json"})
    resp = conn.getresponse()
    text = resp.read().decode()
    data = json.loads(text or "{}")
    if resp.status >= 400:
        raise RuntimeError(data.get("error", text))
    return data


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="keyholder")
    p.add_argument("--socket", default=DEFAULT_SOCKET)
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grants"); g.add_argument("--profile", default="default")
    i = sub.add_parser("issue"); i.add_argument("grant"); i.add_argument("--ttl", type=int, default=None); i.add_argument("--reason", required=True); i.add_argument("--profile", default="default"); i.add_argument("--format", choices=["json", "env"], default="json")
    r = sub.add_parser("run"); r.add_argument("grant"); r.add_argument("--env", required=True, dest="env_var"); r.add_argument("--ttl", type=int, default=None); r.add_argument("--reason", required=True); r.add_argument("--profile", default="default")
    rv = sub.add_parser("revoke"); rv.add_argument("lease_id"); rv.add_argument("--reason", default="manual revoke")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args, extra = parser.parse_known_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    try:
        if args.cmd == "grants":
            data = request(args.socket, "GET", f"/v1/grants?profile={args.profile}")
            for grant in data.get("grants", []):
                print(f"{grant['name']:<24} {grant['provider']:<12} max TTL {grant['max_ttl_seconds']}s")
        elif args.cmd == "issue":
            data = request(args.socket, "POST", "/v1/issue", {"grant":args.grant, "ttl_seconds":args.ttl, "reason":args.reason, "profile":args.profile})
            if args.format == "json":
                print(json.dumps(data, sort_keys=True))
            else:
                if data.get("access_token"):
                    print(f"KEYHOLDER_TOKEN={data['access_token']}")
        elif args.cmd == "run":
            command = extra[1:] if extra and extra[0] == "--" else extra
            if not command:
                raise RuntimeError("run requires command after --")
            data = request(args.socket, "POST", "/v1/run", {"grant":args.grant, "env_var":args.env_var, "ttl_seconds":args.ttl, "reason":args.reason, "profile":args.profile, "command":command})
            sys.stdout.write(data.get("stdout", "")); sys.stderr.write(data.get("stderr", ""))
            return int(data.get("exit_code", 0))
        elif args.cmd == "revoke":
            print(json.dumps(request(args.socket, "POST", "/v1/revoke", {"lease_id":args.lease_id, "reason":args.reason})))
        return 0
    except Exception as exc:
        print(f"keyholder: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
