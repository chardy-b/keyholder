from __future__ import annotations

import argparse
import grp
import http.client
import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import secret_create
from .grafana_import import BoundedResult, run_bounded
from .policy import load_policy

DEFAULT_SOCKET = "/run/keyholder/keyholder.sock"
DEFAULT_CREATE_SOCKET = "/run/keyholder-secret-writer/keyholder.sock"
DEFAULT_POLICY = "/etc/keyholder/policy.yaml"
DEFAULT_CRED = "/etc/keyholder/bws-access-token.cred"
CLIENT_GROUP = "keyholder-clients"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, *, timeout: float | None = None):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
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


# --- create-secret --------------------------------------------------------
# Nothing on this path prints caller input, generator output, raw daemon
# replies, or exception text: only the fixed messages below or id/key.

GENERATOR_TIMEOUT_SECONDS = 10.0
CREATE_REPLY_TIMEOUT_SECONDS = secret_create.BODY_READ_SECONDS + secret_create.OPERATION_TIMEOUT_SECONDS + 15
MAX_CREATE_REPLY_BYTES = 8192
CREATE_USAGE = (
    "usage: keyholder [--socket PATH] create-secret --grant NAME --key KEY --reason TEXT\n"
    "                 [--profile NAME] [--raw] -- GENERATOR [ARG ...]\n"
    "Runs GENERATOR locally (no shell, stdin/stderr discarded) and stores its stdout\n"
    "(max 4096 bytes; one trailing LF removed unless --raw) as a new secret.\n"
)
CREATE_MESSAGES = {
    "usage": "invalid create-secret arguments (see keyholder create-secret --help)",
    "generator_failed": "generator failed; nothing was sent",
    "generator_timeout": "generator timed out; nothing was sent",
    "generator_too_large": "generator output exceeds 4096 bytes; nothing was sent",
    "generator_invalid": "generator output is empty, contains NUL, or is not valid UTF-8; nothing was sent",
    "connect_failed": "could not connect to the keyholder daemon; nothing was sent",
    "no_reply": "no valid reply from the keyholder daemon; the secret may exist, check before retrying",
}
_DAEMON_MESSAGES = {message: status for status, message, _state in secret_create.ERRORS.values()}
_CREATE_OPTS = ("--grant", "--key", "--reason", "--profile")


class CreateSecretError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.message = CREATE_MESSAGES.get(code, code)


def _split_create_secret(argv: list[str]) -> tuple[str, list[str]] | None:
    """If argv is ``[--socket PATH] create-secret ...`` return (socket, rest)."""
    socket_path, i = DEFAULT_CREATE_SOCKET, 0
    while i < len(argv):
        if argv[i] == "--socket" and i + 1 < len(argv):
            socket_path, i = argv[i + 1], i + 2
        elif argv[i].startswith("--socket="):
            socket_path, i = argv[i][len("--socket="):], i + 1
        else:
            break
    if i < len(argv) and argv[i] == "create-secret":
        return socket_path, argv[i + 1:]
    return None


def parse_create_secret(rest: list[str]) -> tuple[dict[str, Any], list[str]]:
    opts: dict[str, Any] = {"--raw": False}
    i = 0
    while i < len(rest) and rest[i] != "--":
        name, eq, val = rest[i].partition("=")
        if rest[i] == "--raw" and not opts["--raw"]:
            opts["--raw"] = True
            i += 1
            continue
        if name not in _CREATE_OPTS or name in opts:
            raise CreateSecretError("usage")
        if not eq:
            if i + 1 >= len(rest):
                raise CreateSecretError("usage")
            val, i = rest[i + 1], i + 1
        opts[name] = val
        i += 1
    command = rest[i + 1:]
    opts.setdefault("--profile", "default")
    if (
        i >= len(rest) or not command
        or not all(name in opts for name in _CREATE_OPTS)
        or not secret_create.GRANT_RE.fullmatch(opts["--grant"])
        or not secret_create.KEY_RE.fullmatch(opts["--key"])
        or not secret_create.PROFILE_RE.fullmatch(opts["--profile"])
        or not secret_create.valid_reason(opts["--reason"])
    ):
        raise CreateSecretError("usage")
    return opts, command


def _run_generator(command: list[str], env: dict[str, str], timeout: float, max_bytes: int) -> BoundedResult:
    return run_bounded(command, env, timeout, max_bytes, own_group=True)


def generate_value(command: list[str], *, raw: bool, runner: Callable[..., BoundedResult] = _run_generator) -> str:
    """Run the trusted generator as the caller and return its stdout as the value."""
    result: BoundedResult | None = None
    try:
        result = runner(command, dict(os.environ), GENERATOR_TIMEOUT_SECONDS, secret_create.MAX_VALUE_BYTES)
    except Exception:  # e.g. not found: the error text would name argv
        result = None
    if result is None:
        raise CreateSecretError("generator_failed")
    if result.timed_out:
        raise CreateSecretError("generator_timeout")
    if result.exceeded or len(result.data) > secret_create.MAX_VALUE_BYTES:
        raise CreateSecretError("generator_too_large")
    if result.returncode != 0:
        raise CreateSecretError("generator_failed")
    data = result.data
    if not raw and data.endswith(b"\n"):
        data = data[:-1]
    text: str | None = None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:  # the error object would carry the bytes
        text = None
    if text is None or not secret_create.valid_value(text):
        raise CreateSecretError("generator_invalid")
    return text


def _post_create(socket_path: str, body: bytes) -> tuple[int, bytes]:
    conn = UnixHTTPConnection(socket_path, timeout=CREATE_REPLY_TIMEOUT_SECONDS)
    try:
        try:
            conn.connect()
            conn.sock.settimeout(CREATE_REPLY_TIMEOUT_SECONDS)
        except Exception:
            conn.close()
            raise CreateSecretError("connect_failed") from None
        try:
            conn.request("POST", secret_create.ROUTE, body=body, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            return resp.status, resp.read(MAX_CREATE_REPLY_BYTES + 1)
        except Exception:
            raise CreateSecretError("no_reply") from None
    finally:
        conn.close()


def validate_create_reply(status: int, raw: bytes, key: str) -> dict[str, str]:
    data: Any = None
    try:
        if len(raw) <= MAX_CREATE_REPLY_BYTES:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=secret_create._no_duplicate_keys)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        raise CreateSecretError("no_reply")
    if status == 200 and set(data) == {"id", "key"} and data["key"] == key and secret_create._canonical_uuid(data["id"]):
        return {"id": data["id"], "key": key}
    message = data.get("error")
    if status != 200 and set(data) == {"error"} and isinstance(message, str) and _DAEMON_MESSAGES.get(message) == status:
        raise CreateSecretError(message)
    raise CreateSecretError("no_reply")


def run_create_secret(socket_path: str, rest: list[str]) -> int:
    try:
        if rest in (["--help"], ["-h"]):
            sys.stdout.write(CREATE_USAGE)
            return 0
        opts, command = parse_create_secret(rest)
        value = generate_value(command, raw=opts["--raw"])
        body = json.dumps({"grant": opts["--grant"], "key": opts["--key"], "value": value, "reason": opts["--reason"], "profile": opts["--profile"]}, ensure_ascii=False).encode("utf-8")
        del value
        status, raw = _post_create(socket_path, body)
        del body
        print(json.dumps(validate_create_reply(status, raw, opts["--key"]), sort_keys=True))
        return 0
    except CreateSecretError as exc:
        message = exc.message
    except Exception:
        message = CREATE_MESSAGES["no_reply"]
    print(f"keyholder: {message}", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="keyholder")
    p.add_argument("--socket", default=DEFAULT_SOCKET)
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grants"); g.add_argument("--profile", default="default")
    i = sub.add_parser("issue"); i.add_argument("grant"); i.add_argument("--ttl", type=int, default=None); i.add_argument("--reason", required=True); i.add_argument("--profile", default="default"); i.add_argument("--format", choices=["json", "env"], default="json")
    r = sub.add_parser("run"); r.add_argument("grant"); r.add_argument("--env", required=True, dest="env_var"); r.add_argument("--ttl", type=int, default=None); r.add_argument("--reason", required=True); r.add_argument("--profile", default="default")
    gp = sub.add_parser("grafana-projects"); gp.add_argument("--profile", default="default")
    gi = sub.add_parser("grafana-import"); gi.add_argument("--profile", default="default")
    sub.add_parser("create-secret", help="store a locally generated value as a new secret (parsed separately, see create-secret --help)", add_help=False)
    rv = sub.add_parser("revoke"); rv.add_argument("lease_id"); rv.add_argument("--reason", default="manual revoke")
    sub.add_parser("doctor")
    return p


@dataclass
class CheckResult:
    status: str  # "ok" | "warn" | "fail"
    detail: str


def check_systemd_version() -> CheckResult:
    if shutil.which("systemctl") is None:
        return CheckResult("warn", "systemctl not found (dev box?)")
    try:
        first_line = subprocess.run(["systemctl", "--version"], capture_output=True, text=True, timeout=5).stdout.splitlines()[0]
        version = int(first_line.split()[1])
    except Exception as exc:
        return CheckResult("warn", f"could not determine systemd version: {exc}")
    if version >= 254:
        return CheckResult("ok", f"systemd {version}")
    return CheckResult("fail", f"systemd {version} < 254 (LoadCredentialEncrypted= requires >= 254)")


def _unit_installed() -> bool:
    if shutil.which("systemctl") is None:
        return False
    try:
        out = subprocess.run(["systemctl", "show", "-p", "FragmentPath", "--value", "keyholder.service"], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return False
    return bool(out)


def check_bws() -> CheckResult:
    if shutil.which("bws") is not None:
        return CheckResult("ok", "bws found on PATH")
    if _unit_installed():
        return CheckResult("fail", "bws not on PATH but keyholder.service is installed on this host")
    return CheckResult("warn", "bws not found on PATH (fine if the daemon runs elsewhere)")


def check_service_active() -> CheckResult:
    if shutil.which("systemctl") is None:
        return CheckResult("warn", "systemctl not found, cannot check service state")
    try:
        out = subprocess.run(["systemctl", "is-active", "keyholder.service"], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception as exc:
        return CheckResult("fail", f"could not query service state: {exc}")
    if out == "active":
        return CheckResult("ok", "keyholder.service is active")
    return CheckResult("fail", f"keyholder.service is {out or 'unknown'} (hint: journalctl -u keyholder.service)")


def check_socket(socket_path: str) -> CheckResult:
    p = Path(socket_path)
    if not p.exists():
        return CheckResult("fail", f"{socket_path} does not exist (hint: is keyholder.service running?)")
    st = p.stat()
    if not stat.S_ISSOCK(st.st_mode):
        return CheckResult("fail", f"{socket_path} exists but is not a socket")
    mode = stat.S_IMODE(st.st_mode)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    problems = []
    if mode != 0o660:
        problems.append(f"mode {oct(mode)} (expected 0660)")
    if group != CLIENT_GROUP:
        problems.append(f"group {group} (expected {CLIENT_GROUP})")
    if problems:
        return CheckResult("warn", f"{socket_path}: " + "; ".join(problems))
    return CheckResult("ok", f"{socket_path} mode 0660 group {CLIENT_GROUP}")


def check_group_membership(client_user: str | None = None) -> CheckResult:
    user = client_user or os.environ.get("USER") or pwd.getpwuid(os.getuid()).pw_name
    try:
        group = grp.getgrnam(CLIENT_GROUP)
    except KeyError:
        return CheckResult("fail", f"{CLIENT_GROUP} group does not exist (hint: sudo packaging/install.sh)")
    try:
        primary_gid = pwd.getpwnam(user).pw_gid
    except KeyError:
        primary_gid = None
    configured = user in group.gr_mem or primary_gid == group.gr_gid
    active = group.gr_gid in os.getgroups()
    if not configured:
        return CheckResult("fail", f"{user} is not in {CLIENT_GROUP} (hint: sudo packaging/install.sh --client-user {user})")
    if not active:
        return CheckResult("warn", f"{user} is in {CLIENT_GROUP} but not in the active session (hint: run 'newgrp {CLIENT_GROUP}' or re-login)")
    return CheckResult("ok", f"{user} is in {CLIENT_GROUP} (active)")


def check_policy(config_path: str = DEFAULT_POLICY) -> CheckResult:
    # /etc/keyholder is 0750 root:keyholder — a caller outside the `keyholder`
    # group (e.g. one only in keyholder-clients) gets PermissionError just
    # walking the directory, not only on open(). Treat that the same as an
    # unreadable-but-present file rather than "missing" or a crash.
    try:
        p = Path(config_path)
        exists = p.exists()
    except PermissionError:
        return CheckResult("ok", f"{config_path} exists (unreadable by this user, skipped parse)")
    if not exists:
        return CheckResult("fail", f"{config_path} does not exist (hint: sudo packaging/install.sh)")
    try:
        if not os.access(config_path, os.R_OK):
            return CheckResult("ok", f"{config_path} exists (unreadable by this user, skipped parse)")
        load_policy(config_path)
    except PermissionError:
        return CheckResult("ok", f"{config_path} exists (unreadable by this user, skipped parse)")
    except Exception as exc:
        return CheckResult("fail", f"{config_path} failed to parse: {exc}")
    return CheckResult("ok", f"{config_path} present and parses")


def check_credential(cred_path: str = DEFAULT_CRED) -> CheckResult:
    try:
        p = Path(cred_path)
        exists = p.exists()
    except PermissionError:
        return CheckResult("warn", f"{cred_path} not verifiable (permission denied on parent directory; run as root or a keyholder-group member)")
    if not exists:
        return CheckResult("fail", f"{cred_path} does not exist (hint: sudo packaging/install.sh)")
    if os.getuid() != 0:
        return CheckResult("warn", f"{cred_path} exists (run with sudo to verify decryption)")
    try:
        subprocess.run(["systemd-creds", "decrypt", "--name=bws-access-token", cred_path, "/dev/null"], check=True, capture_output=True, timeout=10)
    except Exception as exc:
        return CheckResult("fail", f"{cred_path} failed to decrypt: {exc}")
    return CheckResult("ok", f"{cred_path} decrypts successfully")


def check_grants_endpoint(socket_path: str) -> CheckResult:
    try:
        data = request(socket_path, "GET", "/v1/grants?profile=default")
    except Exception as exc:
        return CheckResult("fail", f"could not reach {socket_path}: {exc}")
    return CheckResult("ok", f"{len(data.get('grants', []))} grant(s) visible for this caller")


def build_doctor_checks(socket_path: str) -> list[tuple[str, Callable[[], CheckResult]]]:
    return [
        ("systemd version", check_systemd_version),
        ("bws on PATH", check_bws),
        ("service active", check_service_active),
        ("socket", lambda: check_socket(socket_path)),
        ("group membership", check_group_membership),
        ("policy config", check_policy),
        ("bws credential", check_credential),
        ("grants endpoint", lambda: check_grants_endpoint(socket_path)),
    ]


def run_doctor(socket_path: str) -> int:
    exit_code = 0
    for name, check_fn in build_doctor_checks(socket_path):
        try:
            result = check_fn()
        except Exception as exc:
            result = CheckResult("fail", f"check crashed: {exc}")
        print(f"{result.status:<5} {name:<20} {result.detail}")
        if result.status == "fail":
            exit_code = 1
    return exit_code


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    split = _split_create_secret(argv)
    if split is not None:
        return run_create_secret(*split)
    if "create-secret" in argv[:argv.index("--") if "--" in argv else len(argv)]:
        print(f"keyholder: {CREATE_MESSAGES['usage']}", file=sys.stderr)
        return 2
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
        elif args.cmd in ("grafana-projects", "grafana-import"):
            if extra:
                raise RuntimeError(f"{args.cmd} takes no arguments other than --profile")
            data = request(args.socket, "POST", "/v1/" + args.cmd, {"profile":args.profile})
            if args.cmd == "grafana-projects":
                for project in data.get("projects", []):
                    print(f"{project['id']}  {project['name']}")
            else:
                print(json.dumps({k: data.get(k) for k in ("id", "key", "project_id", "status_verified")}, sort_keys=True))
        elif args.cmd == "revoke":
            print(json.dumps(request(args.socket, "POST", "/v1/revoke", {"lease_id":args.lease_id, "reason":args.reason})))
        elif args.cmd == "doctor":
            return run_doctor(args.socket)
        return 0
    except Exception as exc:
        print(f"keyholder: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
