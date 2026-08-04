from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import socketserver
import subprocess
import grp
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any

from .audit import write_audit_event
from .bitwarden import BwsResolver
from .leases import LeaseStore
from .peercred import get_peercred, uid_to_name
from .policy import PolicyError, get_grant, grants_for_caller, load_policy, validate_ttl
from .providers.aws_sts import AwsStsProvider
from .providers.fake import FakeProvider
from .providers.github_app import GitHubAppProvider
from .providers.google_oauth import GoogleOAuthProvider
from .providers.local_proxy import LocalProxyProvider

LOG = logging.getLogger(__name__)

PROVIDERS = {"fake": FakeProvider(), "github_app": GitHubAppProvider(), "aws_sts": AwsStsProvider(), "google_oauth": GoogleOAuthProvider(), "local_proxy": LocalProxyProvider()}


class ServerError(RuntimeError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=getattr(logging, level.upper()), format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')


def _audit_paths(config: dict[str, Any]) -> tuple[str, str]:
    paths = config.get("paths", {})
    return paths.get("leases_db", "/var/lib/keyholder/leases.db"), paths.get("audit_log", "/var/log/keyholder/audit.jsonl")


def _resolver(config: dict[str, Any]) -> BwsResolver:
    bw = config.get("bitwarden", {})
    return BwsResolver(project_id=bw.get("project_id"), cache_seconds=int(bw.get("cache_seconds", 0)))


def handle_grants(config: dict[str, Any], caller: str, profile: str = "default") -> dict[str, Any]:
    grants = grants_for_caller(config, caller, profile)
    lease_db, audit = _audit_paths(config)
    write_audit_event(audit, {"event":"grants", "caller":caller, "profile":profile, "grant":"*", "provider":"policy", "ttl_seconds":0, "lease_id":"", "reason":"list grants"})
    return {"grants":[{"name":g["name"], "provider":g["provider"], "max_ttl_seconds":g.get("max_ttl_seconds", g.get("ttl_seconds", 0)), "default_ttl_seconds":g.get("ttl_seconds", 0)} for g in grants]}


def _issue_credential(config: dict[str, Any], caller: str, profile: str, grant_name: str, ttl_seconds: int | None, reason: str) -> tuple[Any, Any, int]:
    if not reason:
        raise ServerError("reason is required", 400)
    grant = get_grant(config, caller, profile, grant_name)
    ttl = validate_ttl(grant, ttl_seconds)
    provider = PROVIDERS.get(grant["provider"])
    if provider is None:
        raise ServerError(f"unknown provider {grant['provider']!r}", 500)
    if isinstance(provider, GoogleOAuthProvider):
        try:
            provider.validate(grant)
            provider.validate_secret_refs(grant.get("bitwarden_refs"))
        except ValueError as exc:
            raise ServerError(str(exc), 400) from exc
    secrets = _resolver(config).resolve_refs(grant.get("bitwarden_refs", {}))
    cred = provider.issue(grant, secrets, ttl)
    lease_db, audit = _audit_paths(config)
    lease = LeaseStore(lease_db).create_lease(caller, profile, grant_name, cred.provider, ttl, reason)
    write_audit_event(audit, {"event":"issue", "caller":caller, "profile":profile, "grant":grant_name, "provider":cred.provider, "ttl_seconds":ttl, "lease_id":lease.lease_id, "reason":reason, "scope_summary":cred.scope_summary})
    return cred, lease, ttl


def handle_issue(config: dict[str, Any], caller: str, request: dict[str, Any]) -> dict[str, Any]:
    cred, lease, _ttl = _issue_credential(config, caller, request.get("profile", "default"), request["grant"], request.get("ttl_seconds"), request.get("reason", ""))
    return {"token_type":cred.token_type, "access_token":cred.display_token, "expires_at":cred.expires_at.isoformat(), "lease_id":lease.lease_id, "provider":cred.provider, "scope_summary":cred.scope_summary}


def handle_run(config: dict[str, Any], caller: str, request: dict[str, Any]) -> dict[str, Any]:
    command = request.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        raise ServerError("command must be a non-empty string array", 400)
    cred, lease, ttl = _issue_credential(config, caller, request.get("profile", "default"), request["grant"], request.get("ttl_seconds"), request.get("reason", ""))
    env_var = request.get("env_var")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"), "LANG": "C.UTF-8"}
    env.update(cred.env)
    if env_var and len(cred.env) == 1:
        env[env_var] = next(iter(cred.env.values()))
    completed = subprocess.run(command, capture_output=True, text=True, env=env, timeout=int(request.get("timeout_seconds", min(ttl, 300))))
    lease_db, audit = _audit_paths(config)
    write_audit_event(audit, {"event":"run", "caller":caller, "profile":request.get("profile", "default"), "grant":request["grant"], "provider":cred.provider, "ttl_seconds":ttl, "lease_id":lease.lease_id, "reason":request.get("reason", ""), "exit_code":completed.returncode})
    return {"exit_code":completed.returncode, "stdout":completed.stdout, "stderr":completed.stderr, "lease_id":lease.lease_id, "expires_at":cred.expires_at.isoformat()}


def handle_revoke(config: dict[str, Any], caller: str, request: dict[str, Any]) -> dict[str, Any]:
    lease_db, audit = _audit_paths(config)
    LeaseStore(lease_db).revoke(request["lease_id"])
    write_audit_event(audit, {"event":"revoke", "caller":caller, "grant":"", "provider":"", "ttl_seconds":0, "lease_id":request["lease_id"], "reason":request.get("reason", "")})
    return {"revoked": True, "lease_id": request["lease_id"]}


class UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True
    def __init__(self, socket_path: str, config: dict[str, Any]):
        self.config = config
        try: os.unlink(socket_path)
        except FileNotFoundError: pass
        super().__init__(socket_path, KeyholderHandler)


class KeyholderHandler(BaseHTTPRequestHandler):
    server: UnixHTTPServer
    def log_message(self, format: str, *args: Any) -> None:
        LOG.info(format, *args)

    def _caller(self) -> str:
        _pid, uid, _gid = get_peercred(self.connection)  # type: ignore[arg-type]
        return uid_to_name(uid)

    def _json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_GET(self) -> None:
        try:
            if self.path.startswith("/v1/grants"):
                self._send(200, handle_grants(self.server.config, self._caller()))
            else: self._send(404, {"error":"not found"})
        except Exception as exc:
            self._send(getattr(exc, "status", 500), {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            body = self._json_body(); caller = self._caller()
            if self.path == "/v1/issue": payload = handle_issue(self.server.config, caller, body)
            elif self.path == "/v1/run": payload = handle_run(self.server.config, caller, body)
            elif self.path == "/v1/revoke": payload = handle_revoke(self.server.config, caller, body)
            else: self._send(404, {"error":"not found"}); return
            self._send(200, payload)
        except (PolicyError, ServerError, KeyError) as exc:
            self._send(getattr(exc, "status", 403), {"error": str(exc)})
        except Exception as exc:
            LOG.exception("request failed")
            self._send(500, {"error": str(exc)})


def serve(config_path: str, socket_path: str, socket_group: str | None = None) -> None:
    config = load_policy(config_path)
    with UnixHTTPServer(socket_path, config) as server:
        if socket_group:
            gid = grp.getgrnam(socket_group).gr_gid
            os.chown(socket_path, -1, gid)
        os.chmod(socket_path, 0o660)
        LOG.info("keyholderd listening on %s", socket_path)
        server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/keyholder/policy.yaml")
    parser.add_argument("--socket", default="/run/keyholder/keyholder.sock")
    parser.add_argument("--socket-group", default=None)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)
    configure_logging(args.log_level)
    serve(args.config, args.socket, args.socket_group)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
