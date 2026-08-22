from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import socket
import socketserver
import subprocess
import grp
import threading
import stat
import secrets
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any

from .audit import write_audit_event
from .bitwarden import BwsResolver
from .leases import LeaseStore
from .peercred import get_peercred, uid_to_name
from .policy import PolicyError, get_grant, get_peercred_proxy_grant, grants_for_caller, load_policy, validate_ttl
from .proxy import ProxyRequestError, ProxyAuthorizationError, forward_request, validated_proxy_grant, validated_content_length, read_exact_body, validated_header_items, validate_proxy_resource_limits
from .providers.aws_sts import AwsStsProvider
from .providers.fake import FakeProvider
from .providers.github_app import GitHubAppProvider
from .providers.local_proxy import LocalProxyProvider
from .proxy import ProxyHTTPServer

LOG = logging.getLogger(__name__)

PROVIDERS = {"fake": FakeProvider(), "github_app": GitHubAppProvider(), "aws_sts": AwsStsProvider(), "local_proxy": LocalProxyProvider()}


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
    secrets = _resolver(config).resolve_refs(grant.get("bitwarden_refs", {}))
    if isinstance(provider, LocalProxyProvider):
        provider.validate(grant, secrets)
    cred = provider.issue(grant, secrets, ttl)
    lease_db, audit = _audit_paths(config)
    lease = LeaseStore(lease_db).create_lease(caller, profile, grant_name, cred.provider, ttl, reason)
    if isinstance(provider, LocalProxyProvider):
        provider.activate(
            cred,
            lease.lease_id,
            grant,
            secrets,
            caller=caller,
            profile=profile,
            grant_name=grant_name,
        )
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
    store = LeaseStore(lease_db)
    lease = store.get_lease(request["lease_id"])
    if lease.caller_user != caller:
        raise ServerError("lease does not belong to caller", 403)
    store.revoke(lease.lease_id)
    provider = PROVIDERS.get(lease.provider)
    if isinstance(provider, LocalProxyProvider):
        provider.store.revoke_lease(lease.lease_id)
    write_audit_event(audit, {"event":"revoke", "caller":caller, "grant":"", "provider":"", "ttl_seconds":0, "lease_id":request["lease_id"], "reason":request.get("reason", "")})
    return {"revoked": True, "lease_id": request["lease_id"]}


class UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True
    def __init__(self, socket_path: str, config: dict[str, Any]):
        self.config = config
        try: os.unlink(socket_path)
        except FileNotFoundError: pass
        super().__init__(socket_path, KeyholderHandler)


def proxy_listener_enabled(config: dict[str, Any]) -> bool:
    return config.get("proxy", {}).get("enabled") is True


def create_proxy_server(config: dict[str, Any]) -> ProxyHTTPServer:
    proxy_config = config.get("proxy", {})
    host = str(proxy_config.get("host", "127.0.0.1"))
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError as exc:
        raise ServerError("proxy host must be an explicit loopback IP address", 500) from exc
    if not is_loopback:
        raise ServerError("proxy host must be loopback", 500)
    provider = PROVIDERS["local_proxy"]
    if not isinstance(provider, LocalProxyProvider):
        raise ServerError("local_proxy provider is unavailable", 500)
    _lease_db, audit_path = _audit_paths(config)
    return ProxyHTTPServer(
        (host, int(proxy_config.get("port", 8787))),
        store=provider.store,
        audit_path=audit_path,
        max_body_bytes=proxy_config.get("max_body_bytes", 8 * 1024 * 1024),
        max_response_bytes=proxy_config.get("max_response_bytes", 8 * 1024 * 1024),
        max_workers=proxy_config.get("max_workers", 16),
        request_timeout_seconds=proxy_config.get("request_timeout_seconds", 15),
        upstream_timeout_seconds=proxy_config.get("upstream_timeout_seconds", 30),
    )


def validate_unix_socket_mode(value: Any) -> int:
    if isinstance(value, bool):
        raise ServerError("unix_socket_mode must be an octal mode", 500)
    if isinstance(value, int):
        mode = value
    elif isinstance(value, str) and (re.fullmatch(r"0o[0-7]{3}", value) or re.fullmatch(r"0[0-7]{3}", value)):
        mode = int(value, 8)
    else:
        raise ServerError("unix_socket_mode must be a canonical octal mode", 500)
    if mode & ~0o660 or mode & 0o600 != 0o600:
        raise ServerError("unix_socket_mode must provide owner read/write and no unsafe bits", 500)
    return mode


def _socket_parent(path: str) -> tuple[int, str]:
    parent, name = os.path.dirname(path), os.path.basename(path)
    if not path or not os.path.isabs(path) or not name or name in {".", ".."} or "/" in name or ".." in path.split(os.sep):
        raise ServerError("proxy unix socket path must be absolute and contain no traversal", 500)
    info = os.lstat(parent)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ServerError("proxy unix socket parent must be a real directory", 500)
    if info.st_uid not in {os.geteuid(), 0} or info.st_mode & 0o022:
        raise ServerError("proxy unix socket parent is unsafe", 500)
    return os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)), name


def validate_peer_proxy_socket_path(path: str) -> None:
    fd, name = _socket_parent(path)
    try:
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(info.st_mode):
            raise ServerError("proxy unix socket path is not a socket", 500)
    finally:
        os.close(fd)


class PeerProxyHTTPServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    def __init__(self, socket_path: str, config: dict[str, Any], resolver: BwsResolver):
        validate_peer_proxy_socket_path(socket_path)
        self.config, self.resolver = config, resolver
        proxy_config = config.get("proxy", {})
        limits = validate_proxy_resource_limits(
            max_body_bytes=proxy_config.get("max_body_bytes", 8 * 1024 * 1024),
            max_response_bytes=proxy_config.get("max_response_bytes", 8 * 1024 * 1024),
            request_timeout_seconds=proxy_config.get("request_timeout_seconds", 15),
            upstream_timeout_seconds=proxy_config.get("upstream_timeout_seconds", 30),
            max_workers=proxy_config.get("max_workers", 16),
        )
        parent_fd, socket_name = _socket_parent(socket_path)
        try:
            try:
                os.unlink(socket_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        finally:
            os.close(parent_fd)
        self.request_timeout_seconds = limits[2]
        self.max_workers = limits[4]
        self._worker_slots = threading.BoundedSemaphore(self.max_workers)
        socket_mode = validate_unix_socket_mode(proxy_config.get("unix_socket_mode", "0o660"))
        super().__init__(socket_path, PeerProxyHandler)
        group = proxy_config.get("unix_socket_group")
        if group:
            os.chown(socket_path, -1, grp.getgrnam(str(group)).gr_gid)
        os.chmod(socket_path, socket_mode, follow_symlinks=False)

    def get_request(self) -> tuple[Any, Any]:
        request, address = super().get_request()
        request.settimeout(self.request_timeout_seconds)
        return request, address

    def process_request(self, request: Any, client_address: Any) -> None:
        self._worker_slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class PeerProxyHandler(BaseHTTPRequestHandler):
    server: PeerProxyHTTPServer
    def log_message(self, format: str, *args: Any) -> None: LOG.info(format, *args)
    def _send(self, status: int, payload: bytes) -> None:
        self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
    def _handle(self) -> None:
        audited_rejection = False
        try:
            if self.request_version != "HTTP/1.1" or not self.path.startswith("/"):
                raise ProxyRequestError("origin-form HTTP/1.1 is required")
            headers = validated_header_items(list(self.headers.raw_items()))
            if any(name.lower() == "authorization" for name in headers):
                raise ProxyAuthorizationError("Authorization header is not accepted")
            _pid, uid, _gid = get_peercred(self.connection)  # type: ignore[arg-type]
            caller = uid_to_name(uid)
            grant = get_peercred_proxy_grant(self.server.config, caller, "default")
            secrets_map = self.server.resolver.resolve_refs(grant.get("bitwarden_refs", {}))
            validated_proxy_grant(grant, secrets_map)
            raw = list(self.headers.raw_items())
            proxy_config = self.server.config.get("proxy", {})
            length = validated_content_length(
                [v for n, v in raw if n.lower() == "content-length"],
                transfer_encoding=next((v for n, v in raw if n.lower() == "transfer-encoding"), None),
                max_body_bytes=int(proxy_config.get("max_body_bytes", 8 * 1024 * 1024)),
            )
            body = read_exact_body(self.rfile, length)
            provider = PROVIDERS["local_proxy"]
            assert isinstance(provider, LocalProxyProvider)
            from datetime import UTC, datetime, timedelta
            token = "_peercred_internal_" + secrets.token_urlsafe(32)
            lease_id = "peercred-request-" + secrets.token_urlsafe(32)
            provider.store.register(token=token, lease_id=lease_id, grant=grant, secrets=secrets_map, expires_at=datetime.now(UTC)+timedelta(seconds=float(proxy_config.get("request_timeout_seconds", 15))), caller=caller, grant_name=str(grant.get("name", "")))
            try:
                result = forward_request(provider.store, token=token, method=self.command, target=self.path, headers=headers, body=body, max_response_bytes=int(proxy_config.get("max_response_bytes", 8 * 1024 * 1024)), upstream_timeout_seconds=float(proxy_config.get("upstream_timeout_seconds", 30)), audit_path=_audit_paths(self.server.config)[1])
            finally:
                provider.store.revoke_lease(lease_id)
            self._send(result.status, result.body)
        except (PolicyError, ProxyAuthorizationError, ProxyRequestError) as exc:
            audited_rejection = bool(getattr(exc, "_keyholder_rejection_audited", False))
            if not audited_rejection:
                write_audit_event(_audit_paths(self.server.config)[1], {"event":"proxy_rejected", "caller":"unknown", "profile":"default", "grant":"", "provider":"local_proxy", "ttl_seconds":0, "lease_id":"", "reason":"peer proxy request rejected", "method":self.command, "route":"", "failure_type":type(exc).__name__})
            self._send(getattr(exc, "status", 403), json.dumps({"error": str(exc)}).encode())
        except Exception:
            LOG.exception("peer proxy request failed")
            self._send(500, b'{"error":"proxy request failed"}')
    do_POST = _handle
    do_GET = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle


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
    proxy_server = create_proxy_server(config) if proxy_listener_enabled(config) else None
    proxy_thread = None
    peer_proxy = None
    peer_thread = None
    unix_proxy_path = config.get("proxy", {}).get("unix_socket_path")
    if unix_proxy_path:
        peer_proxy = PeerProxyHTTPServer(str(unix_proxy_path), config, _resolver(config))
        peer_thread = threading.Thread(target=peer_proxy.serve_forever, name="keyholder-peer-proxy", daemon=True)
        peer_thread.start()
    if proxy_server is not None:
        proxy_thread = threading.Thread(target=proxy_server.serve_forever, name="keyholder-proxy", daemon=True)
        proxy_thread.start()
    try:
        with UnixHTTPServer(socket_path, config) as server:
            if socket_group:
                gid = grp.getgrnam(socket_group).gr_gid
                os.chown(socket_path, -1, gid)
            os.chmod(socket_path, 0o660)
            LOG.info("keyholderd listening on %s", socket_path)
            if proxy_server is not None:
                LOG.info(
                    "keyholder proxy listening on http://%s:%s",
                    proxy_server.server_address[0],
                    proxy_server.server_address[1],
                )
            server.serve_forever()
    finally:
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass
        if peer_proxy is not None:
            peer_proxy.shutdown()
            peer_proxy.server_close()
            if peer_thread is not None:
                peer_thread.join(timeout=5)
            try:
                os.unlink(str(unix_proxy_path))
            except FileNotFoundError:
                pass
        if proxy_server is not None:
            proxy_server.shutdown()
            proxy_server.server_close()
        if proxy_thread is not None:
            proxy_thread.join(timeout=5)


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
