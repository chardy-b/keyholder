from __future__ import annotations

import hashlib
import secrets
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse

import requests

TEMPLATE = "google-calendar-events-read"
GOOGLE_ORIGIN = "https://www.googleapis.com"
ROUTE = "/calendar/v3/calendars/primary/events"
ALLOWED_QUERY = {"timeMin", "timeMax", "maxResults", "pageToken", "singleEvents", "orderBy"}
MAX_REQUEST = 4096
MAX_RESPONSE = 2 * 1024 * 1024


class CapabilityError(ValueError):
    pass


class CapabilityStore:
    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def issue(self, caller: str, grant: str, ttl: int, lease_id: str = "", template: str = TEMPLATE, method: str = "GET", profile: str = "default") -> tuple[str, datetime]:
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
            raise CapabilityError("capability TTL must be positive integer")
        token = "khcap_" + secrets.token_urlsafe(32)
        expires = datetime.now(UTC) + timedelta(seconds=ttl)
        item = {"lease_id": lease_id, "caller": caller, "grant": grant, "profile": profile, "template": template, "method": method, "expires": expires, "revoked": False}
        with self._lock:
            self._items[hashlib.sha256(token.encode()).hexdigest()] = item
        return token, expires

    def revoke(self, token: str) -> None:
        with self._lock:
            item = self._items.get(hashlib.sha256(token.encode()).hexdigest())
            if item:
                item["revoked"] = True

    def revoke_lease_atomically(self, lease_id: str, persist_callback: Callable[[], None]) -> None:
        """Persist revocation and invalidate capabilities under one lock."""
        with self._lock:
            persist_callback()
            for item in self._items.values():
                if item["lease_id"] == lease_id:
                    item["revoked"] = True

    def revoke_lease(self, lease_id: str) -> None:
        """Invalidate capabilities without a backing lease store (test/local use)."""
        with self._lock:
            for item in self._items.values():
                if item["lease_id"] == lease_id:
                    item["revoked"] = True

    def lookup(self, token: str) -> dict[str, Any]:
        with self._lock:
            item = self._items.get(hashlib.sha256(token.encode()).hexdigest())
            if item is None:
                raise CapabilityError("invalid capability")
            return item.copy()

    @contextmanager
    def authorize(self, token: str, caller: str, grant: str, method: str, path: str, template: str = TEMPLATE):
        """Hold the capability lock through the complete protected forward."""
        with self._lock:
            if not token:
                raise CapabilityError("capability required")
            item = self._items.get(hashlib.sha256(token.encode()).hexdigest())
            if item is None:
                raise CapabilityError("invalid capability")
            if item["revoked"] or item["expires"] <= datetime.now(UTC):
                raise CapabilityError("invalid capability")
            if (item["caller"], item["grant"], item["method"], item["template"]) != (caller, grant, method, template):
                raise CapabilityError("capability metadata mismatch")
            if method != "GET" or path != ROUTE:
                raise CapabilityError("route or method not allowed")
            yield item.copy()

    def validate(self, token: str, caller: str, grant: str, method: str, path: str, template: str = TEMPLATE) -> dict[str, Any]:
        with self.authorize(token, caller, grant, method, path, template) as item:
            return item


class CalendarProxy:
    def __init__(self, store: CapabilityStore, token_resolver: Callable[[dict[str, Any]], str], upstream_origin: str = GOOGLE_ORIGIN, session_factory: Callable[[], Any] | None = None, *, verify: bool | str = True, test_only: bool = False) -> None:
        if upstream_origin != GOOGLE_ORIGIN and not test_only:
            raise ValueError("production origin is fixed")
        self.store = store
        self.token_resolver = token_resolver
        self.session_factory = session_factory or requests.Session
        self.upstream_origin = upstream_origin.rstrip("/")
        self.verify = verify

    def forward(self, token: str, caller: str, grant: str, method: str, path: str, query: dict[str, list[str]], headers: dict[str, str], body: bytes = b"") -> tuple[int, dict[str, str], bytes]:
        with self.store.authorize(token, caller, grant, method, path) as item:
            if len(body) > MAX_REQUEST or any(key not in ALLOWED_QUERY or len(values) != 1 or not values[0] for key, values in query.items()):
                raise CapabilityError("request not allowed")
            params = [(key, values[0]) for key, values in query.items()]
            session = self.session_factory()
            session.trust_env = False
            try:
                access_token = self.token_resolver(item)
                response = session.get(self.upstream_origin + path + (("?" + urlencode(params)) if params else ""), headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}, timeout=(3, 10), stream=True, verify=self.verify)
                data = response.raw.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    raise CapabilityError("response too large")
                allowed = {key: response.headers[key] for key in ("Content-Type", "ETag", "Cache-Control") if key in response.headers}
                return response.status_code, allowed, data
            finally:
                session.close()


class ProxyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], proxy: CalendarProxy) -> None:
        if address[0] not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("proxy must bind loopback")
        self.proxy = proxy
        super().__init__(address, ProxyHandler)


class ProxyLifecycle:
    """Own a proxy listener and the capability store used by daemon handlers."""

    def __init__(self, config: dict[str, Any], *, bind: str = "127.0.0.1", port: int = 0,
                 upstream_origin: str = GOOGLE_ORIGIN, upstream_verify: bool | str = True,
                 token_resolver: Callable[[dict[str, Any]], str] | None = None) -> None:
        if bind not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("proxy must bind loopback")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("proxy port must be an integer from 0 through 65535")
        self.config = config
        self.host, self.requested_port = bind, port
        self.port = port
        self.store = CapabilityStore()
        self._test_injection = upstream_origin != GOOGLE_ORIGIN or upstream_verify is not True or token_resolver is not None
        if not self._test_injection and upstream_origin != GOOGLE_ORIGIN:
            raise ValueError("production origin is fixed")
        self._token_resolver = token_resolver or self._production_resolver
        self.proxy = CalendarProxy(self.store, self._token_resolver, upstream_origin,
                                    verify=upstream_verify, test_only=self._test_injection)
        self.server: ProxyHTTPServer | None = None
        self._thread: threading.Thread | None = None
        from . import server as daemon_server
        daemon_server.register_proxy_store(config, self.store)

    def _production_resolver(self, item: dict[str, Any]) -> str:
        from . import server as daemon_server
        grant = daemon_server.get_grant(self.config, item["caller"], item.get("profile", "default"), item["grant"])
        if grant.get("provider") != "google_calendar_proxy" or grant.get("template") != TEMPLATE:
            raise CapabilityError("invalid proxy grant")
        secrets_map = daemon_server._resolver(self.config).resolve_refs(grant["bitwarden_refs"])
        remaining = max(1, int((item["expires"] - datetime.now(UTC)).total_seconds()))
        def oauth_session():
            session = requests.Session()
            session.verify = self.proxy.verify
            return session
        return daemon_server.GoogleOAuthProvider(session_factory=oauth_session).issue(grant, secrets_map, remaining).display_token

    def start(self) -> None:
        if self.server is not None:
            return
        self.server = ProxyHTTPServer((self.host, self.requested_port), self.proxy)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self.server is None:
            return
        self.server.shutdown()
        self.server.server_close()
        if self._thread:
            self._thread.join(timeout=5)
        self.server = None

    def issue_for_test(self, caller: str, grant: str, ttl: int, *, with_lease: bool = False):
        from . import server as daemon_server
        lease = daemon_server.LeaseStore(daemon_server._audit_paths(self.config)[0]).create_lease(caller, "default", grant, "google_calendar_proxy", ttl, "test")
        token, _ = self.store.issue(caller, grant, ttl, lease.lease_id)
        audit_path = daemon_server._audit_paths(self.config)[1]
        from .audit import write_audit_event
        write_audit_event(audit_path, {"event": "issue", "caller": caller, "profile": "default", "grant": grant, "provider": "google_calendar_proxy", "template": TEMPLATE, "ttl_seconds": ttl, "lease_id": lease.lease_id, "reason": "test"})
        return (token, lease.lease_id) if with_lease else token


class ProxyHandler(BaseHTTPRequestHandler):
    server: ProxyHTTPServer

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            auth = self.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else ""
            item = self.server.proxy.store.lookup(token)
            status, headers, data = self.server.proxy.forward(token, item["caller"], item["grant"], "GET", parsed.path, parse_qs(parsed.query, keep_blank_values=True), {})
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except CapabilityError as exc:
            self.send_error(403, str(exc))
        except Exception:
            self.send_error(502, "upstream unavailable")

    def do_POST(self) -> None:
        self.send_error(405, "method not allowed")

    do_PUT = do_DELETE = do_PATCH = do_POST

    def log_message(self, *_: Any) -> None:
        pass
