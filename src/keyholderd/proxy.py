from __future__ import annotations

import hashlib
import secrets
import threading
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

    def revoke_lease(self, lease_id: str) -> None:
        with self._lock:
            for item in self._items.values():
                if item["lease_id"] == lease_id:
                    item["revoked"] = True

    def lookup(self, token: str) -> dict[str, Any]:
        with self._lock:
            item = self._items.get(hashlib.sha256(token.encode()).hexdigest())
        if item is None:
            raise CapabilityError("invalid capability")
        return item

    def validate(self, token: str, caller: str, grant: str, method: str, path: str, template: str = TEMPLATE) -> dict[str, Any]:
        if not token:
            raise CapabilityError("capability required")
        item = self.lookup(token)
        if item["revoked"] or item["expires"] <= datetime.now(UTC):
            raise CapabilityError("invalid capability")
        if (item["caller"], item["grant"], item["method"], item["template"]) != (caller, grant, method, template):
            raise CapabilityError("capability metadata mismatch")
        if method != "GET" or path != ROUTE:
            raise CapabilityError("route or method not allowed")
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
        item = self.store.validate(token, caller, grant, method, path)
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
