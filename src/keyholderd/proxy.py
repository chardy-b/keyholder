from __future__ import annotations

import hashlib
import json
import secrets
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import requests

TEMPLATE = "google-calendar-events-read"
GOOGLE_ORIGIN = "https://www.googleapis.com"
ALLOWED_QUERY = {"timeMin", "timeMax", "maxResults", "pageToken", "singleEvents", "orderBy"}
ALLOWED_HEADERS = {"accept", "content-type"}
MAX_REQUEST = 4096
MAX_RESPONSE = 2 * 1024 * 1024

class CapabilityError(ValueError): pass

class CapabilityStore:
    def __init__(self): self._items = {}; self._lock = threading.Lock()
    def issue(self, caller: str, grant: str, ttl: int) -> tuple[str, datetime]:
        token = "khcap_" + secrets.token_urlsafe(32); exp = datetime.now(UTC) + timedelta(seconds=ttl)
        with self._lock: self._items[hashlib.sha256(token.encode()).hexdigest()] = {"caller":caller,"grant":grant,"template":TEMPLATE,"method":"GET","expires":exp,"revoked":False}
        return token, exp
    def revoke(self, token: str) -> None:
        with self._lock:
            item=self._items.get(hashlib.sha256(token.encode()).hexdigest())
            if item: item["revoked"] = True
    def validate(self, token: str, caller: str, grant: str) -> dict:
        if not token: raise CapabilityError("capability required")
        with self._lock: item=self._items.get(hashlib.sha256(token.encode()).hexdigest())
        if not item or item["revoked"] or item["expires"] <= datetime.now(UTC) or item["caller"] != caller or item["grant"] != grant: raise CapabilityError("invalid capability")
        return item

class CalendarProxy: 
    def __init__(self, store: CapabilityStore, token_resolver, upstream_origin: str = GOOGLE_ORIGIN, session_factory=None, *, test_only=False):
        if upstream_origin != GOOGLE_ORIGIN and not test_only: raise ValueError("production origin is fixed")
        self.store=store; self.token_resolver=token_resolver; self.session_factory=session_factory or requests.Session; self.upstream_origin=upstream_origin
    def forward(self, token: str, caller: str, grant: str, method: str, path: str, query: dict[str,list[str]], headers: dict[str,str], body: bytes=b"") -> tuple[int,dict[str,str],bytes]:
        self.store.validate(token, caller, grant)
        if method != "GET" or path != "/calendar/v3/calendars/primary/events": raise CapabilityError("route or method not allowed")
        if len(body)>MAX_REQUEST or any(k not in ALLOWED_QUERY for k in query): raise CapabilityError("request not allowed")
        params=[]
        for key, vals in query.items():
            if len(vals)>1: raise CapabilityError("duplicate query parameter")
            params.append((key, vals[0]))
        session=self.session_factory(); session.trust_env=False
        try:
            access_token=self.token_resolver()
            resp=session.get(self.upstream_origin+path+(("?"+urlencode(params)) if params else ""), headers={"Authorization":"Bearer "+access_token,"Accept":headers.get("Accept","application/json")}, data=None, timeout=(3,10), stream=True)
            data=resp.raw.read(MAX_RESPONSE+1)
            if len(data)>MAX_RESPONSE: raise CapabilityError("response too large")
            return resp.status_code, {"Content-Type":resp.headers.get("Content-Type","application/json")}, data
        finally: session.close()

class ProxyHTTPServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self, address, proxy, caller, grant):
        self.proxy=proxy; self.caller=caller; self.grant=grant
        if address[0] not in {"127.0.0.1","::1","localhost"}: raise ValueError("proxy must bind loopback")
        super().__init__(address, ProxyHandler)

class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed=urlparse(self.path); token=self.headers.get("Authorization","").removeprefix("Bearer ")
            status, headers, data=self.server.proxy.forward(token,self.server.caller,self.server.grant,"GET",parsed.path,parse_qs(parsed.query,keep_blank_values=True),dict(self.headers))
            self.send_response(status); [self.send_header(k,v) for k,v in headers.items()]; self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
        except CapabilityError as exc: self.send_error(403,str(exc))
        except Exception: self.send_error(502,"upstream unavailable")
    do_POST=do_PUT=do_DELETE=do_GET
    def log_message(self, *_): pass
