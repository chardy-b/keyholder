from __future__ import annotations

import base64
import hashlib
import http.client
import json
import logging
import math
import re
import socket
import subprocess
import sys
import threading
from numbers import Real
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Iterator, Mapping, cast
from urllib.parse import urlsplit

import requests

from .audit import write_audit_event


LOG = logging.getLogger(__name__)


class ProxyAuthorizationError(PermissionError):
    """Raised when a proxy capability cannot authorize a request."""


class ProxyConfigurationError(ValueError):
    """Raised when a local proxy grant is unsafe or incomplete."""


class ProxyRequestError(ValueError):
    """Raised for malformed or unsupported downstream HTTP framing."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class ProxyUpstreamError(RuntimeError):
    """Raised when an upstream response cannot be forwarded safely."""


@dataclass(frozen=True)
class ProxyCapability:
    lease_id: str
    caller: str
    profile: str
    grant_name: str
    upstream_base_url: str
    upstream_api_key: str
    allowed_methods: frozenset[str]
    allowed_routes: frozenset[str]
    authentication: str
    allowed_models: frozenset[str] | None
    expires_at: datetime


@dataclass
class _CapabilityState:
    capability: ProxyCapability
    in_flight: int = 0
    revoked: bool = False


@dataclass(frozen=True)
class ForwardResponse:
    status: int
    headers: dict[str, str]
    body: bytes


SUPPORTED_METHODS = frozenset({"DELETE", "GET", "PATCH", "POST", "PUT"})

MAX_PROXY_BODY_BYTES = 64 * 1024 * 1024
MAX_PROXY_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_PROXY_TIMEOUT_SECONDS = 300.0
MAX_PROXY_WORKERS = 256


def validate_proxy_resource_limits(
    *, max_body_bytes: Any, max_response_bytes: Any,
    request_timeout_seconds: Any, upstream_timeout_seconds: Any,
    max_workers: Any,
) -> tuple[int, int, float, float, int]:
    """Validate limits before any server constructor can bind a socket."""
    integer_limits = {
        "max_body_bytes": (max_body_bytes, MAX_PROXY_BODY_BYTES),
        "max_response_bytes": (max_response_bytes, MAX_PROXY_RESPONSE_BYTES),
        "max_workers": (max_workers, MAX_PROXY_WORKERS),
    }
    for name, (value, upper) in integer_limits.items():
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= upper:
            raise ProxyConfigurationError(f"{name} must be a positive integer no greater than {upper}")
    float_limits = {
        "request_timeout_seconds": request_timeout_seconds,
        "upstream_timeout_seconds": upstream_timeout_seconds,
    }
    for name, value in float_limits.items():
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ProxyConfigurationError(f"{name} must be a finite number")
        numeric = float(value)
        if not math.isfinite(numeric) or not 0 < numeric <= MAX_PROXY_TIMEOUT_SECONDS:
            raise ProxyConfigurationError(f"{name} must be positive and no greater than {MAX_PROXY_TIMEOUT_SECONDS:g}")
    return (max_body_bytes, max_response_bytes, float(request_timeout_seconds),
            float(upstream_timeout_seconds), max_workers)


HOP_BY_HOP_HEADERS = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def validate_peercred_chat_body(body: bytes, allowed_models: frozenset[str] | list[str]) -> None:
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProxyRequestError("request body must be valid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("model"), str):
        raise ProxyRequestError("request body must contain a string model")
    if payload["model"] not in allowed_models:
        raise ProxyRequestError("model is not allowed")


def validated_proxy_grant(
    grant: dict[str, Any], secrets: dict[str, str]
) -> tuple[str, frozenset[str], frozenset[str], str, frozenset[str] | None]:
    try:
        upstream_base_url = str(grant["upstream_base_url"])
        upstream_api_key = secrets["upstream_api_key"]
    except KeyError as exc:
        raise ProxyConfigurationError(f"missing local_proxy setting: {exc.args[0]}") from exc
    if not upstream_api_key:
        raise ProxyConfigurationError("upstream_api_key must not be empty")

    insecure_opt_in = grant.get("allow_insecure_http", False)
    if not isinstance(insecure_opt_in, bool):
        raise ProxyConfigurationError("allow_insecure_http must be a boolean")
    parsed_upstream = urlsplit(upstream_base_url)
    if parsed_upstream.scheme not in {"http", "https"}:
        raise ProxyConfigurationError("upstream_base_url must use HTTP or HTTPS")
    if parsed_upstream.scheme == "http" and insecure_opt_in is not True:
        raise ProxyConfigurationError("upstream_base_url must use HTTPS")
    if not parsed_upstream.hostname:
        raise ProxyConfigurationError("upstream_base_url must include a hostname")
    try:
        parsed_upstream.port
    except ValueError as exc:
        raise ProxyConfigurationError("upstream_base_url contains an invalid port") from exc
    if parsed_upstream.username is not None or parsed_upstream.password is not None:
        raise ProxyConfigurationError("upstream_base_url must not contain userinfo")
    if parsed_upstream.query or parsed_upstream.fragment:
        raise ProxyConfigurationError("upstream_base_url must not contain a query or fragment")

    raw_routes = grant.get("allowed_routes", [])
    if not isinstance(raw_routes, list) or not raw_routes or not all(isinstance(route, str) for route in raw_routes):
        raise ProxyConfigurationError("allowed_routes must be a non-empty string array")
    routes = frozenset(raw_routes)
    for route in routes:
        parsed_route = urlsplit(route)
        if (
            not route.startswith("/")
            or parsed_route.scheme
            or parsed_route.netloc
            or parsed_route.query
            or parsed_route.fragment
            or parsed_route.path != route
        ):
            raise ProxyConfigurationError("allowed_routes must contain origin-form paths without query or fragment")

    raw_methods = grant.get("allowed_methods", ["POST"])
    if not isinstance(raw_methods, list) or not raw_methods or not all(isinstance(method, str) for method in raw_methods):
        raise ProxyConfigurationError("allowed_methods must be a non-empty string array")
    methods = frozenset(method.upper() for method in raw_methods)
    if not methods.issubset(SUPPORTED_METHODS):
        raise ProxyConfigurationError("allowed_methods contains an unsupported method")
    authentication = grant.get("authentication", "capability")
    if authentication not in {"capability", "peercred"}:
        raise ProxyConfigurationError("authentication must be capability or peercred")
    allowed_models: frozenset[str] | None = None
    if authentication == "peercred":
        raw_models = grant.get("allowed_models")
        if (
            not isinstance(raw_models, list)
            or not raw_models
            or not all(isinstance(model, str) and model for model in raw_models)
        ):
            raise ProxyConfigurationError("allowed_models must be a non-empty string array")
        allowed_models = frozenset(raw_models)
    return upstream_base_url, methods, routes, authentication, allowed_models


def validated_content_length(
    values: list[str], *, transfer_encoding: str | None, max_body_bytes: int
) -> int:
    if transfer_encoding is not None:
        raise ProxyRequestError("Transfer-Encoding is not supported")
    if not values:
        return 0
    if len(values) != 1:
        raise ProxyRequestError("request must contain exactly one Content-Length")
    value = values[0]
    if not value.isdecimal():
        if value.startswith("-") and value[1:].isdecimal():
            raise ProxyRequestError("Content-Length must be non-negative")
        raise ProxyRequestError("Content-Length must be a decimal integer")
    length = int(value)
    if length > max_body_bytes:
        raise ProxyRequestError("request body is too large", 413)
    return length


def read_exact_body(stream: Any, content_length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = content_length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise ProxyRequestError("request body is shorter than Content-Length")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def validated_header_items(items: list[tuple[str, str]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    seen: dict[str, str] = {}
    for name, value in items:
        normalized = name.lower()
        if normalized in seen:
            raise ProxyRequestError(f"duplicate {seen[normalized]} header")
        seen[normalized] = name
        headers[name] = value
    return headers


def address_family_for_host(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


class CapabilityStore:
    def __init__(self) -> None:
        self._capabilities: dict[str, _CapabilityState] = {}
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._in_flight_by_lease: dict[str, int] = {}

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def register(
        self,
        *,
        token: str,
        lease_id: str,
        grant: dict[str, Any],
        secrets: dict[str, str],
        expires_at: datetime,
        caller: str = "",
        profile: str = "",
        grant_name: str = "",
    ) -> None:
        upstream_base_url, methods, routes, authentication, allowed_models = validated_proxy_grant(grant, secrets)
        capability = ProxyCapability(
            lease_id=lease_id,
            caller=caller,
            profile=profile,
            grant_name=grant_name or str(grant.get("name", "")),
            upstream_base_url=upstream_base_url,
            upstream_api_key=secrets["upstream_api_key"],
            allowed_methods=methods,
            allowed_routes=routes,
            authentication=authentication,
            allowed_models=allowed_models,
            expires_at=expires_at,
        )
        with self._lock:
            self._capabilities[self._token_hash(token)] = _CapabilityState(capability)

    def revoke_lease(self, lease_id: str) -> None:
        with self._condition:
            matching = [
                (token_hash, state)
                for token_hash, state in self._capabilities.items()
                if state.capability.lease_id == lease_id
            ]
            for token_hash, state in matching:
                state.revoked = True
                del self._capabilities[token_hash]
            while self._in_flight_by_lease.get(lease_id, 0):
                self._condition.wait()

    def purge_expired(self) -> int:
        now = datetime.now(UTC)
        with self._lock:
            expired_hashes = [
                token_hash
                for token_hash, state in self._capabilities.items()
                if state.capability.expires_at <= now
            ]
            for token_hash in expired_hashes:
                del self._capabilities[token_hash]
        return len(expired_hashes)

    def _authorize_state_unlocked(self, token: str, method: str, path: str) -> _CapabilityState:
        token_hash = self._token_hash(token)
        state = self._capabilities.get(token_hash)
        if state is None or state.revoked:
            raise ProxyAuthorizationError("invalid capability")
        capability = state.capability
        if capability.expires_at <= datetime.now(UTC):
            self._capabilities.pop(token_hash, None)
            raise ProxyAuthorizationError("capability expired")
        if method.upper() not in capability.allowed_methods:
            raise ProxyAuthorizationError("method is not allowed")
        if path not in capability.allowed_routes:
            raise ProxyAuthorizationError("route is not allowed")
        return state

    def authorize(self, token: str, method: str, path: str) -> ProxyCapability:
        with self._lock:
            return self._authorize_state_unlocked(token, method, path).capability

    @contextmanager
    def dispatch(
        self, token: str, method: str, path: str
    ) -> Iterator[ProxyCapability]:
        # The gate is brief and per-capability in-flight state lets unrelated
        # capabilities continue. Revocation removes access first, then waits for
        # an already-dispatched request using that lease to finish.
        with self._condition:
            state = self._authorize_state_unlocked(token, method, path)
            state.in_flight += 1
            lease_id = state.capability.lease_id
            self._in_flight_by_lease[lease_id] = self._in_flight_by_lease.get(lease_id, 0) + 1
        try:
            yield state.capability
        finally:
            with self._condition:
                state.in_flight -= 1
                remaining = self._in_flight_by_lease[lease_id] - 1
                if remaining:
                    self._in_flight_by_lease[lease_id] = remaining
                else:
                    del self._in_flight_by_lease[lease_id]
                self._condition.notify_all()


def _forward_headers(headers: Mapping[str, str]) -> dict[str, str]:
    connection_value = next(
        (value for name, value in headers.items() if name.lower() == "connection"),
        "",
    )
    connection_tokens = {
        token.strip().lower()
        for token in connection_value.split(",")
        if token.strip()
    }
    excluded = HOP_BY_HOP_HEADERS | connection_tokens | {"authorization"}
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in excluded
    }


_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


def _validated_upstream_headers(items: list[tuple[str, str]]) -> dict[str, str]:
    headers: dict[str, tuple[str, str]] = {}
    connection_values: list[str] = []
    for name, value in items:
        normalized = name.lower()
        if _HEADER_NAME.fullmatch(name) is None:
            raise ProxyUpstreamError("upstream returned an invalid response header name")
        if any((ord(character) < 32 and character != "\t") or ord(character) == 127 for character in value):
            raise ProxyUpstreamError("upstream returned an unsafe response header value")
        if normalized == "connection":
            connection_values.append(value)
        headers[normalized] = (name, value)
    connection_tokens = {
        token.strip().lower()
        for value in connection_values
        for token in value.split(",")
        if token.strip()
    }
    excluded = HOP_BY_HOP_HEADERS | connection_tokens
    return {
        original_name: value
        for normalized, (original_name, value) in headers.items()
        if normalized not in excluded
    }


def _direct_upstream_request(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    max_response_bytes: int,
    timeout_seconds: float,
) -> ForwardResponse:
    parsed = urlsplit(url)
    if parsed.hostname is None:
        raise ProxyUpstreamError("upstream URL is missing a hostname")
    connection_class = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_class(parsed.hostname, parsed.port, timeout=timeout_seconds)
    timed_out = threading.Event()

    def expire() -> None:
        timed_out.set()
        connection.close()

    deadline = threading.Timer(timeout_seconds, expire)
    deadline.daemon = True
    deadline.start()
    response: Any | None = None
    try:
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        connection.request(method, target, body=body, headers=dict(headers))
        response = connection.getresponse()
        declared_length = response.getheader("Content-Length")
        if declared_length is not None:
            try:
                if int(declared_length) > max_response_bytes:
                    raise ProxyUpstreamError("upstream response is too large")
            except ValueError as exc:
                raise ProxyUpstreamError("upstream returned an invalid Content-Length") from exc
        response_body = response.read(max_response_bytes + 1)
        if timed_out.is_set():
            raise ProxyUpstreamError("upstream total deadline exceeded")
        if len(response_body) > max_response_bytes:
            raise ProxyUpstreamError("upstream response is too large")
        status = int(response.status)
        if not 200 <= status <= 599:
            raise ProxyUpstreamError("upstream returned an unsupported response status")
        return ForwardResponse(
            status=status,
            headers=_validated_upstream_headers(response.getheaders()),
            body=response_body,
        )
    except Exception as exc:
        if timed_out.is_set() and not isinstance(exc, ProxyUpstreamError):
            raise ProxyUpstreamError("upstream total deadline exceeded") from exc
        raise
    finally:
        deadline.cancel()
        if response is not None:
            response.close()
        connection.close()


def _default_upstream_request(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    max_response_bytes: int,
    timeout_seconds: float,
) -> ForwardResponse:
    # Execute the credential-bearing network operation in a short-lived child.
    # Socket and HTTP timeouts are inactivity timers; a process boundary lets
    # the parent terminate trickling I/O at an absolute deadline.
    payload = json.dumps(
        {
            "method": method,
            "url": url,
            "headers": dict(headers),
            "body": base64.b64encode(body).decode("ascii"),
            "max_response_bytes": max_response_bytes,
            "timeout_seconds": timeout_seconds,
        },
        separators=(",", ":"),
    ).encode()
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "keyholderd.proxy_worker"],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProxyUpstreamError("upstream total deadline exceeded") from exc
    if completed.returncode != 0:
        raise ProxyUpstreamError("upstream request failed")
    try:
        output = json.loads(completed.stdout)
        if not output.get("ok"):
            raise ProxyUpstreamError("upstream request failed")
        status = int(output["status"])
        response_body = base64.b64decode(output["body"], validate=True)
        if not 200 <= status <= 599 or len(response_body) > max_response_bytes:
            raise ProxyUpstreamError("upstream worker returned an invalid response")
        return ForwardResponse(
            status=status,
            headers=_validated_upstream_headers(
                [(str(name), str(value)) for name, value in output["headers"].items()]
            ),
            body=response_body,
        )
    except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProxyUpstreamError("upstream worker returned an invalid response") from exc


def forward_request(
    store: CapabilityStore,
    *,
    token: str,
    method: str,
    target: str,
    headers: Mapping[str, str],
    body: bytes,
    sender: Callable[..., Any] | None = None,
    max_response_bytes: int = 8 * 1024 * 1024,
    upstream_timeout_seconds: float = 30,
    audit_path: str | None = None,
) -> ForwardResponse:
    parsed_target = urlsplit(target)
    if not target.startswith("/") or parsed_target.scheme or parsed_target.netloc or parsed_target.fragment:
        raise ProxyRequestError("request target must use origin-form")
    with store.dispatch(token, method, parsed_target.path) as capability:
        audit_base = {
            "caller": capability.caller or "capability",
            "profile": capability.profile,
            "grant": capability.grant_name,
            "provider": "local_proxy",
            "ttl_seconds": 0,
            "lease_id": capability.lease_id,
            "reason": "proxy request",
            "method": method.upper(),
            "route": parsed_target.path,
        }
        if audit_path is not None:
            write_audit_event(audit_path, {"event": "proxy_attempt", **audit_base})
        if capability.authentication == "peercred":
            # Peer-credential grants are renewable, so the model boundary is
            # enforced on every request rather than by a short-lived token.
            assert capability.allowed_models is not None
            try:
                validate_peercred_chat_body(body, capability.allowed_models)
            except ProxyRequestError as exc:
                if audit_path is not None:
                    write_audit_event(
                        audit_path,
                        {"event": "proxy_rejected", **audit_base, "failure_type": "model_validation"},
                    )
                # The HTTP handler must not emit a second terminal rejection.
                try:
                    setattr(exc, "_keyholder_rejection_audited", True)
                except (AttributeError, TypeError):
                    pass
                raise
        upstream_headers = _forward_headers(headers)
        upstream_headers["Authorization"] = f"Bearer {capability.upstream_api_key}"
        try:
            upstream_url = capability.upstream_base_url.rstrip("/") + target
            if sender is None:
                result = _default_upstream_request(
                    method=method.upper(),
                    url=upstream_url,
                    headers=upstream_headers,
                    body=body,
                    max_response_bytes=max_response_bytes,
                    timeout_seconds=upstream_timeout_seconds,
                )
            else:
                response = sender(
                    method=method.upper(),
                    url=upstream_url,
                    headers=upstream_headers,
                    data=body,
                    timeout=upstream_timeout_seconds,
                    allow_redirects=False,
                    stream=True,
                )
                try:
                    declared_length = response.headers.get("Content-Length")
                    if declared_length is not None and int(declared_length) > max_response_bytes:
                        raise ProxyUpstreamError("upstream response is too large")
                    if hasattr(response, "raw"):
                        response_body = response.raw.read(max_response_bytes + 1, decode_content=False)
                    else:
                        response_body = bytes(response.content)
                    if len(response_body) > max_response_bytes:
                        raise ProxyUpstreamError("upstream response is too large")
                    result = ForwardResponse(
                        status=int(response.status_code),
                        headers=_validated_upstream_headers(list(response.headers.items())),
                        body=response_body,
                    )
                    if not 200 <= result.status <= 599:
                        raise ProxyUpstreamError("upstream returned an unsupported response status")
                finally:
                    close = getattr(response, "close", None)
                    if close is not None:
                        close()
        except Exception as exc:
            if audit_path is not None:
                write_audit_event(
                    audit_path,
                    {"event": "proxy_failed", **audit_base, "failure_type": type(exc).__name__},
                )
                try:
                    setattr(exc, "_keyholder_audited", True)
                except (AttributeError, TypeError):
                    pass
            raise
        if audit_path is not None:
            write_audit_event(
                audit_path,
                {"event": "proxy_complete", **audit_base, "upstream_status": result.status},
            )
        return result


class ProxyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        store: CapabilityStore,
        audit_path: str,
        sender: Callable[..., Any] | None = None,
        max_body_bytes: int = 8 * 1024 * 1024,
        max_response_bytes: int = 8 * 1024 * 1024,
        max_workers: int = 16,
        request_timeout_seconds: float = 15,
        upstream_timeout_seconds: float = 30,
    ) -> None:
        (max_body_bytes, max_response_bytes, request_timeout_seconds,
         upstream_timeout_seconds, max_workers) = validate_proxy_resource_limits(
            max_body_bytes=max_body_bytes, max_response_bytes=max_response_bytes,
            request_timeout_seconds=request_timeout_seconds,
            upstream_timeout_seconds=upstream_timeout_seconds, max_workers=max_workers,
        )
        self.store = store
        self.audit_path = audit_path
        self.sender = sender
        self.max_body_bytes = max_body_bytes
        self.max_response_bytes = max_response_bytes
        self.max_workers = max_workers
        self.request_timeout_seconds = request_timeout_seconds
        self.upstream_timeout_seconds = upstream_timeout_seconds
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        self._deadline_lock = threading.Lock()
        self._request_deadlines: dict[int, threading.Timer] = {}
        self.address_family = address_family_for_host(server_address[0])
        super().__init__(server_address, ProxyHandler)

    def service_actions(self) -> None:
        self.store.purge_expired()

    def get_request(self) -> tuple[Any, Any]:
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout_seconds)
        deadline = threading.Timer(
            self.request_timeout_seconds, self._expire_request, args=(request,)
        )
        deadline.daemon = True
        with self._deadline_lock:
            self._request_deadlines[id(request)] = deadline
        deadline.start()
        return request, client_address

    def _expire_request(self, request: Any) -> None:
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        request.close()

    def _cancel_request_deadline(self, request: Any) -> None:
        with self._deadline_lock:
            deadline = self._request_deadlines.pop(id(request), None)
        if deadline is not None:
            deadline.cancel()

    def process_request(self, request: Any, client_address: Any) -> None:
        self._worker_slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._cancel_request_deadline(request)
            self._worker_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._cancel_request_deadline(request)
            self._worker_slots.release()


class ProxyHandler(BaseHTTPRequestHandler):
    def __getattr__(self, name: str) -> Any:
        if name.startswith("do_"):
            return self._handle
        raise AttributeError(name)

    def log_message(self, format: str, *args: Any) -> None:
        LOG.info(format, *args)

    def _send(self, status: int, body: bytes, headers: Mapping[str, str]) -> None:
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._send(
            status,
            json.dumps({"error": message}).encode(),
            {"Content-Type": "application/json"},
        )

    def _audit_rejection(self, event: str, failure_type: str) -> None:
        server = cast(ProxyHTTPServer, self.server)
        write_audit_event(
            server.audit_path,
            {
                "event": event,
                "caller": "capability",
                "profile": "",
                "grant": "",
                "provider": "local_proxy",
                "ttl_seconds": 0,
                "lease_id": "",
                "reason": "proxy request rejected",
                "method": self.command,
                "route": urlsplit(self.path).path,
                "failure_type": failure_type,
            },
        )

    @staticmethod
    def _capability_token(headers: Mapping[str, str]) -> str:
        authorization = next(
            (value for name, value in headers.items() if name.lower() == "authorization"),
            "",
        )
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token:
            raise ProxyAuthorizationError("bearer capability is required")
        return token

    def _proxy(self) -> None:
        server = cast(ProxyHTTPServer, self.server)
        raw_header_items = list(self.headers.raw_items())
        headers = validated_header_items(raw_header_items)
        token = self._capability_token(headers)
        parsed_target = urlsplit(self.path)
        server.store.authorize(token, self.command, parsed_target.path)
        content_lengths = [
            value for name, value in raw_header_items if name.lower() == "content-length"
        ]
        transfer_encoding = next(
            (value for name, value in raw_header_items if name.lower() == "transfer-encoding"),
            None,
        )
        content_length = validated_content_length(
            content_lengths,
            transfer_encoding=transfer_encoding,
            max_body_bytes=server.max_body_bytes,
        )
        body = read_exact_body(self.rfile, content_length)
        response = forward_request(
            server.store,
            token=token,
            method=self.command,
            target=self.path,
            headers=headers,
            body=body,
            sender=server.sender,
            max_response_bytes=server.max_response_bytes,
            upstream_timeout_seconds=server.upstream_timeout_seconds,
            audit_path=server.audit_path,
        )
        try:
            self._send(response.status, response.body, response.headers)
        except OSError:
            # The upstream operation and its audit record are complete. A caller
            # disconnect must not create a contradictory proxy-failure record.
            LOG.info("proxy caller disconnected before receiving response")

    def _handle(self) -> None:
        try:
            self._proxy()
        except ProxyAuthorizationError as exc:
            self._audit_rejection("proxy_denied", type(exc).__name__)
            status = 401 if str(exc) in {"bearer capability is required", "invalid capability"} else 403
            self._error(status, str(exc))
        except ProxyRequestError as exc:
            if not getattr(exc, "_keyholder_rejection_audited", False):
                self._audit_rejection("proxy_rejected", type(exc).__name__)
            self._error(exc.status, str(exc))
        except (requests.RequestException, ProxyUpstreamError, OSError, ValueError) as exc:
            if not getattr(exc, "_keyholder_audited", False):
                self._audit_rejection("proxy_handler_failed", type(exc).__name__)
            LOG.exception("proxy request failed")
            self._error(502, "upstream request failed")

    do_CONNECT = _handle
    do_DELETE = _handle
    do_GET = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle
    do_PATCH = _handle
    do_POST = _handle
    do_PUT = _handle
    do_TRACE = _handle
