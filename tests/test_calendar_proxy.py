from datetime import UTC, datetime, timedelta
import threading

import pytest
from keyholderd.proxy import CapabilityError, CapabilityStore, CalendarProxy

class Raw:
    def __init__(self, data): self.data=data
    def read(self, n=-1): return self.data
class Resp:
    status_code=200; headers={"Content-Type":"application/json"}
    def __init__(self, data=b'{"ok":true}'): self.raw=Raw(data)
class Session:
    def __init__(self): self.trust_env=True; self.calls=[]
    def get(self, url, **kw): self.calls.append((url,kw)); return Resp()
    def close(self): pass

def test_named_template_forwards_only_safe_google_request():
    store=CapabilityStore(); token, _=store.issue("hermes", "google-calendar-events-read-proxy", 30); session=Session()
    proxy=CalendarProxy(store, lambda _item: "oauth-access", session_factory=lambda: session)
    status, headers, body=proxy.forward(token,"hermes","google-calendar-events-read-proxy","GET","/calendar/v3/calendars/primary/events",{"maxResults":["5"]},{"Authorization":"attacker","X-Forwarded-For":"x"})
    assert status == 200 and body == b'{"ok":true}'
    assert session.calls[0][0].endswith("?maxResults=5")
    assert session.calls[0][1]["headers"] == {"Authorization":"Bearer oauth-access","Accept":"application/json"}

def test_proxy_denies_wrong_route_query_expiry_revocation_and_caller():
    store=CapabilityStore(); token, _=store.issue("hermes", "g", 30); proxy=CalendarProxy(store, lambda: "x")
    for kwargs in ({"path":"/other"},{"path":"/calendar/v3/calendars/primary/events","query":{"bad":["x"]}},{"caller":"other"}):
        with pytest.raises(CapabilityError): proxy.forward(token, kwargs.pop("caller","hermes"), "g", "GET", kwargs.pop("path","/calendar/v3/calendars/primary/events"), kwargs.pop("query",{}), {})
    store.revoke(token)
    with pytest.raises(CapabilityError): proxy.forward(token,"hermes","g","GET","/calendar/v3/calendars/primary/events",{}, {})

def test_production_origin_cannot_be_injected():
    with pytest.raises(ValueError):
        CalendarProxy(CapabilityStore(), lambda: "x", "http://127.0.0.1:1")


def test_revoke_waits_for_authorized_forward_and_blocks_subsequent_use():
    store = CapabilityStore()
    token, _ = store.issue("hermes", "g", 30, lease_id="lease")
    resolver_entered = threading.Event()
    release_resolver = threading.Event()
    resolver_calls = 0

    def resolver(_item):
        nonlocal resolver_calls
        resolver_calls += 1
        resolver_entered.set()
        assert release_resolver.wait(5)
        return "oauth"

    class Response:
        status_code = 200
        headers = {}
        class Raw:
            @staticmethod
            def read(_limit): return b"ok"
        raw = Raw()

    class ForwardSession:
        trust_env = True
        def get(self, *args, **kwargs): return Response()
        def close(self): pass

    proxy = CalendarProxy(store, resolver, session_factory=ForwardSession)
    forward = threading.Thread(target=lambda: proxy.forward(token, "hermes", "g", "GET", "/calendar/v3/calendars/primary/events", {}, {}))
    forward.start()
    assert resolver_entered.wait(5)
    revoked = threading.Event()
    revoke = threading.Thread(target=lambda: (store.revoke_lease("lease"), revoked.set()))
    revoke.start()
    assert not revoked.wait(0.1)
    release_resolver.set()
    forward.join(5); revoke.join(5)
    assert not forward.is_alive() and revoked.is_set()
    with pytest.raises(CapabilityError):
        proxy.forward(token, "hermes", "g", "GET", "/calendar/v3/calendars/primary/events", {}, {})
    assert resolver_calls == 1
