from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.client import HTTPSConnection
from urllib.parse import urlencode

from .base import IssuedCredential

ORIGIN = "api.vercel.com"
PROJECT_NAME = __import__('re').compile(r"^atlas-[a-z0-9-]+$")
DOMAIN = __import__('re').compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.chezchardin\.com$")
TARGETS = frozenset({"production", "preview", "development"})
MAX_LIMIT = 100

@dataclass(frozen=True)
class VercelCapability:
    token: str
    expires_at: datetime
    api_token: str
    lease_id: str

class VercelControlError(ValueError): pass

class VercelControlStore:
    def __init__(self) -> None:
        self._items: dict[str, VercelCapability] = {}
        self._lock = threading.RLock()
    def register(self, token: str, api_token: str, lease_id: str, ttl: int) -> None:
        with self._lock:
            self._items[token] = VercelCapability(token, datetime.now(UTC)+timedelta(seconds=ttl), api_token, lease_id)
    def revoke_lease(self, lease_id: str) -> None:
        with self._lock:
            for token in [t for t,c in self._items.items() if c.lease_id == lease_id]: self._items.pop(token, None)
    def resolve(self, token: str) -> VercelCapability:
        with self._lock:
            c = self._items.get(token)
            if c is None or c.expires_at <= datetime.now(UTC):
                self._items.pop(token, None)
                raise PermissionError("invalid or expired capability")
            return c


def _name(value: object) -> str:
    if not isinstance(value, str) or PROJECT_NAME.fullmatch(value) is None: raise VercelControlError("invalid Atlas project name")
    return value

def _domain(value: object) -> str:
    if not isinstance(value, str) or DOMAIN.fullmatch(value) is None: raise VercelControlError("invalid domain")
    return value

def translate(operation: str, request: dict) -> tuple[str,str,dict|None]:
    if not isinstance(request, dict): raise VercelControlError("request must be an object")
    allowed = {"create_project","get_project","add_domain","list_domains","list_deployments"}
    if operation not in allowed: raise VercelControlError("operation is not permitted")
    name = _name(request.get("project_name"))
    if set(request) - ({"project_name"} if operation in {"create_project","get_project"} else ({"project_name","domain"} if operation in {"add_domain","list_domains"} else {"project_name","limit","target"})): raise VercelControlError("unknown request field")
    if operation == "create_project":
        if set(request) != {"project_name"}: raise VercelControlError("create_project accepts project_name only")
        return "POST", "/v10/projects", {"name":name,"framework":"nextjs","gitRepository":{"type":"github","repo":"chardy-b/"+name},"rootDirectory":None,"gitComments":None,"gitLfs":None,"buildCommand":None,"devCommand":None,"installCommand":None,"outputDirectory":None,"publicSource":None,"serverlessFunctionRegion":None,"productionBranch":"main"}
    if operation == "get_project": return "GET", "/v9/projects?"+urlencode({"search":name}), None
    domain = _domain(request.get("domain")) if operation == "add_domain" else None
    if operation == "add_domain": return "POST", "/v10/projects/"+name+"/domains", {"name":domain}
    if operation == "list_domains": return "GET", "/v9/projects/"+name+"/domains", None
    limit = request.get("limit", 20)
    if not isinstance(limit,int) or isinstance(limit,bool) or not 1 <= limit <= MAX_LIMIT: raise VercelControlError("limit must be between 1 and 100")
    target = request.get("target")
    if target is not None and target not in TARGETS: raise VercelControlError("invalid target")
    query={"projectId":name,"limit":str(limit)}
    if target is not None: query["target"] = target
    return "GET", "/v6/deployments?"+urlencode(query), None

class VercelControlProvider:
    name = "vercel_control"
    def __init__(self, store: VercelControlStore|None=None): self.store=store or VercelControlStore()
    def validate(self, grant: dict, secrets_map: dict[str,str]) -> None:
        if not isinstance(secrets_map.get("vercel_api_token"),str) or not secrets_map["vercel_api_token"]: raise VercelControlError("missing vercel API token")
    def issue(self, grant:dict,secrets_map:dict[str,str],ttl_seconds:int)->IssuedCredential:
        self.validate(grant,secrets_map); token="khcap_"+secrets.token_urlsafe(32)
        return IssuedCredential(self.name,"capability",{"KEYHOLDER_CAPABILITY_TOKEN":token},token,datetime.now(UTC)+timedelta(seconds=ttl_seconds),"bounded Vercel control")
    def activate(self, cred, lease_id, secrets_map, ttl): self.store.register(cred.display_token,secrets_map["vercel_api_token"],lease_id,ttl)
    def request(self, token:str, operation:str, request:dict, timeout:float=15):
        c=self.store.resolve(token); method,path,payload=translate(operation,request)
        conn=HTTPSConnection(ORIGIN,timeout=timeout)
        try:
            body=None if payload is None else json.dumps(payload).encode()
            headers={"Authorization":"Bearer "+c.api_token,"Content-Type":"application/json"}
            conn.request(method,path,body=body,headers=headers); response=conn.getresponse(); raw=response.read(8*1024*1024+1)
            if len(raw)>8*1024*1024: raise VercelControlError("upstream response too large")
            try: result=json.loads(raw)
            except json.JSONDecodeError as exc: raise VercelControlError("malformed upstream response") from exc
            if not isinstance(result,dict): raise VercelControlError("malformed upstream response")
            return response.status,result
        finally: conn.close()
