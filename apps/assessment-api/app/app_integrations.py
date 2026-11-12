"""Customer-registered application integrations.

A workspace administrator registers an application by name, HTTPS base URL and
credentials. Secrets are encrypted at rest on the TrustOps server and are never
returned to the browser. "Test" makes one authenticated GET to the application's
health path. Registering an application does not, by itself, enforce policy on it:
the application must call TrustOps for decisions (see docs).

Local storage note: the encryption key lives in the server data directory. A hosted
deployment should move secrets to Secret Manager / KMS before customer use.
"""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
import json
import os
import re
import socket
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet
from fastapi import APIRouter, Body, Depends, HTTPException

ADMIN_ROLES = {"customer_admin", "cloudseals_admin"}
READ_ROLES = ADMIN_ROLES | {"customer_architect", "customer_risk", "customer_controller", "auditor_readonly",
                            "cloudseals_platform_ops", "customer_viewer", "customer_operator"}
AUTH_TYPES = {"trustops_key", "api_key", "bearer", "basic", "oauth_client"}
SECRET_FIELDS = {"api_key", "token", "password", "client_secret"}
NAME = re.compile(r"^[\w .&()-]{2,60}$")


def _err(code, status, message):
    return HTTPException(status, {"code": code, "message": message})


class _Mem:
    def __init__(self):
        import threading
        self.lock = threading.RLock()
        self.integrations = {}


def _fernet():
    """Encryption key for stored credentials: TRUSTOPS_INTEGRATION_KEY (from a secret manager) in hosted
    environments; a key file in the local data directory only when TAAD_ENV=local."""
    env_key = os.environ.get("TRUSTOPS_INTEGRATION_KEY")
    if env_key:
        return Fernet(env_key.encode())
    if os.environ.get("TAAD_ENV", "local") != "local":
        return None
    d = Path(os.environ.get("TRUSTOPS_POLICY_DATA_DIR", str(Path.cwd() / ".trustops-data")))
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    keyfile = d / "integration-secrets.key"
    if not keyfile.exists():
        fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Fernet.generate_key())
    return Fernet(keyfile.read_bytes())


class IntegrationStore:
    """Integrations live in the shared Store (persisted with the rest of TrustOps state)."""

    def __init__(self, state=None):
        self.state = state if state is not None else _Mem()
        self.fernet = _fernet()

    def _enc(self, secret):
        if self.fernet is None:
            raise _err("secrets_unavailable", 503, "Credential storage is not configured on this server (TRUSTOPS_INTEGRATION_KEY)")
        return self.fernet.encrypt(json.dumps(secret).encode()).decode()

    def list(self, tenant):
        with self.state.lock:
            rows = [r for r in self.state.integrations.values() if r["tenant"] == tenant]
        return [dict(r["body"]) for r in sorted(rows, key=lambda r: r["body"].get("created_at", 0))]

    def get(self, tenant, iid):
        with self.state.lock:
            r = self.state.integrations.get(iid)
        if not r or r["tenant"] != tenant:
            return None, None
        if not r.get("secret"):
            return dict(r["body"]), {}
        if self.fernet is None:
            raise _err("secrets_unavailable", 503, "Credential storage is not configured on this server (TRUSTOPS_INTEGRATION_KEY)")
        return dict(r["body"]), json.loads(self.fernet.decrypt(r["secret"].encode()))

    def put(self, tenant, body, secret):
        enc = self._enc(secret)
        with self.state.lock:
            self.state.integrations[body["id"]] = {"tenant": tenant, "body": dict(body), "secret": enc}

    def find_by_key(self, key):
        if not key or not key.startswith("tok_"):
            return None
        h = hashlib.sha256(key.encode()).hexdigest()
        with self.state.lock:
            rows = list(self.state.integrations.values())
        for r in rows:
            if r["body"].get("key_hash") and secrets.compare_digest(r["body"]["key_hash"], h):
                return r["tenant"], dict(r["body"])
        return None

    def delete(self, tenant, iid):
        with self.state.lock:
            r = self.state.integrations.get(iid)
            if not r or r["tenant"] != tenant:
                return 0
            del self.state.integrations[iid]
            return 1


TRANSPORT = None   # tests may set an httpx transport


def authed_client(body, secret, transport=None):
    """httpx client + request kwargs authenticated with the stored credentials of an integration."""
    c = httpx.Client(timeout=httpx.Timeout(15, connect=8), follow_redirects=False, transport=transport or TRANSPORT)
    headers, auth = {"User-Agent": "TrustOps"}, None
    t = body["auth_type"]
    if t == "trustops_key":
        headers["X-TrustOps-Key"] = secret["trustops_key"]      # the same shared key the application uses to call TrustOps
    elif t == "api_key":
        headers[secret["api_key_header"]] = secret["api_key"]
    elif t == "bearer":
        headers["Authorization"] = f"Bearer {secret['token']}"
    elif t == "basic":
        auth = (secret["username"], secret["password"])
    else:
        tok = c.post(secret["token_url"], data={"grant_type": "client_credentials",
                     "client_id": secret["client_id"], "client_secret": secret["client_secret"]})
        if tok.status_code != 200 or "access_token" not in tok.json():
            c.close()
            raise RuntimeError(f"Token request was refused (HTTP {tok.status_code})")
        headers["Authorization"] = f"Bearer {tok.json()['access_token']}"
    return c, {"headers": headers, "auth": auth}


def _check_url(url, allow_private=False):
    u = urlsplit(url or "")
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise _err("invalid_url", 422, "Enter the application's HTTPS address, e.g. https://app.example.com")
    if not allow_private:
        try:
            addrs = {ai[4][0] for ai in socket.getaddrinfo(u.hostname, u.port or 443)}
        except OSError:
            raise _err("unreachable", 422, "That address could not be resolved")
        for a in addrs:
            ip = ipaddress.ip_address(a)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise _err("invalid_url", 422, "Private or internal network addresses are not allowed")
    return url.rstrip("/")


def _public(body):
    return {k: v for k, v in body.items() if k not in ("secret_fields", "key_hash")} | {
        "secrets_set": body.get("secret_fields", []), "has_trustops_key": bool(body.get("key_hash"))}


def _new_key():
    key = "tok_" + secrets.token_urlsafe(32)
    return key, hashlib.sha256(key.encode()).hexdigest()


def make_router(principal, audit=None, identity=None, store=None, transport=None, state=None):
    router = APIRouter(prefix="/v1/integrations", tags=["Application integrations"])
    db = store or IntegrationStore(state)
    allow_private = os.environ.get("TAAD_ENV", "local") == "local" and os.environ.get("TRUSTOPS_INTEGRATIONS_ALLOW_PRIVATE") == "1"

    def need(p, roles):
        if not p.tenant_id or not set(p.roles) & roles:
            raise _err("forbidden", 403, "Only a workspace administrator can manage application integrations"
                       if roles is ADMIN_ROLES else "Not permitted")

    @router.get("")
    def list_integrations(p=Depends(principal)):
        need(p, READ_ROLES)
        return {"items": [_public(b) for b in db.list(p.tenant_id)], "can_manage": bool(set(p.roles) & ADMIN_ROLES)}

    @router.post("")
    def create(body: dict = Body(...), p=Depends(principal)):
        need(p, ADMIN_ROLES)
        name = str(body.get("name", "")).strip()
        if not NAME.match(name):
            raise _err("invalid_name", 422, "Enter an application name (2–60 characters)")
        auth = body.get("auth_type") or "trustops_key"
        if auth not in AUTH_TYPES:
            raise _err("invalid_auth", 422, "Choose how TrustOps should authenticate")
        raw_base = str(body.get("base_url") or "").strip()
        base = _check_url(raw_base, allow_private) if raw_base else None      # optional: only needed to load review details
        health = str(body.get("health_path") or "/").strip()
        details_path = str(body.get("details_path") or "/trustops/items/{ref}").strip()
        if not details_path.startswith("/") or "{ref}" not in details_path or ".." in details_path or "?" in details_path or len(details_path) > 200:
            raise _err("invalid_path", 422, "Details path must start with / and contain {ref}, e.g. /trustops/items/{ref}")
        if not health.startswith("/") or ".." in health or "?" in health or "#" in health:
            raise _err("invalid_path", 422, "Health path must start with / (e.g. /health)")
        secret, fields = {}, []
        req = {"trustops_key": [], "api_key": ["api_key"], "bearer": ["token"], "basic": ["username", "password"],
               "oauth_client": ["client_id", "client_secret", "token_url"]}[auth]
        for f in req + (["api_key_header"] if auth == "api_key" else []):
            v = str(body.get(f) or "").strip()
            if f == "api_key_header":
                v = v or "X-API-Key"
                if not re.match(r"^[A-Za-z0-9-]{1,64}$", v):
                    raise _err("invalid_header", 422, "Header name may contain letters, numbers and -")
            if not v:
                raise _err("missing_credential", 422, f"Enter {f.replace('_', ' ')}")
            if f == "token_url":
                v = _check_url(v, allow_private) if not urlsplit(v).query else v
            secret[f] = v
            if f in SECRET_FIELDS:
                fields.append(f)
        record = {"id": "int_" + uuid.uuid4().hex[:12], "name": name, "category": str(body.get("category") or "Other")[:40],
                  "base_url": base, "health_path": health, "details_path": details_path, "auth_type": auth,
                  "username": secret.get("username"), "client_id": secret.get("client_id"),
                  "api_key_header": secret.get("api_key_header"), "secret_fields": fields,
                  "status": "untested" if base else "key_only", "last_tested_at": None, "last_result": None,
                  "created_by": identity(p) if identity else p.sub, "created_at": time.time()}
        key, record["key_hash"] = _new_key()
        if auth == "trustops_key":
            secret["trustops_key"] = key
        record["key_hint"] = key[:8] + "…" + key[-4:]
        db.put(p.tenant_id, record, secret)
        if audit:
            audit(p, "integration.create", f"{record['id']}:{name}")
        return _public(record) | {"trustops_key": key}

    @router.post("/{iid}/rotate-key")
    def rotate(iid: str, p=Depends(principal)):
        need(p, ADMIN_ROLES)
        body, secret = db.get(p.tenant_id, iid)
        if not body:
            raise _err("not_found", 404, "Integration not found")
        key, body["key_hash"] = _new_key()
        if body["auth_type"] == "trustops_key":
            secret["trustops_key"] = key
        body["key_hint"] = key[:8] + "…" + key[-4:]
        db.put(p.tenant_id, body, secret)
        if audit:
            audit(p, "integration.rotate_key", iid)
        return _public(body) | {"trustops_key": key}

    @router.patch("/{iid}")
    def update(iid: str, body: dict = Body(...), p=Depends(principal)):
        need(p, ADMIN_ROLES)
        rec, secret = db.get(p.tenant_id, iid)
        if not rec:
            raise _err("not_found", 404, "Integration not found")
        if "base_url" in body:
            raw = str(body.get("base_url") or "").strip()
            rec["base_url"] = _check_url(raw, allow_private) if raw else None
            rec["status"] = "untested" if rec["base_url"] else "key_only"
        db.put(p.tenant_id, rec, secret)
        if audit:
            audit(p, "integration.update", iid)
        return _public(rec)

    @router.delete("/{iid}")
    def remove(iid: str, p=Depends(principal)):
        need(p, ADMIN_ROLES)
        if not db.delete(p.tenant_id, iid):
            raise _err("not_found", 404, "Integration not found")
        if audit:
            audit(p, "integration.delete", iid)
        return {"deleted": iid}

    @router.post("/{iid}/test")
    def test(iid: str, p=Depends(principal)):
        need(p, ADMIN_ROLES)
        body, secret = db.get(p.tenant_id, iid)
        if not body:
            raise _err("not_found", 404, "Integration not found")
        ok, message = False, ""
        if not body.get("base_url"):
            return {"ok": False, "message": "No address set. Add the application's address to test it.", "integration": _public(body)}
        try:
            c, kw = authed_client(body, secret, transport)
            with c:
                r = c.get(body["base_url"] + body["health_path"], **kw)
                ok = 200 <= r.status_code < 300
                message = f"Reached {body['name']} (HTTP {r.status_code})" if ok else \
                    "Credentials were rejected (HTTP %d)" % r.status_code if r.status_code in (401, 403) else \
                    f"Application responded with HTTP {r.status_code}"
        except RuntimeError as e:
            message = str(e)
        except Exception:
            message = "Could not reach the application. Check the address."
        body.update(status="connected" if ok else "failed", last_tested_at=time.time(), last_result=message)
        db.put(p.tenant_id, body, secret)
        if audit:
            audit(p, "integration.test", f"{iid}:{'ok' if ok else 'fail'}")
        return {"ok": ok, "message": message, "integration": _public(body)}

    router.store = db
    return router
