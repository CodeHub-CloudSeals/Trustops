"""Authenticated, read-only LedgerSight Cloud Run connector.

The local operator can reuse the deployed bootstrap identity via gcloud. Its
credentials and session cookie remain in server memory. The connector exposes
only governance metadata for explicitly mapped TrustOps tenants/workspaces.
It never redeploys LedgerSight or copies its database or uploaded source files.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import subprocess
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Query, Response

SIGNED_FIELDS = ["event_id", "timestamp_utc", "tenant_id", "workspace_id", "actor_type", "actor_id",
                 "workflow_pack", "run_id", "source_batch_sha256", "source_line_refs", "canonical_version",
                 "matching_rule_id", "model_route", "action", "policy_decision", "approval_id",
                 "policy_id", "policy_version", "required_role", "agent_code", "delegated_by", "trace_id",
                 "prior_hash", "key_id"]
READ_ROLES = {"customer_admin", "customer_architect", "customer_risk", "customer_controller",
              "cloudseals_admin", "cloudseals_platform_ops", "auditor_readonly", "customer_viewer", "customer_operator"}


class ConnectorUnavailable(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def verify_chain(events, public_key_pem):
    """Independently verify the source's canonical Ed25519 event format."""
    if not events or not public_key_pem:
        return {"state": "UNKNOWN", "checked": 0, "reason": "No events or verification key"}
    checked = 0
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("wrong key type")
        prior = "0" * 64
        for ev in events:
            if ev.get("prior_hash") != prior:
                raise ValueError("chain break")
            body = json.dumps({k: ev.get(k) for k in SIGNED_FIELDS}, sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(body).hexdigest() != ev.get("event_hash"):
                raise ValueError("hash mismatch")
            key.verify(bytes.fromhex(ev["signature"]), body)
            prior = ev["event_hash"]
            checked += 1
    except Exception:
        return {"state": "FAIL", "checked": checked, "reason": "Hash chain or Ed25519 signature verification failed"}
    return {"state": "PASS", "checked": checked, "reason": "Hash chain and Ed25519 signatures verified by TrustOps"}


def _gcloud(*args):
    try:
        result = subprocess.run([os.environ.get("TRUSTOPS_GCLOUD_BIN", "gcloud"), *args], capture_output=True,
                                text=True, check=True, timeout=40)
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        raise ConnectorUnavailable("The local Cloud Run credential source is unavailable") from None


def load_credentials():
    """Local-only reuse of the existing deployed identity, without credential files."""
    if os.environ.get("TAAD_ENV", "local") != "local" or os.environ.get("TRUSTOPS_LEDGERSIGHT_AUTH") != "local_gcloud":
        raise ConnectorUnavailable("LedgerSight service authentication is not configured")
    project = os.environ["TRUSTOPS_LEDGERSIGHT_PROJECT"]
    service = os.environ["TRUSTOPS_LEDGERSIGHT_SERVICE"]
    region = os.environ["TRUSTOPS_LEDGERSIGHT_REGION"]
    try:
        metadata = json.loads(_gcloud("run", "services", "describe", service, "--project", project,
                                      "--region", region, "--format=json"))
        env = {e["name"]: e for e in metadata["spec"]["template"]["spec"]["containers"][0].get("env", [])}

        def value(name):
            entry = env[name]
            if "value" in entry:
                return entry["value"]
            ref = entry["valueFrom"]["secretKeyRef"]
            return _gcloud("secrets", "versions", "access", ref.get("key", "latest"),
                           "--secret", ref["name"], "--project", project).strip()

        return value("AVOCET_BOOTSTRAP_USER"), value("AVOCET_BOOTSTRAP_PASSWORD"), value("AVOCET_BOOTSTRAP_TOTP")
    except (KeyError, ValueError, TypeError):
        raise ConnectorUnavailable("The existing LedgerSight service identity could not be resolved") from None


def totp(secret):
    secret = secret.strip().upper()
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


class LedgerSightClient:
    def __init__(self, base_url, credentials=load_credentials, transport=None):
        u = urlsplit(base_url)
        if u.scheme != "https" or not u.netloc or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
            raise ValueError("LedgerSight requires a fixed HTTPS service origin")
        self.base_url = base_url.rstrip("/")
        self.http = httpx.Client(base_url=self.base_url, timeout=httpx.Timeout(45, connect=15),
                                 follow_redirects=False, transport=transport)
        self.credentials = credentials
        self.lock = threading.RLock()
        self.login_after = 0

    def _login(self):
        if time.monotonic() < self.login_after:
            raise ConnectorUnavailable("LedgerSight authentication needs attention; retry after one minute")
        self.login_after = time.monotonic() + 60
        try:
            uid, password, secret = self.credentials()
            result = self.http.post("/v1/login", json={"user_id": uid, "password": password, "code": totp(secret)})
            if result.status_code != 200 or not self.http.cookies.get("ls_session"):
                raise ConnectorUnavailable("LedgerSight sign-in failed; check the existing service identity")
        except ConnectorUnavailable:
            raise
        except Exception:
            raise ConnectorUnavailable("LedgerSight authentication could not be completed") from None

    def get(self, path):
        # No arbitrary proxying, caller-supplied URLs or financial mutation paths.
        if not (path in {"/v1/trust", "/v1/rulebooks", "/v1/workspaces"}
                or path.startswith("/v1/workspaces/") and not any(x in path for x in ("..", "?", "#"))):
            raise ValueError("Unsupported read resource")
        with self.lock:
            try:
                if not self.http.cookies.get("ls_session"):
                    self._login()
                result = self.http.get(path)
                if result.status_code == 401:
                    self.http.cookies.clear()
                    self._login()
                    result = self.http.get(path)
                if result.status_code in (403, 404):
                    raise ConnectorUnavailable("LedgerSight denied access to the configured resource")
                if result.status_code != 200:
                    raise ConnectorUnavailable("LedgerSight did not return a successful read response")
                return result.json()
            except (httpx.HTTPError, ValueError):
                raise ConnectorUnavailable("LedgerSight could not be reached or returned an invalid response") from None


class GovernanceConnector:
    def __init__(self, client):
        self.client = client
        self.cache = {}
        self.lock = threading.RLock()

    def snapshot(self, workspace_ids, refresh=False):
        cache_key = tuple(sorted(workspace_ids))
        with self.lock:
            cached = self.cache.get(cache_key)
            if not refresh and cached and time.monotonic() - cached[0] < 15:
                return cached[1]
            trust = self.client.get("/v1/trust")
            rulebook = self.client.get("/v1/rulebooks")
            workspaces, runs, reviews, events, proofs, documents = [], [], [], [], [], []
            for wid in workspace_ids:
                prefix = f"/v1/workspaces/{quote(wid, safe='')}"
                w = self.client.get(prefix)
                ev = self.client.get(prefix + "/evidence")
                chain = ev.get("events", [])
                # Refuse a mixed-client response even when the remote session is more privileged.
                if w.get("id") != wid or any(e.get("workspace_id") != wid or e.get("tenant_id") != trust["tenant"] for e in chain):
                    raise ConnectorUnavailable("LedgerSight returned evidence outside the configured workspace scope")
                verification = verify_chain(chain, trust.get("evidence", {}).get("public_key_pem"))
                proofs.append({"workspace_id": wid, **verification})
                workspaces.append({"id": wid, "name": w.get("name", wid), "verification": verification,
                                   "events": len(chain), "run_count": len(w.get("runs", []))})
                for upload in w.get("uploads", []) + w.get("held", []):
                    if not upload.get("id") or not upload.get("sha256"):
                        continue
                    documents.append({"upload_id": upload["id"], "sha256": upload["sha256"],
                                      "workspace_id": wid, "workspace_name": w.get("name", wid),
                                      "filename": upload.get("filename", upload["id"]), "kind": upload.get("kind", "document"),
                                      "size": upload.get("size"), "rows": upload.get("rows"),
                                      "uploaded_by": upload.get("uploaded_by"), "uploaded_at": upload.get("uploaded_at"),
                                      "source_state": upload.get("state"), "header": upload.get("header", [])[:30],
                                      "preview": [row[:30] for row in upload.get("preview", [])[:6]],
                                      "fields": upload.get("fields", {}), "unsafe_content": upload.get("unsafe_content", [])})
                events.extend({**e, "workspace_name": w.get("name", wid)} for e in chain)
                for summary in sorted(w.get("runs", []), key=lambda r: r.get("created_at", ""), reverse=True)[:25]:
                    rid = summary["id"]
                    run = self.client.get(prefix + "/runs/" + quote(rid, safe=""))
                    if run.get("id") != rid or run.get("result", {}).get("workspace_id") != wid:
                        raise ConnectorUnavailable("LedgerSight returned an unexpected run")
                    exceptions = run.get("result", {}).get("exceptions", [])
                    pending = sum(e.get("status", "OPEN") in {"OPEN", "PENDING", "PROPOSED", "RETURNED"} for e in exceptions)
                    for e in exceptions:
                        reviews.append({"id": e["id"], "case_id": e.get("case_id"), "run_id": rid,
                                        "workspace_id": wid, "workspace_name": w.get("name", wid),
                                        "type": e.get("type"), "status": e.get("status", "OPEN"),
                                        "reason": e.get("why"), "reviewer": e.get("reviewer"),
                                        "reviewed_at": e.get("reviewed_at"), "approval_id": e.get("approval_id"),
                                        "proposed_by": e.get("proposed_by"), "policy_id": e.get("trustops", {}).get("policy_id"),
                                        "required_role": e.get("trustops", {}).get("required_role"),
                                        "evidence_refs": e.get("evidence_refs", [])})
                    runs.append({"id": rid, "trace_id": run.get("trace_id"), "workspace_id": wid,
                                 "workspace_name": w.get("name", wid), "created_at": run.get("created_at"),
                                 "created_by": run.get("created_by"), "policy_version": run.get("rulebook_version"),
                                 "status": "REVIEW_PENDING" if pending else "COMPLETE", "exceptions": len(exceptions),
                                 "pending_reviews": pending, "workflow": run.get("workflow", []),
                                 "stages": run.get("stages", []), "verification": verification["state"]})
            runs.sort(key=lambda r: r.get("created_at") or "", reverse=True)
            events.sort(key=lambda e: e.get("timestamp_utc") or "", reverse=True)
            counts = Counter(str(e.get("policy_decision", "")).split(":")[0] for e in events)
            run_ids = {(r["workspace_id"], r["id"]) for r in runs}
            linked = [e for e in events if (e["workspace_id"], e.get("run_id")) in run_ids
                      and e.get("action") not in {"workspace.read", "export.read"}][:200]
            # Preserve original agent/reviewer events even when recent reads would
            # otherwise push them out of the activity window.
            visible = {(e["workspace_id"], e["event_id"]): e for e in events[:100] + linked}
            visible = sorted(visible.values(), key=lambda e: e.get("timestamp_utc") or "", reverse=True)
            states = {p["state"] for p in proofs}
            verification_state = "FAIL" if "FAIL" in states else "PASS" if states == {"PASS"} else "UNKNOWN"
            result = {"application_id": "ledgersight", "status": "connected", "source": "cloud_run",
                      "service_url": self.client.base_url, "source_tenant": trust["tenant"], "synced_at": utc_now(),
                      "sync_mode": "authenticated_read_only", "workspaces": workspaces, "runs": runs, "reviews": reviews,
                      "documents": documents, "document_gate_enforced": bool(trust.get("document_review_gate", {}).get("enforced")),
                      "events": visible, "verification": {"state": verification_state, "workspaces": proofs,
                          "checked": sum(p["checked"] for p in proofs), "verifier": "trustops_ed25519"},
                      "policies": rulebook.get("policies", []), "agents": rulebook.get("agents", []),
                      "policy_version": rulebook.get("version"), "decision_counts": dict(counts),
                      "event_window": "Latest 100 activity events plus latest 200 run actions; overlapping events appear once",
                      "run_window": "Latest 25 runs per workspace", "total_runs": sum(w["run_count"] for w in workspaces),
                      "total_events": sum(w["events"] for w in workspaces)}
            self.cache[cache_key] = (time.monotonic(), result)
            return result


def make_router(principal, audit=None, connector=None, identity=None):
    router = APIRouter(prefix="/v1/applications/ledgersight", tags=["Application governance"])
    instance = connector

    @router.get("/snapshot")
    def snapshot(response: Response, refresh: bool = Query(False), p=Depends(principal)):
        nonlocal instance
        response.headers["Cache-Control"] = "no-store"
        try:
            mapping = json.loads(os.environ.get("TRUSTOPS_LEDGERSIGHT_TENANT_MAP", "{}"))
            scope = mapping.get(p.tenant_id)
            if not scope or not set(p.roles) & READ_ROLES:
                raise HTTPException(404, {"code": "not_found", "message": "Application connection not found"})
            if not isinstance(scope.get("workspaces"), list) or not scope["workspaces"] or not scope.get("source_tenant"):
                raise ConnectorUnavailable("LedgerSight workspace mapping is incomplete")
            if instance is None:
                instance = GovernanceConnector(LedgerSightClient(os.environ["TRUSTOPS_LEDGERSIGHT_URL"]))
            data = instance.snapshot(scope["workspaces"], refresh=refresh)
            if data["source_tenant"] != scope["source_tenant"]:
                raise ConnectorUnavailable("LedgerSight tenant identity does not match the configured mapping")
            if data.get("documents"):
                from .document_reviews import DocumentReviewStore, document_key
                records = {r["payload"]["document_key"]: r for r in DocumentReviewStore(os.environ.get("TRUSTOPS_POLICY_DATA_DIR", str(Path.cwd() / ".trustops-data"))).listing(p.tenant_id)}
                documents = [{**d, "review_status": records[document_key(p.tenant_id, data["source_tenant"], d)]["payload"]["decision"] if document_key(p.tenant_id, data["source_tenant"], d) in records else "PENDING"} for d in data["documents"]]
                data = {**data, "documents": documents, "pending_document_reviews": sum(d["review_status"] == "PENDING" for d in documents)}
            if audit:
                audit(p, "application.ledgersight.read", ",".join(scope["workspaces"]))
            return data
        except HTTPException:
            raise
        except Exception:
            # Never return upstream bodies, credential failures or subprocess output.
            raise HTTPException(503, {"code": "ledgersight_unavailable", "message": "LedgerSight live sync is unavailable. Check the server connection and service identity."}) from None

    from .document_reviews import make_document_router
    router.include_router(make_document_router(principal, lambda p, fresh: snapshot(Response(), fresh, p), identity=identity))
    return router
