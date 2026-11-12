"""Uploaded-file review decisions, bound to source client, upload ID and SHA-256."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

REVIEWERS = {"customer_risk", "customer_controller"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def document_key(tenant, source_tenant, doc):
    return hashlib.sha256(canonical([tenant, source_tenant, doc["workspace_id"], doc["upload_id"], doc["sha256"]])).hexdigest()


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["APPROVED", "REJECTED"]
    reason: str = Field(min_length=3, max_length=2000)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: Literal[0] = 0


class InputFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    upload_id: str = Field(min_length=1, max_length=120)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class GateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str = Field(min_length=1, max_length=120)
    action: Literal["mapping.commit", "document.confirm", "run.compute"]
    files: list[InputFile] = Field(min_length=1, max_length=100)
    nonce: str = Field(min_length=16, max_length=120)


class DocumentReviewStore:
    def __init__(self, directory):
        self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "document-reviews.sqlite3"
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS decisions (key TEXT PRIMARY KEY, tenant TEXT NOT NULL, body TEXT NOT NULL)")
        self.path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            with db:
                yield db
        finally:
            db.close()

    def signer(self):
        path = self.directory / "document-review-signing-key.pem"
        if not path.exists():
            key = Ed25519PrivateKey.generate()
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            temporary = path.with_name(".review-key-" + uuid.uuid4().hex)
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f: f.write(pem)
                os.link(temporary, path)
            except FileExistsError:
                pass
            finally:
                temporary.unlink(missing_ok=True)
        return serialization.load_pem_private_key(path.read_bytes(), None)

    def sign(self, value):
        key = self.signer()
        return {"payload": value, "signature": key.sign(canonical(value)).hex(), "algorithm": "Ed25519",
                "public_key_pem": key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}

    def listing(self, tenant):
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT body FROM decisions WHERE tenant=?", (tenant,))]

    def record(self, tenant, source_tenant, doc, reviewer, body):
        reason = body.reason.strip()
        if len(reason) < 3:
            raise HTTPException(422, "Explain why you approved or rejected this document")
        key = document_key(tenant, source_tenant, doc)
        payload = {"event_id": str(uuid.uuid4()), "at": datetime.now(timezone.utc).isoformat(),
                   "tenant_id": tenant, "source_tenant": source_tenant, "workspace_id": doc["workspace_id"],
                   "document_key": key, "upload_id": doc["upload_id"], "sha256": doc["sha256"],
                   "filename": doc["filename"], "uploaded_by": doc["uploaded_by"], "reviewer": reviewer,
                   "decision": body.decision, "reason": reason, "revision": 1}
        signed = self.sign(payload)
        try:
            with self.connect() as db:
                db.execute("INSERT INTO decisions VALUES (?,?,?)", (key, tenant, json.dumps(signed)))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "This exact document already has a review decision. Reload its history") from None
        return signed


def make_document_router(principal, source_snapshot, identity=None, store=None):
    router = APIRouter(prefix="/documents", tags=["Uploaded document reviews"])
    instance = store

    def db():
        nonlocal instance
        if instance is None:
            instance = DocumentReviewStore(os.environ.get("TRUSTOPS_POLICY_DATA_DIR", str(Path.cwd() / ".trustops-data")))
        return instance

    def actor(p):
        return (identity(p) if identity else p.sub).strip().lower()

    def decorated(p, fresh=False):
        mapping = json.loads(os.environ.get("TRUSTOPS_LEDGERSIGHT_TENANT_MAP", "{}")).get(p.tenant_id)
        readers = {"customer_admin", "customer_architect", "customer_operator", "customer_risk", "customer_controller", "customer_viewer", "auditor_readonly"}
        if not mapping or not set(p.roles) & readers:
            raise HTTPException(404, "Document review workspace not found")
        source = source_snapshot(p, fresh)
        if source["source_tenant"] != mapping["source_tenant"]:
            raise HTTPException(503, "Source identity mismatch")
        recorded = {r["payload"]["document_key"]: r for r in db().listing(p.tenant_id)}
        docs = []
        for doc in source.get("documents", []):
            if doc["workspace_id"] not in mapping["workspaces"]:
                raise HTTPException(503, "Source workspace mismatch")
            key = document_key(p.tenant_id, source["source_tenant"], doc)
            signed = recorded.get(key)
            own = not doc.get("uploaded_by") or str(doc["uploaded_by"]).lower() in {actor(p), str(p.sub).lower()}
            docs.append({**doc, "document_key": key, "review_status": signed["payload"]["decision"] if signed else "PENDING",
                         "review": signed["payload"] if signed else None, "decision_evidence": signed,
                         "can_review": bool(set(p.roles) & REVIEWERS) and not own and not signed,
                         "review_block_reason": "A different reviewer must decide" if own else None})
        return {"items": docs, "actor": actor(p), "synced_at": source["synced_at"],
                "runtime_gate_enforced": source.get("document_gate_enforced", False),
                "enforcement_note": "TrustOps decisions are recorded here. The deployed LedgerSight runtime gate has not been enabled; this view does not block source processing." if not source.get("document_gate_enforced") else "LedgerSight blocks unapproved document processing."}

    @router.get("")
    def listing(response: Response, p=Depends(principal)):
        response.headers["Cache-Control"] = "no-store"
        return decorated(p)

    @router.post("/{key}/decision")
    def decide(key: str, body: Decision, p=Depends(principal)):
        if not set(p.roles) & REVIEWERS:
            raise HTTPException(403, "A Reviewer must approve or reject documents")
        source = decorated(p, fresh=True)
        doc = next((d for d in source["items"] if d["document_key"] == key), None)
        if not doc:
            raise HTTPException(404, "Document not found in your current client scope")
        if doc["sha256"] != body.sha256:
            raise HTTPException(409, "The source file changed. Reload and review the current content")
        if not doc["can_review"]:
            raise HTTPException(409 if doc["review"] else 403, doc.get("review_block_reason") or "This document was already reviewed")
        mapping = json.loads(os.environ["TRUSTOPS_LEDGERSIGHT_TENANT_MAP"])[p.tenant_id]
        evidence = db().record(p.tenant_id, mapping["source_tenant"], doc, actor(p), body)
        return {"review": evidence["payload"], "evidence": evidence, "runtime_gate_enforced": source["runtime_gate_enforced"]}

    @router.get("/review-evidence")
    def evidence(p=Depends(principal)):
        decorated(p)
        scope = json.loads(os.environ["TRUSTOPS_LEDGERSIGHT_TENANT_MAP"])[p.tenant_id]
        return {"items": [r for r in db().listing(p.tenant_id) if r["payload"]["workspace_id"] in scope["workspaces"] and r["payload"]["source_tenant"] == scope["source_tenant"]]}

    @router.post("/runtime/authorize")
    def authorize(body: GateRequest, authorization: str | None = Header(default=None)):
        expected = os.environ.get("TRUSTOPS_DOCUMENT_GATE_TOKEN", "")
        supplied = (authorization or "").removeprefix("Bearer ")
        if not expected or not (authorization or "").startswith("Bearer ") or not hmac.compare_digest(hashlib.sha256(supplied.encode()).digest(), hashlib.sha256(expected.encode()).digest()):
            raise HTTPException(401, "Runtime service authentication required")
        tenant = os.environ.get("TRUSTOPS_DOCUMENT_GATE_TENANT", "")
        scope = json.loads(os.environ.get("TRUSTOPS_LEDGERSIGHT_TENANT_MAP", "{}")).get(tenant)
        if not scope or body.workspace_id not in scope["workspaces"]:
            raise HTTPException(403, "Runtime client scope denied")
        records = {r["payload"]["document_key"]: r for r in db().listing(tenant)}
        statuses = []
        for file in body.files:
            key = document_key(tenant, scope["source_tenant"], {**file.model_dump(), "workspace_id": body.workspace_id})
            row = records.get(key)
            if row:
                # Verify persisted decisions before granting authority.
                try:
                    key_object = db().signer().public_key()
                    key_object.verify(bytes.fromhex(row["signature"]), canonical(row["payload"]))
                except Exception:
                    raise HTTPException(503, "Decision evidence failed verification") from None
            statuses.append({**file.model_dump(), "status": row["payload"]["decision"] if row else "PENDING",
                             "reason": row["payload"]["reason"] if row else "Awaiting reviewer decision"})
        return db().sign({"schema": "trustops.document-gate.v1", "workspace_id": body.workspace_id, "action": body.action,
                          "nonce": body.nonce, "files": statuses, "allowed": all(r["status"] == "APPROVED" for r in statuses),
                          "expires_at": int(time.time()) + 30})

    return router
