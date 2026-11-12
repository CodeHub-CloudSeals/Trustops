"""LedgerSight runtime adapter: process only reviewed source-file fingerprints.

Install in the LedgerSight process before serving. This module is deployment
code; adding it to this checkout does not modify the running Cloud Run revision.
"""
import asyncio
import json
import os
import secrets
import time
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class GateDenied(Exception):
    pass


class DocumentGateClient:
    def __init__(self, url, token, public_key_pem, transport=None):
        origin = urlsplit(url)
        if origin.scheme != "https" or not origin.netloc or origin.username or origin.password or origin.query or origin.fragment:
            raise ValueError("A fixed HTTPS TrustOps gate endpoint is required")
        if not token:
            raise ValueError("Runtime service authentication is required")
        self.key = serialization.load_pem_public_key(public_key_pem.encode())
        if not isinstance(self.key, Ed25519PublicKey):
            raise ValueError("Pin the TrustOps Ed25519 review key")
        self.url = url
        self.client = httpx.Client(timeout=10, follow_redirects=False, transport=transport,
                                   headers={"Authorization": "Bearer " + token})

    def authorize(self, workspace_id, action, files):
        nonce = secrets.token_hex(24)
        request = {"workspace_id": workspace_id, "action": action, "files": files, "nonce": nonce}
        try:
            response = self.client.post(self.url, json=request)
            if response.status_code != 200 or len(response.content) > 100000:
                raise ValueError("gate unavailable")
            signed = response.json(); payload = signed["payload"]
            self.key.verify(bytes.fromhex(signed["signature"]), canonical(payload))
            actual = sorted((f["upload_id"], f["sha256"]) for f in payload["files"])
            expected = sorted((f["upload_id"], f["sha256"]) for f in files)
            if (payload.get("schema") != "trustops.document-gate.v1" or payload.get("workspace_id") != workspace_id
                    or payload.get("action") != action or payload.get("nonce") != nonce or actual != expected
                    or type(payload.get("expires_at")) is not int or not time.time() < payload["expires_at"] <= time.time() + 35):
                raise ValueError("gate response binding failed")
            if payload.get("allowed") is not True or any(f.get("status") != "APPROVED" for f in payload["files"]):
                rejected = next((f for f in payload["files"] if f.get("status") == "REJECTED"), None)
                if rejected:
                    raise GateDenied("DOCUMENT_REJECTED: " + str(rejected.get("reason") or "Open TrustOps Reviews for the rejection reason"))
                raise GateDenied("DOCUMENT_REVIEW_PENDING: Approve the document in TrustOps Reviews before processing")
        except GateDenied:
            raise
        except Exception:
            raise GateDenied("DOCUMENT_APPROVAL_UNVERIFIED: Processing blocked because TrustOps approval could not be verified") from None


def input_files(workspace):
    files = {}
    for batch in workspace.batches.values():
        ids = [batch.get("upload_id")]
        ids.extend(row.get("id") for row in batch.get("rows", []) if row.get("id") in workspace.uploads)
        matched = [workspace.uploads[uid] for uid in ids if uid in workspace.uploads]
        if not matched and batch.get("rows"):
            matched = [u for u in workspace.uploads.values() if u.get("sha256") == batch.get("sha256")]
        if batch.get("rows") and not matched:
            raise GateDenied("DOCUMENT_PROVENANCE_MISSING: Processing blocked")
        for upload in matched:
            if not upload.get("sha256"):
                raise GateDenied("DOCUMENT_FINGERPRINT_MISSING: Processing blocked")
            files[upload["id"]] = {"upload_id": upload["id"], "sha256": upload["sha256"]}
    if not files:
        raise GateDenied("NO_APPROVED_INPUT_DOCUMENTS: Processing blocked")
    return list(files.values())


def install_document_gate(app, service, denied, client):
    """Keep baseline policy authoritative and gate all three input-consumption paths."""
    originals = {name: getattr(service, name) for name in ("commit_mapping", "confirm_pdf", "run", "trust")}

    def check(workspace, action, files):
        try:
            client.authorize(workspace.id, action, files)
        except GateDenied as exc:
            raise denied(str(exc), policy_id="TRUSTOPS-DOCUMENT-APPROVAL") from None

    def mapping(user, wid, upload_id, mapping):
        w = service.gate(user, wid, "mapping.commit")
        upload = w.uploads.get(upload_id)
        if not upload:
            raise denied("DOCUMENT_NOT_FOUND")
        check(w, "mapping.commit", [{"upload_id": upload_id, "sha256": upload["sha256"]}])
        return originals["commit_mapping"](user, wid, upload_id, mapping)

    def document(user, wid, doc_id, fields, doc_type):
        w = service.gate(user, wid, "mapping.commit")
        upload = w.uploads.get(doc_id)
        if not upload:
            raise denied("DOCUMENT_NOT_FOUND")
        check(w, "document.confirm", [{"upload_id": doc_id, "sha256": upload["sha256"]}])
        return originals["confirm_pdf"](user, wid, doc_id, fields, doc_type)

    def run(user, wid):
        w = service.gate(user, wid, "run.create")
        try:
            files = input_files(w)
        except GateDenied as exc:
            raise denied(str(exc), policy_id="TRUSTOPS-DOCUMENT-APPROVAL") from None
        check(w, "run.compute", files)
        return originals["run"](user, wid)

    def trust():
        return {**originals["trust"](), "document_review_gate": {"enforced": True,
                "actions": ["mapping.commit", "document.confirm", "run.compute"], "fail_closed": True}}

    service.commit_mapping = mapping; service.confirm_pdf = document; service.run = run; service.trust = trust
    mutation_lock = asyncio.Lock()

    @app.middleware("http")
    async def serialize_mutations(request, call_next):
        # Prevent a source mapping/clear/reset racing between authorisation and use.
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            async with mutation_lock:
                return await call_next(request)
        return await call_next(request)


def configured_client():
    return DocumentGateClient(os.environ["TRUSTOPS_DOCUMENT_GATE_URL"], os.environ["TRUSTOPS_DOCUMENT_GATE_TOKEN"],
                              os.environ["TRUSTOPS_REVIEW_PUBLIC_KEY_PEM"])
