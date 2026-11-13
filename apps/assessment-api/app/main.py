"""TAAD assessment API (modular monolith). Implements taad_assessment_api_v1.yaml locally."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import queue
import re
import secrets
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal, Optional
from urllib.parse import urlparse

import reporting
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from question_engine import candidate_findings, eligible_questions, load_registry
from question_engine.branching import is_eligible

from . import application_evidence, llm, model_schemas, persist, scanner, studio, swaska, taad_agents, trustops_runtime, use_cases
from .evidence import inspect, make_store
from .ledgersight_connector import make_router as _ledgersight_router
from .governance_team import make_team_router
from .app_integrations import make_router as _integrations_router
from .decisions import make_router as _decisions_router
from .security import AUTH_MODE, AUTH_PROVIDER, CLOUDSEALS_ROLES, ENV, issue_token, verify_identity
from .store import Store

ROOT = Path(__file__).resolve().parents[3]
REG = load_registry(ROOT / "taad_question_control_registry_v1.0.0.json", ROOT / "taad_catalog_sha256.txt")
STORE = Store()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if ENV == "local" and AUTH_MODE == "dev" and os.environ.get("TAAD_SEED") == "1" and not STORE.users:
        from .seed import seed
        seed()
    if os.environ.get("TAAD_MODEL_STARTUP_CHECK") == "1":
        # Explicit self-host deployment gate: use synthetic text only; never publish or mutate customer material.
        if SWASKA_CLIENT is None:
            raise RuntimeError("Model startup check requires a configured provider")
        stage = 'json_connection'
        analysis_check = {}
        try:
            reply = json.loads(model_schemas.complete(SWASKA_CLIENT, 'Return exactly the JSON object {"ok":true}.',
                                                     "Synthetic server readiness check. No customer data.", 128, model_schemas.READY))
            if reply != {"ok": True}:
                raise ValueError("Invalid model readiness reply")
            if os.environ.get("TAAD_MODEL_DOCUMENT_CHECK") == "1":
                stage = 'document_inventory'
                result = use_cases.run_inventory(SWASKA_CLIENT, [{"evidence_id": "startup-synthetic", "filename": "synthetic-ai-register.txt",
                    "text": "The customer support chatbot answers account FAQs. Support owns the chatbot. It cannot change accounts."}])
                analysis_check = {'status': result.get('status'), 'accepted': len(result.get('items', [])), 'rejected': result.get('rejected')}
                if result.get("status") != "completed" or not result["items"]:
                    raise ValueError("Synthetic document analysis did not pass grounding checks")
        except Exception as exc:
            print(json.dumps({'event': 'MODEL_STARTUP_FAILED', 'stage': stage, 'error_type': type(exc).__name__,
                              'analysis_check': analysis_check}), flush=True)
            raise RuntimeError("Model startup verification failed; no customer data was used") from None
        print(f"MODEL_STARTUP_VERIFIED provider={llm.provider()} model={llm.configured_model_id()} "
              f"document_check={os.environ.get('TAAD_MODEL_DOCUMENT_CHECK') == '1'}", flush=True)
    yield


app = FastAPI(title="CloudSeals TAAD Diagnosis API", version="1.0.0", docs_url=None if ENV == "prod" else "/docs",
              redoc_url=None, openapi_url=None if ENV == "prod" else "/openapi.json", lifespan=lifespan)
DB_PATH = os.environ.get("TAAD_DB")
OBJECTS = make_store()
SWASKA_CLIENT = swaska.default_client()
INVITE_TTL = 7 * 24 * 3600
FINDING_STATUSES = ["Confirmed gap", "Potential gap", "No gap evidenced", "Not applicable"]
if persist.enabled():
    persist.load(STORE)
ALLOWED_MIME = {"application/pdf", "text/plain", "text/csv", "application/json",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
MAX_UPLOAD = 25 * 1024 * 1024


class Principal(BaseModel):
    sub: str
    tenant_id: Optional[str]
    roles: list[str]

    @property
    def is_staff(self) -> bool:
        return bool(set(self.roles) & CLOUDSEALS_ROLES)


def err(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message})


@app.middleware("http")
async def hardening(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    if request.url.path.startswith("/portal"):
        token_url = urlparse(os.environ.get("TAAD_PORTAL_TOKEN_URL", ""))
        cognito_origin = f" {token_url.scheme}://{token_url.netloc}" if AUTH_MODE == "oidc" and token_url.scheme == "https" and token_url.netloc else ""
        portal_csp = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                      f"connect-src 'self'{cognito_origin}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    else:
        portal_csp = "default-src 'none'; frame-ancestors 'none'"
    resp.headers.setdefault("Content-Security-Policy", portal_csp)
    if request.method not in ("GET", "HEAD", "OPTIONS") and persist.enabled() and resp.headers.get("X-Workflow-Stream") != "1":
        try:
            persist.save(STORE)
        except persist.PersistConflict as e:
            return JSONResponse(status_code=503, content={"code": "retry", "message": str(e)}, headers={"Retry-After": "1"})
    return resp


@app.exception_handler(HTTPException)
async def http_err(request: Request, exc: HTTPException):
    d = exc.detail if isinstance(exc.detail, dict) else {"code": "error", "message": str(exc.detail)}
    return JSONResponse(status_code=exc.status_code, content={**d, "trace_id": uuid.uuid4().hex})


def authenticated_identity(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise err(401, "unauthenticated", "Bearer token required")
    ident = verify_identity(authorization[7:])
    if not ident:
        raise err(401, "unauthenticated", "Invalid token")
    return ident


def authenticated_sub(ident: dict = Depends(authenticated_identity)) -> str:
    """Identity only (no membership required): used by invitation acceptance."""
    return ident["sub"]


# The environment owner holds every CloudSeals role.
OWNER_ROLES = ["cloudseals_admin", "cloudseals_assessor", "cloudseals_platform_ops", "cloudseals_reviewer"]


def maybe_bootstrap_first_admin(ident: dict) -> bool:
    """One-time first CloudSeals admin: the verified Google email named in TAAD_FIRST_ADMIN_EMAIL, dev environment only,
    only while no admin exists. Recorded in the audit log and the durable state; the setting is inert afterwards."""
    want = os.environ.get("TAAD_FIRST_ADMIN_EMAIL", "").strip().lower()
    if not (want and ENV == "dev" and AUTH_MODE == "oidc" and ident.get("email_verified") and ident.get("email") == want):
        return False
    with STORE.lock:
        if STORE.admin_bootstrap or any("cloudseals_admin" in u.get("roles", []) for u in STORE.users.values()):
            return False
        STORE.users[ident["sub"]] = {"tenant_id": None, "roles": list(OWNER_ROLES), "email": want}
        STORE.admin_bootstrap.update({"completed_at": time.time(), "sub": ident["sub"], "email": want})
        STORE.audit.append({"at": time.time(), "sub": ident["sub"], "tenant_id": None, "action": "admin.bootstrap",
                            "ref": "first_cloudseals_admin"})
    if persist.enabled():
        persist.save(STORE)
    return True


def maybe_activate_pending(ident: dict) -> bool:
    """An admin pre-registered this verified email; the first sign-in turns it into a membership (once)."""
    email = ident.get("email")
    if not (email and ident.get("email_verified")):
        return False
    with STORE.lock:
        inv = STORE.pending_users.pop(email, None)
        if not inv:
            return False
        STORE.users[ident["sub"]] = {"tenant_id": inv["tenant_id"], "roles": inv["roles"], "email": email,
                                     **{k: inv[k] for k in ("apps", "app_access") if k in inv}}
        STORE.audit.append({"at": time.time(), "sub": ident["sub"], "tenant_id": inv["tenant_id"], "action": "user.activated", "ref": email})
    if persist.enabled():
        persist.save(STORE)
    return True


def principal(ident: dict = Depends(authenticated_identity)) -> Principal:
    sub = ident["sub"]
    user = STORE.users.get(sub)
    if not user and (maybe_bootstrap_first_admin(ident) or maybe_activate_pending(ident)):
        user = STORE.users.get(sub)
    if not user:
        raise err(401, "unauthenticated", "Invalid token")
    if ident.get("email_verified") and ident.get("email") and user.get("email") != ident["email"]:
        user["email"] = ident["email"]    # kept for display; persisted with the next write
    return Principal(sub=sub, tenant_id=user.get("tenant_id"), roles=user["roles"])


ORG_TENANT = os.environ.get("TRUSTOPS_ORG_TENANT", "t-cloudseals")
ORG_NAME = os.environ.get("TRUSTOPS_ORG_NAME", "CloudSeals")


def console_principal(p: Principal = Depends(principal)) -> Principal:
    """Governance console identity. CloudSeals administrators without a customer workspace work in the
    CloudSeals organisation workspace as its administrators; everyone else keeps their own workspace."""
    if p.tenant_id is None and "cloudseals_admin" in p.roles:
        if ORG_TENANT not in STORE.tenants:
            STORE.tenants[ORG_TENANT] = {"tenant_id": ORG_TENANT, "name": ORG_NAME}
        return Principal(sub=p.sub, tenant_id=ORG_TENANT, roles=sorted(set(p.roles) | {"customer_admin"}))
    return p


def audit(p: Principal, action: str, ref: str) -> None:
    STORE.audit.append({"at": time.time(), "sub": p.sub, "tenant_id": p.tenant_id, "action": action, "ref": ref})


app.include_router(_ledgersight_router(principal, audit, identity=lambda p: STORE.users[p.sub].get("email") or p.sub))
_INTEGRATIONS = _integrations_router(console_principal, audit, identity=lambda p: STORE.users[p.sub].get("email") or p.sub, state=STORE)
app.include_router(_INTEGRATIONS)
app.include_router(_decisions_router(console_principal, _INTEGRATIONS.store.find_by_key, audit, identity=lambda p: STORE.users[p.sub].get("email") or p.sub, state=STORE,
                                    tenant_name=lambda t: (STORE.tenants.get(t) or {}).get("name") or t,
                                    integrations=_INTEGRATIONS.store, reviewers=lambda t: _reviewers(t)))
app.include_router(make_team_router(console_principal, STORE, lambda: persist.save(STORE) if persist.enabled() else None,
                                   list_apps=lambda t: _INTEGRATIONS.store.list(t) if t else []))


def _reviewers(tenant: str) -> list[dict]:
    """People who can approve in this workspace (Admins and Approvers), for assigning reviews."""
    out = {}
    with STORE.lock:
        for sub, u in STORE.users.items():
            roles = set(u.get("roles", []))
            staff = u.get("tenant_id") is None and "cloudseals_admin" in roles and tenant == ORG_TENANT
            if (u.get("tenant_id") == tenant and roles & {"customer_admin", "customer_controller"}) or staff:
                email = (u.get("email") or sub).lower()
                if email:
                    out[email] = {"email": email, "name": u.get("name") or email.split("@")[0],
                                  "role": "Admin" if staff or "customer_admin" in roles else "Approver", "signed_in": True}
        for email, u in STORE.pending_users.items():
            roles = set(u.get("roles", []))
            if u.get("tenant_id") == tenant and roles & {"customer_admin", "customer_controller"} and email.lower() not in out:
                out[email.lower()] = {"email": email.lower(), "name": email.split("@")[0],
                                      "role": "Admin" if "customer_admin" in roles else "Approver", "signed_in": False}
    return sorted(out.values(), key=lambda r: (r["role"] != "Admin", r["email"]))


@app.get("/v1/app-access")
def app_access(email: str = Query(..., max_length=200), x_trustops_key: Optional[str] = Header(default=None)):
    """For a connected application: what access does this person have in it? Managed in TrustOps Team & access."""
    found = _INTEGRATIONS.store.find_by_key(x_trustops_key or "")
    if not found:
        raise err(401, "invalid_key", "A valid X-TrustOps-Key is required")
    tenant, integ = found
    email = email.strip().lower()
    with STORE.lock:
        rec = next((u for sub, u in STORE.users.items() if u.get("tenant_id") == tenant and (u.get("email") or sub).lower() == email), None)
        if rec is None and tenant == ORG_TENANT:
            # CloudSeals administrators work in the CloudSeals workspace as its administrators (see console_principal).
            staff = next((u for u in STORE.users.values() if u.get("tenant_id") is None and "cloudseals_admin" in u.get("roles", [])
                          and (u.get("email") or "").lower() == email), None)
            rec = {**staff, "roles": sorted(set(staff.get("roles", [])) | {"customer_admin"})} if staff else None
        if rec is None:
            pend = STORE.pending_users.get(email)
            rec = pend if pend and pend.get("tenant_id") == tenant else None
    if rec is not None and rec.get("apps") is not None and integ["id"] not in rec["apps"]:
        return {"email": email, "application": integ["name"], "role": None}     # not given this application
    explicit = (rec or {}).get("app_access", {}).get(integ["id"])
    roles = set((rec or {}).get("roles", []))
    # Application access follows the TrustOps role: admins and approvers review, preparers prepare, viewers have none.
    derived = ("reviewer" if roles & {"customer_admin", "customer_controller"} else
               "preparer" if "customer_app_user" in roles else None)
    return {"email": email, "application": integ["name"], "role": explicit or derived}


def publish_event(ev: dict) -> None:
    """Publish to EventBridge when configured; the local list remains the audit copy. Failures never block the API."""
    bus = os.environ.get("TAAD_EVENT_BUS")
    if not bus:
        return
    try:
        import boto3
        boto3.client("events").put_events(Entries=[{"EventBusName": bus, "Source": "taad", "DetailType": ev["type"],
                                                    "Detail": json.dumps({k: v for k, v in ev.items() if k != "payload"} | {"payload_ref": ev["event_id"]})}])
    except Exception:
        ev["publish_failed"] = True


def emit(event_type: str, tenant_id: str, payload: dict) -> dict:
    ev = {"event_id": str(uuid.uuid4()), "type": event_type, "tenant_id": tenant_id,
          "trace_id": uuid.uuid4().hex, "schema_version": "1.0.0", "source": "taad",
          "occurred_at": time.time(), "payload": payload,
          "payload_digest": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}
    STORE.events.append(ev)
    publish_event(ev)
    return ev


def get_assessment(p: Principal, aid: str) -> dict[str, Any]:
    """Cross-tenant and unknown IDs are indistinguishable (404) so existence never leaks."""
    a = STORE.assessments.get(aid)
    if not a or (not p.is_staff and a["tenant_id"] != p.tenant_id):
        raise err(404, "not_found", "Assessment not found")
    return a


def require(p: Principal, *roles: str) -> None:
    if not set(p.roles) & set(roles):
        raise err(403, "forbidden", "Role not permitted for this operation")


def idempotent(p: Principal, key: Optional[str], op: str, fn):
    if not key or len(key) > 128:
        raise err(400, "idempotency_key_required", "Idempotency-Key header required (max 128 chars)")
    k = (p.sub, op, key)
    with STORE.lock:
        if k in STORE.idempotency:
            return STORE.idempotency[k]
        res = fn()
        STORE.idempotency[k] = res
        return res


# ---------- models ----------
class RegistrationRequest(BaseModel):
    organisation_name: str = Field(max_length=200)
    work_email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    industry: str
    jurisdiction: list[str]
    engagement_reference: str


class AssessmentCreate(BaseModel):
    ai_system_name: str = Field(min_length=1, max_length=200)
    industry: str
    questionnaire_version: str


class ScopedAnswer(BaseModel):
    scope_id: str
    value: Any
    answer_status: Literal["answered", "unknown", "not_applicable", "not_requested"]
    comment: str = Field(default="", max_length=5000)
    evidence_refs: list[str] = []


class SwaskaTurn(BaseModel):
    scope_id: str
    user_message: str = Field(max_length=10000)
    parent_question_id: Optional[str] = None


class EvidenceUploadRequest(BaseModel):
    filename: str
    content_type: str
    file_size_bytes: int = Field(ge=1)
    claimed_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class ReviewDecision(BaseModel):
    decision: Literal["approve", "request_clarification", "reject"]
    reviewer_reason: str = Field(min_length=1)


class POCBlueprintRequest(BaseModel):
    report_id: str
    workflow_pack_id: str
    customer_security_signoff_ref: Optional[str] = None
    cloudseals_architect_signoff_ref: Optional[str] = None
    success_criteria: list[str] = Field(default_factory=list)


# ---------- helpers ----------
def merged_answers(aid: str, scope_id: str) -> dict[str, Any]:
    """Org-scope answers overlaid by the requested scope's answers (branch rules reference Q-BASE)."""
    out: dict[str, Any] = {}
    for sc in ("org", scope_id):
        for (a, s, qid), ans in STORE.answers.items():
            if a == aid and s == sc and ans["answer_status"] == "answered":
                out[qid] = ans["value"]
            elif a == aid and s == sc and ans["answer_status"] == "unknown":
                out[qid] = "Unknown"
    return out


def all_answers(aid: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for (a, _s, qid), ans in sorted(STORE.answers.items()):
        if a != aid:
            continue
        if ans["answer_status"] == "answered":
            out.setdefault(qid, ans["value"])
        elif ans["answer_status"] == "unknown":
            out.setdefault(qid, "Unknown")
    return out


def validate_value(q: dict, ans: ScopedAnswer) -> None:
    if ans.answer_status != "answered":
        return
    t, v = q["response_type"], ans.value
    if t == "select_one":
        if v not in REG.option_sets[q["option_set"]]:
            raise err(422, "invalid_option", f"{v!r} not valid for {q['question_id']}")
    elif t == "select_multi":
        if not isinstance(v, list) or not set(v) <= set(REG.option_sets[q["option_set"]]):
            raise err(422, "invalid_option", "invalid multi-select value")
    elif t == "number":
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise err(422, "invalid_number", "number expected")
    elif t in ("text", "long_text"):
        if not isinstance(v, str) or len(v) > 10000:
            raise err(422, "invalid_text", "text expected (max 10000 chars)")
        if reporting.clean(v) != v:
            raise err(422, "invalid_characters", "Control or bidirectional-override characters are not allowed")


# ---------- routes ----------
@app.get("/health")
def health():
    return {"status": "ok", "registry_version": REG.version, "registry_sha256": REG.sha256,
            "question_count": len(REG.questions)}


@app.post("/v1/registration-requests", status_code=202)
def register(req: RegistrationRequest, request: Request):
    now = time.time()
    keys = [f"ip:{request.client.host if request.client else '?'}", f"dom:{req.work_email.split('@')[1].lower()}"]
    for k in keys:
        STORE.rate[k] = [t for t in STORE.rate.get(k, []) if now - t < 3600]
        if len(STORE.rate[k]) >= 5:
            raise err(429, "rate_limited", "Too many registration requests; try again later")
        STORE.rate[k].append(now)
    eng = STORE.engagements.get(req.engagement_reference)
    STORE.registrations.append({**req.model_dump(), "registration_id": str(uuid.uuid4()), "at": now,
                                "status": "pending_approval",
                                "engagement_verified": bool(eng) and eng.get("status") == "approved"})
    return {"status": "pending_verification"}   # identical response whether or not the engagement exists


@app.post("/v1/assessments", status_code=201)
def create_assessment(body: AssessmentCreate, p: Principal = Depends(principal),
                      idempotency_key: Optional[str] = Header(default=None)):
    require(p, "customer_admin", "customer_architect")
    if body.questionnaire_version != REG.version:
        raise err(422, "unknown_questionnaire_version", f"Published version is {REG.version}")

    def create():
        aid = str(uuid.uuid4())
        a = {"assessment_id": aid, "tenant_id": p.tenant_id, "ai_system_name": body.ai_system_name,
             "industry": body.industry, "questionnaire_version": REG.version,
             "registry_sha256": REG.sha256, "status": "In progress", "created_by": p.sub,
             "created_at": time.time(), "snapshot": None}
        STORE.assessments[aid] = a
        audit(p, "assessment.create", aid)
        return a
    return idempotent(p, idempotency_key, "create_assessment", create)


@app.get("/v1/assessments")
def list_assessments(p: Principal = Depends(principal)):
    items = [a for a in STORE.assessments.values() if p.is_staff or a["tenant_id"] == p.tenant_id]
    return {"items": items}


@app.get("/v1/assessments/{aid}/questions")
def questions(aid: str, scope_id: str, scope_type: str = "org", p: Principal = Depends(principal)):
    a = get_assessment(p, aid)
    qs = eligible_questions(REG, scope_type, merged_answers(aid, scope_id))
    return {"questionnaire_version": a["questionnaire_version"], "scope_id": scope_id,
            "questions": [{k: q[k] for k in ("question_id", "question", "section", "response_type", "required",
                                              "option_set", "guidance", "evidence_request", "control_id")} |
                          {"options": REG.option_sets.get(q["option_set"], [])} for q in qs]}


@app.put("/v1/assessments/{aid}/answers/{qid}")
def put_answer(aid: str, qid: str, body: ScopedAnswer, if_match: Optional[str] = Header(default=None),
               p: Principal = Depends(principal)):
    a = get_assessment(p, aid)
    require(p, "customer_admin", "customer_architect", "customer_risk", "customer_contributor",
            "cloudseals_assessor", "cloudseals_admin")
    if a["status"] != "In progress":
        raise err(409, "frozen", "Assessment is submitted; answers are immutable")
    q = REG.questions.get(qid)
    if not q:
        raise err(422, "unknown_question", "Question ID not in pinned questionnaire")
    # eligibility is evaluated against the scope's merged answers
    if not is_eligible(REG, qid, merged_answers(aid, body.scope_id)):
        raise err(422, "question_not_eligible", "Question not applicable under current branching")
    validate_value(q, body)
    if set(p.roles) == {"customer_contributor"}:
        if q["section"] not in STORE.assignments.get(aid, {}).get(p.sub, []):
            raise err(403, "not_assigned", "Section not assigned to this contributor")
    for ref in body.evidence_refs:
        ev = STORE.evidence.get(ref)
        if not ev or ev["assessment_id"] != aid or ev["state"] != "clean":
            raise err(422, "invalid_evidence_ref", "Evidence must exist for this assessment and have passed quarantine scanning")
    key = (aid, body.scope_id, qid)
    with STORE.lock:
        cur = STORE.answers.get(key)
        cur_etag = cur["etag"] if cur else "0"
        if if_match is None or if_match.strip('"') != cur_etag:
            raise err(409, "etag_mismatch", f"Concurrent modification; current ETag is {cur_etag}")
        rev = (cur["revision"] if cur else 0) + 1
        rec = {**body.model_dump(), "question_id": qid, "revision": rev, "etag": str(rev),
               "updated_by": p.sub, "updated_at": time.time()}
        STORE.answers[key] = rec
        STORE.revisions.append({"assessment_id": aid, **rec})
        audit(p, "answer.put", f"{aid}/{qid}")
    return JSONResponse(rec, headers={"ETag": f'"{rec["etag"]}"'})


@app.post("/v1/assessments/{aid}/swaska/turns")
def swaska_turn(aid: str, body: SwaskaTurn, p: Principal = Depends(principal)):
    """Read-only interviewer: allowlisted tools, schema-validated output, deterministic fallback."""
    a = get_assessment(p, aid)
    qid = body.parent_question_id
    if not qid or qid not in REG.questions:
        raise err(422, "unknown_question", "Swaska may only reference existing question IDs")
    ans = merged_answers(aid, body.scope_id)
    tools = {
        "get_assessment_context": lambda: {"assessment_id": aid, "questionnaire_version": a["questionnaire_version"],
                                            "industry": a["industry"]},
        "get_next_eligible_questions": lambda: [q["question_id"] for q in eligible_questions(REG, "org", ans)][:5],
        "read_answer_for_current_scope": lambda question_id: ans.get(question_id),
        "get_evidence_metadata": lambda: [{"evidence_id": e["evidence_id"], "state": e["state"],
                                           "injection_flagged": e.get("injection_flagged", False)}
                                          for e in STORE.evidence.values() if e["assessment_id"] == aid],
        "suggest_clarification": lambda **kw: kw, "propose_evidence_request": lambda **kw: kw,
    }
    return swaska.run_turn(SWASKA_CLIENT, swaska.ToolBox(tools), REG.questions[qid], body.user_message, set(REG.questions))


@app.post("/v1/assessments/{aid}/evidence/upload-url", status_code=201)
def upload_url(aid: str, body: EvidenceUploadRequest, p: Principal = Depends(principal)):
    a = get_assessment(p, aid)
    if body.content_type not in ALLOWED_MIME:
        raise err(422, "mime_not_allowed", "Content type not permitted")
    if body.file_size_bytes > MAX_UPLOAD:
        raise err(422, "too_large", "File exceeds size limit")
    eid = str(uuid.uuid4())
    # Opaque key: the client filename is metadata only and never used in the object path.
    STORE.evidence[eid] = {"evidence_id": eid, "assessment_id": aid, "tenant_id": a["tenant_id"],
                           "filename": body.filename, "content_type": body.content_type, "size": body.file_size_bytes,
                           "sha256": body.claimed_sha256.lower(), "state": "awaiting_upload", "uploaded_by": p.sub}
    return {"evidence_id": eid, "state": "awaiting_upload",
            "upload_url": f"/v1/assessments/{aid}/evidence/{eid}/content", "expires_in_seconds": 300,
            "note": "Content is quarantined and scanned before it can be cited as evidence."}


@app.put("/v1/assessments/{aid}/evidence/{eid}/content")
async def upload_content(aid: str, eid: str, request: Request, p: Principal = Depends(principal)):
    """Dev stand-in for a presigned S3 PUT into the quarantine bucket + malware scan."""
    get_assessment(p, aid)
    ev = STORE.evidence.get(eid)
    if not ev or ev["assessment_id"] != aid:
        raise err(404, "not_found", "Evidence not found")
    if ev["state"] != "awaiting_upload":
        raise err(409, "conflict", "Content already uploaded")
    declared = ev["size"]
    data = b""
    async for chunk in request.stream():
        data += chunk
        if len(data) > min(declared, MAX_UPLOAD):
            break
    verdict = inspect(ev["content_type"], data, ev["sha256"], declared)
    av = scanner.from_env()
    if verdict["state"] == "clean" and av is not None:       # mandatory when configured: no verdict means no evidence
        try:
            is_clean, detail = av.scan(data)
        except scanner.ScannerError:
            verdict = {**verdict, "state": "rejected", "reason": "malware_scanner_unavailable"}
        else:
            if not is_clean:
                verdict = {**verdict, "state": "infected", "reason": f"malware_detected: {detail}"[:120]}
    ev.update(state=verdict["state"], reason=verdict["reason"], injection_flagged=verdict["injection_flagged"])
    if verdict["state"] == "clean":
        if hasattr(OBJECTS, "promote"):
            OBJECTS.put(ev["tenant_id"], "quarantine", eid, data)
            # Local byte checks are a prefilter. In AWS, only GuardDuty's explicit clean
            # result can promote an object into the citable evidence bucket.
            ev.update(state="scanning", reason="guardduty_scan_pending", scan_status=None)
            refresh_guardduty_scan(ev)
        else:
            OBJECTS.put(ev["tenant_id"], "evidence", eid, data)
    audit(p, f"evidence.{verdict['state']}", eid)
    return {"evidence_id": eid, "state": ev["state"], "reason": ev["reason"], "injection_flagged": ev["injection_flagged"]}


def refresh_guardduty_scan(ev: dict) -> None:
    """Fail closed: only the documented GuardDuty clean tag makes AWS evidence citable."""
    if ev.get("state") != "scanning" or not hasattr(OBJECTS, "scan_status"):
        return
    status = OBJECTS.scan_status(ev["tenant_id"], ev["evidence_id"])
    ev["scan_status"] = status
    if status is None:
        ev["reason"] = "guardduty_scan_pending"
    elif status == "NO_THREATS_FOUND":
        OBJECTS.promote(ev["tenant_id"], ev["evidence_id"])
        ev.update(state="clean", reason="", scanned_by="guardduty")
    elif status == "THREATS_FOUND":
        ev.update(state="infected", reason="guardduty_threat_detected", scanned_by="guardduty")
    elif status in {"UNSUPPORTED", "ACCESS_DENIED", "FAILED"}:
        ev.update(state="rejected", reason=f"guardduty_{status.lower()}", scanned_by="guardduty")


@app.get("/v1/assessments/{aid}/evidence")
def list_evidence(aid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    if hasattr(OBJECTS, "scan_status"):
        for ev in STORE.evidence.values():
            if ev["assessment_id"] == aid:
                refresh_guardduty_scan(ev)
    return {"items": [{k: e.get(k) for k in ("evidence_id", "filename", "content_type", "state", "reason", "injection_flagged", "size")}
                      for e in STORE.evidence.values() if e["assessment_id"] == aid]}


@app.post("/v1/assessments/{aid}/submit", status_code=202)
def submit(aid: str, p: Principal = Depends(principal), idempotency_key: Optional[str] = Header(default=None)):
    a = get_assessment(p, aid)
    require(p, "customer_admin", "customer_architect")

    def do():
        if a["status"] != "In progress":
            raise err(409, "conflict", "Already submitted")
        ans = all_answers(aid)
        missing = [q["question_id"] for q in REG.questions.values()
                   if q["required"] == "yes" and q["enabled"] and q["scope"] == "org" and q["question_id"] not in ans]
        if missing:
            raise err(409, "missing_mandatory_answers", f"Missing: {', '.join(missing[:20])}")
        manifest = {"assessment_id": aid, "questionnaire_version": a["questionnaire_version"],
                    "answers": {f"{s}/{q}": v["value"] for (x, s, q), v in sorted(STORE.answers.items()) if x == aid}}
        digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, default=str).encode()).hexdigest()
        a["status"] = "Submitted"
        a["snapshot"] = {"snapshot_id": str(uuid.uuid4()), "answer_manifest_digest": digest}
        emit("taad.assessment.submitted.v1", a["tenant_id"], {"assessment_id": aid, **a["snapshot"],
                                                              "questionnaire_version": a["questionnaire_version"]})
        run_diagnosis(a)
        audit(p, "assessment.submit", aid)
        return {"status": "Submitted", **a["snapshot"]}
    return idempotent(p, idempotency_key, f"submit:{aid}", do)


def run_diagnosis(a: dict) -> None:
    aid = a["assessment_id"]
    ev: dict[str, list[str]] = {}
    for (x, _s, qid), ans in STORE.answers.items():
        if x == aid and ans["evidence_refs"]:
            ev.setdefault(qid, []).extend(ans["evidence_refs"])
    res = candidate_findings(REG, all_answers(aid), ev)
    STORE.findings[aid] = res["findings"]
    STORE.not_assessed[aid] = res["not_assessed"]
    rid = str(uuid.uuid4())
    STORE.reports[rid] = {
        "report_id": rid, "assessment_id": aid, "tenant_id": a["tenant_id"], "status": "draft",
        "visibility": "staff_only", "version": 1, "provenance": {
            "questionnaire_version": a["questionnaire_version"], "registry_sha256": a["registry_sha256"],
            "rule_versions": {r["rule_id"]: r["rule_version"] for r in REG.risk_rules},
            "answer_manifest_digest": a["snapshot"]["answer_manifest_digest"],
            "regulatory_content_status": REG.raw["status"]},
        "sections": [{"id": x["id"], "title": x["title"]} for x in REG.report_sections], "finding_count": len(res["findings"]),
        "not_assessed": res["not_assessed"],
        "disclaimer": "Candidate findings for human review. Not a legal determination of regulatory applicability."}
    emit("taad.diagnosis.draft_ready.v1", a["tenant_id"], {"assessment_id": aid, "report_id": rid})


@app.get("/v1/assessments/{aid}/findings")
def findings(aid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    items = STORE.findings.get(aid, [])
    published = any(r["assessment_id"] == aid and r["status"] == "published" for r in STORE.reports.values())
    if not p.is_staff and not published:
        return {"items": [], "note": "Findings are visible after reviewer approval"}
    return {"items": items}


@app.get("/v1/report-library")
def report_library(assessment_id: Optional[str] = None, p: Principal = Depends(principal)):
    """Customer-safe metadata for both published questionnaire reports and released document diagnostics."""
    if assessment_id:
        get_assessment(p, assessment_id)
    items = []
    with STORE.lock:
        visible = {aid: a for aid, a in STORE.assessments.items()
                   if (p.is_staff or a["tenant_id"] == p.tenant_id) and (not assessment_id or aid == assessment_id)}
        for r in STORE.reports.values():
            aid = r["assessment_id"]
            if aid not in visible or r["status"] != "published":
                continue
            a = visible[aid]
            items.append({"kind": "questionnaire", "assessment_id": aid, "ai_system_name": a["ai_system_name"], "industry": a["industry"],
                          "report_id": r["report_id"], "version": r["version"], "status": "published",
                          "download_urls": {f: f"/v1/assessments/{aid}/reports/{r['report_id']}/download?format={f}" for f in ("pdf", "docx")}})
        for aid, a in visible.items():
            for r in STORE.inventory.get(aid, {}).get("published_diagnostics", []):
                items.append({"kind": "document_diagnostic", "assessment_id": aid, "ai_system_name": r["system_name"], "industry": a["industry"],
                              "report_id": r["report_id"], "version": r["version"], "status": "published", "published_at": r["published_at"],
                              "download_urls": {"html": f"/v1/assessments/{aid}/diagnostic-report?report_id={r['report_id']}"}})
        for aid, a in visible.items():
            for run in STORE.inventory.get(aid, {}).get("technical_runs", {}).values():
                for release in run.get("releases", []):
                    items.append({"kind": "application_evidence", "assessment_id": aid, "ai_system_name": a["ai_system_name"],
                                  "industry": a["industry"], "report_id": release["report_id"], "version": release["version"],
                                  "status": "published", "published_at": release["published_at"],
                                  "download_urls": {"html": f"/v1/assessments/{aid}/application-evidence/{run['run_id']}/report"}})
    items.sort(key=lambda r: (r.get("published_at", 0), r["version"], r["report_id"]), reverse=True)
    return {"items": items, "total": len(items)}


@app.get("/v1/assessments/{aid}/reports")
def reports(aid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    items = [r for r in STORE.reports.values() if r["assessment_id"] == aid and (p.is_staff or r["status"] == "published")]
    return {"items": items}


@app.post("/v1/assessments/{aid}/reviews/{rid}/decision")
def review(aid: str, rid: str, body: ReviewDecision, p: Principal = Depends(principal),
           idempotency_key: Optional[str] = Header(default=None)):
    get_assessment(p, aid)
    require(p, "cloudseals_reviewer")
    r = STORE.reports.get(rid)
    if not r or r["assessment_id"] != aid:
        raise err(404, "not_found", "Report not found")

    def do():
        if r["status"] == "published":
            raise err(409, "conflict", "Already published")
        outcomes = {"approve": "published", "request_clarification": "clarification_requested", "reject": "rejected"}
        r["status"] = outcomes[body.decision]
        r["review"] = {"by": p.sub, "decision": body.decision, "reason": body.reviewer_reason}
        if body.decision == "approve":
            r["visibility"] = "customer"
            r["findings_snapshot"] = json.loads(json.dumps(STORE.findings.get(aid, [])))
            r["published_digest"] = render_model(STORE.assessments[aid], r)["content_digest"]
            emit("taad.diagnosis.report_published.v1", r["tenant_id"], {"assessment_id": aid, "report_id": rid})
        audit(p, f"review.{body.decision}", rid)
        return {"report_id": rid, "status": r["status"]}
    return idempotent(p, idempotency_key, f"review:{rid}", do)


REQUIRED_BLUEPRINT_FIELDS = json.loads((ROOT / "taad_integration_contracts_v1.json").read_text())["poc_blueprint_required_fields"]


def build_blueprint(a: dict, r: dict, body: "POCBlueprintRequest", bid: str) -> dict:
    """Deterministic DRAFT objects derived from approved findings and answers. Nothing here can execute or hold credentials."""
    aid = a["assessment_id"]
    ans = all_answers(aid)
    findings = r["findings_snapshot"]
    by_dom = lambda *ds: sorted(q for q in ans if q in REG.questions and q.split("-")[1] in ds)  # noqa: E731
    scopes = sorted({s for (x, s, q), v in STORE.answers.items() if x == aid and s != "org"})
    bp = {
        "blueprint_id": bid, "tenant_id": a["tenant_id"], "assessment_id": aid, "report_id": body.report_id,
        "finding_refs": [f["rule_id"] for f in findings],
        "system_inventory_refs": by_dom("AIA", "ENT", "AGT"),
        "connector_drafts": [{"scope": s, "mode": "READ_ONLY", "state": "DRAFT", "credentials": None} for s in scopes],
        "agent_manifests_draft": [{"scope": s, "state": "DRAFT", "approved_capabilities": ["READ", "CLASSIFY", "RECOMMEND"],
                                   "prohibited_capabilities": ["PREPARE_WRITE", "APPROVE", "EXECUTE"]} for s in scopes],
        "policy_candidates_draft": [{"from_rule": f["rule_id"], "control_ids": f["control_ids"], "proposal": f["recommendation"],
                                     "state": "CANDIDATE_REQUIRES_REVIEW"} for f in findings],
        "authority_matrix_draft": [{"action": act, "default": "DENY", "requires_human_approval": act in ("PREPARE_WRITE", "APPROVE", "EXECUTE")}
                                   for act in REG.option_sets["ACTION"]],
        "approval_matrix_draft": [{"from_rule": f["rule_id"], "approval": "HUMAN_REQUIRED"} for f in findings
                                  if {c.split("-")[1] for c in f["control_ids"]} & {"HIT", "POL", "IAM"}],
        "evidence_profile_draft": sorted({REG.questions[q]["evidence_request"] for q in ans if q in REG.questions
                                          and REG.questions[q]["evidence_request"]}),
        "shadow_roi_baseline_ref": {"answers": by_dom("BUS", "ECO"), "state": "BASELINE_TO_BE_MEASURED_IN_SHADOW"},
        "success_criteria": body.success_criteria,
        "customer_security_signoff": body.customer_security_signoff_ref,
        "cloudseals_architect_signoff": body.cloudseals_architect_signoff_ref,
        "workflow_pack_id": body.workflow_pack_id, "state": "DRAFT",
        "runtime_activation": "BLOCKED_PENDING_SEPARATE_APPROVAL", "credentials_provisioned": False, "external_writes_enabled": False,
        "provenance": {"questionnaire_version": a["questionnaire_version"], "registry_sha256": a["registry_sha256"],
                       "report_digest": r["published_digest"]}}
    bp["customer_security_signoff"] = body.customer_security_signoff_ref
    bp["cloudseals_architect_signoff"] = body.cloudseals_architect_signoff_ref
    missing = [f for f in REQUIRED_BLUEPRINT_FIELDS if f not in bp and f.replace("_ref", "") not in bp
               and not any(k.startswith(f.replace("_ref", "")) for k in bp)]
    if missing:
        raise err(500, "blueprint_contract_violation", f"Missing contract fields: {missing}")
    bp["blueprint_digest"] = hashlib.sha256(json.dumps(bp, sort_keys=True, default=str).encode()).hexdigest()
    return bp


@app.post("/v1/assessments/{aid}/poc-blueprints", status_code=201)
def poc_blueprint(aid: str, body: POCBlueprintRequest, p: Principal = Depends(principal),
                  idempotency_key: Optional[str] = Header(default=None)):
    a = get_assessment(p, aid)
    require(p, "cloudseals_admin", "cloudseals_assessor")
    r = STORE.reports.get(body.report_id)
    if not r or r["assessment_id"] != aid or r["status"] != "published":
        raise err(409, "report_not_approved", "Blueprint requires a published (reviewer-approved) report")
    if not (body.customer_security_signoff_ref and body.cloudseals_architect_signoff_ref):
        raise err(409, "signoffs_required", "Customer security and CloudSeals architect sign-offs are both required")

    if not body.success_criteria:
        raise err(422, "success_criteria_required", "At least one measurable success criterion is required")

    def do():
        bid = str(uuid.uuid4())
        bp = build_blueprint(a, r, body, bid)
        STORE.blueprints[bid] = bp
        emit("taad.poc.blueprint_approved.v1", a["tenant_id"], {"blueprint_id": bid, "assessment_id": aid,
                                                                "blueprint_digest": bp["blueprint_digest"]})
        audit(p, "poc.blueprint", bid)
        return bp
    return idempotent(p, idempotency_key, f"poc:{aid}:{body.report_id}", do)


# ---------- advisory TAAD / TrustOps agents (read-only, nothing persisted) ----------
class ExtractionRequest(BaseModel):
    evidence_id: str


AGENT_CALLS_PER_MINUTE = int(os.environ.get("TAAD_AGENT_CALLS_PER_MINUTE", "20"))


def agent_throttle(p: Principal, agent_id: str) -> None:
    """Per-user sliding-window limit so advisory (model-backed) agents cannot be used to burn model budget."""
    now = time.time()
    with STORE.lock:
        k = f"agent:{p.sub}"
        STORE.rate[k] = [t for t in STORE.rate.get(k, []) if now - t < 60]
        if len(STORE.rate[k]) >= AGENT_CALLS_PER_MINUTE:
            raise err(429, "rate_limited", "Too many agent requests; try again in a minute")
        STORE.rate[k].append(now)


STAFF_REVIEW = ("cloudseals_admin", "cloudseals_assessor", "cloudseals_reviewer")


@app.get("/v1/agents")
def agent_registry(p: Principal = Depends(principal)):
    items = [{k: v for k, v in a.items() if k != "behavior_policy"} for a in taad_agents.AGENTS.values()]
    model_ready = SWASKA_CLIENT is not None
    diagnostic_ids = {taad_agents.INVENTORY, taad_agents.GAP, taad_agents.MATURITY,
                      taad_agents.ROADMAP, taad_agents.REPORT, taad_agents.OVERLAY}
    catalog = [{"agent_id": swaska.MANIFEST["agent_id"], "group": "assessment", "name": "Assessment interviewer",
                "purpose": swaska.MANIFEST["purpose"], "availability": "AI configured" if model_ready else "Guided question help",
                "authority": "Explains questions and requests evidence; does not save answers or approve reports."}]
    names = {taad_agents.INVENTORY: "AI inventory", taad_agents.GAP: "Gap analysis", taad_agents.MATURITY: "Maturity assessment",
             taad_agents.ROADMAP: "Remediation roadmap", taad_agents.REPORT: "Report narrative", taad_agents.OVERLAY: "Architecture review",
             taad_agents.EXTRACTION: "Evidence answers", taad_agents.FINDINGS: "Findings summary",
             taad_agents.DRAFTER: "POC scope assistant", taad_agents.APPROVAL: "Approval summary"}
    for agent in items:
        diagnostic = agent['agent_id'] in diagnostic_ids
        catalog.append({"agent_id": agent['agent_id'], "group": "assessment" if diagnostic else "assistant",
                        "name": names[agent['agent_id']], "purpose": agent['purpose'],
                        "availability": "AI configured" if model_ready else "Needs AI connection" if diagnostic else "Rule-based assistance",
                        "authority": "Draft for reviewer validation; cannot publish or approve." if diagnostic else
                                     "Suggestions only; a person checks and applies the result."})
    for agent in trustops_runtime.AGENT_MANIFESTS:
        catalog.append({"agent_id": agent['id'], "group": "payment", "name": agent['id'].split('.')[-1].replace('_', ' ').title(),
                        "purpose": agent['purpose'], "availability": ("AI + policy rules" if llm.provider() else "Policy rules")
                        if runtime_enabled() else "Workflow unavailable", "authority": " · ".join(agent['authority'])})
    return {"items": items, "catalog": catalog, "total": len(catalog),
            "evidence_workflow": {"name": "Application evidence", "available": True,
                                  "description": "Browser capture → evidence checks → reviewer validation → published report. "
                                                 "Metadata checks do not prove AI safety."},
            "behavior_policy": taad_agents.CATALOG["common_behavior_policy"]}


@app.post("/v1/assessments/{aid}/agents/extraction")
def agent_extraction(aid: str, body: ExtractionRequest, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    agent_throttle(p, taad_agents.EXTRACTION)
    ev = STORE.evidence.get(body.evidence_id)
    if not ev or ev["assessment_id"] != aid or ev["state"] != "clean":
        raise err(422, "invalid_evidence_ref", "Evidence must exist for this assessment and be clean")
    if ev["content_type"] not in ("text/plain", "text/csv", "application/json"):
        raise err(422, "unsupported_evidence_type", "Extraction supports text, CSV and JSON evidence")

    def text(evidence_id: str) -> str:
        return OBJECTS.get(ev["tenant_id"], "evidence", evidence_id).decode("utf-8", "replace")[:200000]
    tools = taad_agents.Tools(taad_agents.EXTRACTION, {"get_evidence_text": text,
                                                       "list_published_questions": lambda: sorted(REG.questions)})
    audit(p, "agent.extraction", body.evidence_id)
    return taad_agents.extract_candidates(SWASKA_CLIENT, tools, body.evidence_id, set(REG.questions))


@app.post("/v1/assessments/{aid}/agents/findings-summary")
def agent_findings_summary(aid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, *STAFF_REVIEW)
    agent_throttle(p, taad_agents.FINDINGS)
    tools = taad_agents.Tools(taad_agents.FINDINGS, {"get_candidate_findings": lambda: STORE.findings.get(aid, [])})
    audit(p, "agent.findings_summary", aid)
    return taad_agents.summarize_findings(SWASKA_CLIENT, tools)


@app.post("/v1/assessments/{aid}/poc-blueprints/{bid}/draft-notes")
def agent_draft_notes(aid: str, bid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, "cloudseals_admin", "cloudseals_assessor")
    agent_throttle(p, taad_agents.DRAFTER)
    bp = STORE.blueprints.get(bid)
    if not bp or bp["assessment_id"] != aid:
        raise err(404, "not_found", "Blueprint not found")
    audit(p, "agent.poc_draft_notes", bid)
    return taad_agents.draft_notes(SWASKA_CLIENT, taad_agents.Tools(taad_agents.DRAFTER, {"get_draft_blueprint": lambda: bp}))


@app.get("/v1/runs/{run_id}/approval-summary")
def agent_approval_summary(run_id: str, p: Principal = Depends(principal)):
    run = runtime_run(p, run_id)
    require(p, "customer_controller", "customer_admin", "cloudseals_admin", "cloudseals_reviewer", "auditor_readonly")
    agent_throttle(p, taad_agents.APPROVAL)
    audit(p, "agent.approval_summary", run_id)
    return taad_agents.summarize_approval(SWASKA_CLIENT, taad_agents.Tools(taad_agents.APPROVAL, {"get_workflow_run": lambda: run}))


@app.get("/v1/assessments/{aid}/poc-blueprints")
def list_blueprints(aid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, "cloudseals_admin", "cloudseals_assessor")
    return {"items": [{"blueprint_id": b["blueprint_id"], "state": b["state"], "workflow_pack_id": b["workflow_pack_id"]}
                      for b in STORE.blueprints.values() if b["assessment_id"] == aid]}


# ---------- AI use-case inventory, framework library and gap analysis (advisory; reviewer-gated) ----------
class InventoryRunRequest(BaseModel):
    evidence_ids: list[str] = Field(default_factory=list, max_length=8)


class GapRunRequest(BaseModel):
    framework_id: str


class ReviewItem(BaseModel):
    status: Literal["validated", "rejected"]
    reason: str = Field(min_length=1, max_length=2000)


def _inv(aid: str) -> dict:
    inv = STORE.inventory.setdefault(aid, {"use_cases": [], "gaps": []})
    inv.setdefault("maturity", None)
    inv.setdefault("roadmap", [])
    inv.setdefault("overlay", None)
    inv.setdefault("published_diagnostics", [])
    return inv


def _merge(existing: list[dict], fresh: list[dict], key: str, keep: Any) -> list[dict]:
    """Re-running an agent replaces its unreviewed output; anything a reviewer already decided is kept untouched."""
    preserved = {x[key]: x for x in existing if x["status"] != "UNREVIEWED" or not keep(x)}
    return list(preserved.values()) + [x for x in fresh if x[key] not in preserved]


def require_analysis_result(result: dict) -> None:
    """Unavailable or invalid model output must never masquerade as a successful analysis or erase saved work."""
    if result.get("mode") == "unavailable":
        raise err(503, "model_unavailable", "Document analysis is not connected. Configure a model and verify its live connection. "
                  "Existing analysis is unchanged.")
    if result.get("status") == "failed":
        raise err(502, "analysis_failed", "The model did not return usable analysis. Check the model connection and retry. Existing analysis is unchanged.")



@app.get("/v1/frameworks")
def list_frameworks(p: Principal = Depends(principal)):
    return {"items": [use_cases.framework_summary(f) for f in use_cases.FRAMEWORKS]}


@app.get("/v1/frameworks/{fid}")
def get_framework(fid: str, p: Principal = Depends(principal)):
    if fid not in use_cases.FRAMEWORKS:
        raise err(404, "not_found", "Framework not found")
    d = use_cases.FRAMEWORKS[fid]
    return {**use_cases.framework_summary(fid), "requirements": d["requirements"], "provenance": d["provenance"]}


@app.post("/v1/assessments/{aid}/inventory/run")
def run_inventory(aid: str, body: InventoryRunRequest, p: Principal = Depends(principal)):
    a = get_assessment(p, aid)
    agent_throttle(p, taad_agents.INVENTORY)
    ev = [e for e in STORE.evidence.values() if e["assessment_id"] == aid and e["state"] == "clean"
          and e["content_type"] in use_cases.DOC_TYPES and (not body.evidence_ids or e["evidence_id"] in body.evidence_ids)]
    if body.evidence_ids and len(ev) != len(set(body.evidence_ids)):
        raise err(422, "invalid_evidence_ref", "Every evidence file must exist for this assessment, be clean and be a supported document")
    docs, skipped = [], []
    for e in ev[:use_cases.MAX_DOCS]:
        try:
            data = OBJECTS.get(a["tenant_id"], "evidence", e["evidence_id"])
        except Exception:
            skipped.append(e["filename"])
            continue
        if hashlib.sha256(data).hexdigest() != e['sha256']:
            raise err(409, 'source_integrity_failed', 'An evidence file changed after upload. Upload and review a new copy; existing analysis is unchanged.')
        try:
            docs.append({"evidence_id": e["evidence_id"], "filename": e["filename"], "source_sha256": e['sha256'],
                         "text": use_cases.extract_text(e["content_type"], data)})
        except Exception:
            skipped.append(e["filename"])
    readable = [d for d in docs if d["text"].strip()]
    if not readable:
        raise err(422, "no_readable_documents", "Upload a clean supported document containing readable text before running analysis.")
    result = use_cases.run_inventory(SWASKA_CLIENT, readable)
    require_analysis_result(result)
    source_hashes = {d['evidence_id']: d['source_sha256'] for d in readable}
    for item in result['items']:
        item['source_sha256'] = source_hashes[item['evidence_id']]
    with STORE.lock:
        inv = _inv(aid)
        ran = set(result["successful_document_ids"])
        inv["use_cases"] = _merge(inv["use_cases"], result["items"], "use_case_id", lambda x: x["evidence_id"] in ran)
        audit(p, "agent.inventory", aid)
    return {**result, "documents_read": len(docs), "documents_skipped": skipped,
            "agent_id": taad_agents.INVENTORY, "advisory_only": True, "use_cases": inv["use_cases"]}


def _overlay_view(o: Optional[dict]) -> Optional[dict]:
    if not o:
        return None
    return {**o, "current_svg": studio.render_svg(o["current"], "Current architecture (as evidenced)"),
            "target_svg": studio.render_svg(o["target"], "Recommended target architecture")}


@app.get("/v1/assessments/{aid}/inventory")
def get_inventory(aid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    inv = _inv(aid)
    staff = p.is_staff   # Working material stays private; customers receive only a published snapshot.
    released = inv["published_diagnostics"][-1] if inv["published_diagnostics"] else None
    return {"use_cases": inv["use_cases"] if staff else _for_customer(inv["use_cases"]), "gaps": inv["gaps"] if staff else [],
            "maturity": inv["maturity"] if staff else None,
            "roadmap": inv["roadmap"] if staff else [], "overlay": _overlay_view(inv["overlay"]) if staff else None,
            "delivery": ({**_diagnostic_release_view(released, customer=not staff),
                          "snapshot": released["snapshot"] if staff else _for_customer(released["snapshot"])} if released else None),
            "gaps_note": None if staff else "Gap analysis, maturity and roadmap follow reviewer approval"}


@app.patch("/v1/assessments/{aid}/inventory/use-cases/{uid}")
def review_use_case(aid: str, uid: str, body: ReviewItem, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, *STAFF_REVIEW)
    with STORE.lock:
        uc = next((u for u in _inv(aid)["use_cases"] if u["use_case_id"] == uid), None)
        if not uc:
            raise err(404, "not_found", "Use case not found")
        uc.update(status=body.status.upper(), reviewed_by=p.sub, review_reason=body.reason, reviewed_at=time.time())
        audit(p, f"inventory.{body.status}", uid)
    return uc


@app.post("/v1/assessments/{aid}/gap-analysis/run")
def run_gap_analysis(aid: str, body: GapRunRequest, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, *STAFF_REVIEW)
    if body.framework_id not in use_cases.FRAMEWORKS:
        raise err(404, "not_found", "Framework not found")
    agent_throttle(p, taad_agents.GAP)
    validated = [u for u in _inv(aid)["use_cases"] if u["status"] == "VALIDATED"]
    if not validated:
        raise err(409, "no_validated_use_cases", "Validate at least one AI use case before running gap analysis")
    result = use_cases.run_gap_analysis(SWASKA_CLIENT, body.framework_id, validated)
    require_analysis_result(result)
    with STORE.lock:
        inv = _inv(aid)
        inv["gaps"] = _merge(inv["gaps"], result["items"], "gap_id", lambda x: x["framework_id"] == body.framework_id and result["status"] == "completed")
        audit(p, "agent.gap_analysis", f"{aid}/{body.framework_id}")
    return {**result, "agent_id": taad_agents.GAP, "advisory_only": True, "gaps": inv["gaps"]}


@app.patch("/v1/assessments/{aid}/gaps/{gid}")
def review_gap(aid: str, gid: str, body: ReviewItem, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, *STAFF_REVIEW)
    with STORE.lock:
        gap = next((g for g in _inv(aid)["gaps"] if g["gap_id"] == gid), None)
        if not gap:
            raise err(404, "not_found", "Gap not found")
        gap.update(status=body.status.upper(), reviewed_by=p.sub, review_reason=body.reason, reviewed_at=time.time())
        audit(p, f"gap.{body.status}", gid)
    return gap


@app.post("/v1/assessments/{aid}/maturity/run")
def run_maturity(aid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, *STAFF_REVIEW)
    agent_throttle(p, taad_agents.MATURITY)
    inv = _inv(aid)
    ucs = [u for u in inv["use_cases"] if u["status"] == "VALIDATED"]
    if not ucs:
        raise err(409, "no_validated_use_cases", "Validate at least one AI use case before maturity scoring")
    result = studio.run_maturity(SWASKA_CLIENT, ucs, [g for g in inv["gaps"] if g["status"] == "VALIDATED"])
    require_analysis_result(result)
    with STORE.lock:
        if result["maturity"] and not (inv["maturity"] and inv["maturity"]["status"] == "VALIDATED"):
            inv["maturity"] = result["maturity"]        # a validated score is never silently replaced
        audit(p, "agent.maturity", aid)
    return {**result, "agent_id": taad_agents.MATURITY, "advisory_only": True, "maturity": inv["maturity"]}


@app.patch("/v1/assessments/{aid}/maturity")
def review_maturity(aid: str, body: ReviewItem, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, *STAFF_REVIEW)
    with STORE.lock:
        m = _inv(aid)["maturity"]
        if not m:
            raise err(404, "not_found", "No maturity score yet")
        m.update(status=body.status.upper(), reviewed_by=p.sub, review_reason=body.reason, reviewed_at=time.time())
        audit(p, f"maturity.{body.status}", aid)
    return m


@app.post("/v1/assessments/{aid}/roadmap/run")
def run_roadmap(aid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, *STAFF_REVIEW)
    agent_throttle(p, taad_agents.ROADMAP)
    inv = _inv(aid)
    gaps = [g for g in inv["gaps"] if g["status"] == "VALIDATED"]
    mat = inv["maturity"] if inv["maturity"] and inv["maturity"]["status"] == "VALIDATED" else None
    if not gaps and not mat:
        raise err(409, "nothing_validated", "Validate at least one gap or the maturity score before building a roadmap")
    result = studio.run_roadmap(SWASKA_CLIENT, gaps, mat)
    require_analysis_result(result)
    with STORE.lock:
        inv["roadmap"] = _merge(inv["roadmap"], result["items"], "item_id", lambda x: result["status"] == "completed")
        audit(p, "agent.roadmap", aid)
    return {**result, "agent_id": taad_agents.ROADMAP, "advisory_only": True, "roadmap": inv["roadmap"]}


@app.patch("/v1/assessments/{aid}/roadmap/{item_id}")
def review_roadmap_item(aid: str, item_id: str, body: ReviewItem, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, *STAFF_REVIEW)
    with STORE.lock:
        it = next((i for i in _inv(aid)["roadmap"] if i["item_id"] == item_id), None)
        if not it:
            raise err(404, "not_found", "Roadmap item not found")
        it.update(status=body.status.upper(), reviewed_by=p.sub, review_reason=body.reason, reviewed_at=time.time())
        audit(p, f"roadmap.{body.status}", item_id)
    return it


@app.post("/v1/assessments/{aid}/overlay/run")
def run_overlay(aid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, *STAFF_REVIEW)
    agent_throttle(p, taad_agents.OVERLAY)
    inv = _inv(aid)
    ucs = [u for u in inv["use_cases"] if u["status"] == "VALIDATED"]
    if not ucs:
        raise err(409, "no_validated_use_cases", "Validate at least one AI use case before drawing the architecture")
    result = studio.run_overlay(SWASKA_CLIENT, ucs, [g for g in inv["gaps"] if g["status"] == "VALIDATED"])
    require_analysis_result(result)
    with STORE.lock:
        if result["overlay"] and not (inv["overlay"] and inv["overlay"]["status"] == "VALIDATED"):
            inv["overlay"] = result["overlay"]
        audit(p, "agent.overlay", aid)
    summary = {k: v for k, v in result.items() if k != "overlay"}
    return {**summary, "agent_id": taad_agents.OVERLAY, "advisory_only": True, "overlay": _overlay_view(inv["overlay"])}


@app.patch("/v1/assessments/{aid}/overlay")
def review_overlay(aid: str, body: ReviewItem, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, *STAFF_REVIEW)
    with STORE.lock:
        o = _inv(aid)["overlay"]
        if not o:
            raise err(404, "not_found", "No architecture overlay yet")
        o.update(status=body.status.upper(), reviewed_by=p.sub, review_reason=body.reason, reviewed_at=time.time())
        audit(p, f"overlay.{body.status}", aid)
    return _overlay_view(o)


def _diagnostic_material(inv: dict) -> dict:
    """Copy reviewed inputs so a customer release cannot change when working material changes."""
    reviewed = [u for u in inv['use_cases'] if u['status'] == 'VALIDATED']
    sources = [{'evidence_id': eid, 'sha256': STORE.evidence.get(eid, {}).get('sha256')}
               for eid in sorted({u['evidence_id'] for u in reviewed})]
    return copy.deepcopy({"use_cases": reviewed, 'source_evidence': sources,
                          "gaps": [g for g in inv["gaps"] if g["status"] == "VALIDATED"],
                          "maturity": inv["maturity"] if inv["maturity"] and inv["maturity"]["status"] == "VALIDATED" else None,
                          "roadmap": [i for i in inv["roadmap"] if i["status"] == "VALIDATED"],
                          "overlay": inv["overlay"] if inv["overlay"] and inv["overlay"]["status"] == "VALIDATED" else None})


_INTERNAL_REVIEW_FIELDS = ("reviewed_by", "review_reason", "reviewed_at", "notes_for_architect")


def _for_customer(value: Any) -> Any:
    """Customers see that CloudSeals reviewed something, never who reviewed it or the reviewer's internal notes."""
    if isinstance(value, dict):
        return {k: _for_customer(v) for k, v in value.items() if k not in _INTERNAL_REVIEW_FIELDS}
    if isinstance(value, list):
        return [_for_customer(v) for v in value]
    return value


def _diagnostic_source_digest(a: dict, material: dict) -> str:
    return hashlib.sha256(json.dumps({"assessment": a, "material": material}, sort_keys=True, default=str).encode()).hexdigest()


def _diagnostic_release_view(release: dict, customer: bool = False) -> dict:
    keys = ("report_id", "version", "published_at", "source_digest", "content_digest", "facts")
    return {k: release[k] for k in (keys if customer else keys[:3] + ("published_by", "publication_reason") + keys[3:])}


def _publication_blockers(aid: str, material: dict) -> list[str]:
    _, missing = studio.report_status(material["use_cases"], material["maturity"], material["roadmap"])
    uids = {u["use_case_id"] for u in material["use_cases"]}
    gids = {g["gap_id"] for g in material["gaps"]}
    rids = {r["item_id"] for r in material["roadmap"]}
    for u in material["use_cases"]:
        ev = STORE.evidence.get(u["evidence_id"])
        if not ev or ev["assessment_id"] != aid or ev["state"] != "clean":
            missing.append(f"clean source evidence required for {u['name']}")
            continue
        if u.get('source_sha256', ev['sha256']) != ev['sha256']:
            missing.append(f"source version changed for {u['name']}; analyse and review a new upload")
            continue
        try:
            source_bytes = OBJECTS.get(ev['tenant_id'], 'evidence', ev['evidence_id'])
            if hashlib.sha256(source_bytes).hexdigest() != ev['sha256']:
                missing.append(f"source integrity check failed for {u['name']}")
        except Exception:
            missing.append(f"original source unavailable for {u['name']}")
    if any(not set(g["evidence_use_case_ids"]) <= uids for g in material["gaps"]):
        missing.append("a validated gap cites a use case that is no longer validated")
    mat = material["maturity"]
    if mat and any(not set(refs) <= uids | gids for refs in mat["evidence_refs"].values()):
        missing.append("maturity cites an item that is no longer validated")
    overlay = material["overlay"]
    if overlay and any(not set(n.get("evidence_refs", [])) <= uids | gids for n in overlay["current"]["nodes"]):
        missing.append("architecture cites an item that is no longer validated")
    if any(not set(r["gap_ids_addressed"]) <= gids or not set(r["dependencies"]) <= rids for r in material["roadmap"]):
        missing.append("roadmap cites a gap or dependency that is no longer validated")
    covered = {gid for r in material["roadmap"] for gid in r["gap_ids_addressed"]}
    uncovered = [g["title"] for g in material["gaps"] if g["severity"] in ("critical", "high") and g["gap_id"] not in covered]
    if uncovered:
        missing.append("validated roadmap must address critical/high gaps: " + "; ".join(uncovered))
    return missing


class PublishDiagnosticRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


@app.post("/v1/assessments/{aid}/diagnostic-report/publish")
def publish_diagnostic_report(aid: str, body: PublishDiagnosticRequest, p: Principal = Depends(principal),
                              idempotency_key: Optional[str] = Header(default=None)):
    a = get_assessment(p, aid)
    require(p, "cloudseals_admin", "cloudseals_reviewer")
    if not body.reason.strip():
        raise err(422, "review_reason_required", "Enter a final review reason")

    def publish():
        inv = _inv(aid)
        material = _diagnostic_material(inv)
        source_digest = _diagnostic_source_digest(a, material)
        if source_digest != body.source_digest:
            raise err(409, "report_changed", "Reviewed material changed; reload and check the report before publishing")
        missing = _publication_blockers(aid, material)
        if missing:
            raise err(409, "report_not_ready", "Cannot publish: " + "; ".join(missing))
        releases = inv["published_diagnostics"]
        if releases and releases[-1]["source_digest"] == source_digest:
            return _diagnostic_release_view(releases[-1])
        doc, _ = studio.build_report_html(a, (STORE.tenants.get(a["tenant_id"]) or {}).get("name") or a["tenant_id"],
                                         material["use_cases"], material["gaps"], material["maturity"], material["roadmap"], None, p.sub, material["overlay"])
        release = {"report_id": str(uuid.uuid4()), "version": len(releases) + 1, "published_at": time.time(), "published_by": p.sub,
                   "publication_reason": body.reason.strip(), "source_digest": source_digest, "content_digest": hashlib.sha256(doc.encode()).hexdigest(),
                   "facts": studio.report_facts(material["use_cases"], material["gaps"], material["maturity"], material["roadmap"]),
                   "snapshot": material, "html": doc, "system_name": a["ai_system_name"]}
        releases.append(release)
        audit(p, "report.diagnostic_published", aid)
        return _diagnostic_release_view(release)

    return idempotent(p, idempotency_key, f"publish-diagnostic:{aid}:{body.source_digest}", publish)


@app.get("/v1/assessments/{aid}/diagnostic-report")
def diagnostic_report(aid: str, narrative: bool = False, format: Literal["html", "json"] = "html", report_id: Optional[str] = None,
                      p: Principal = Depends(principal)):
    """Staff preview working material. Customers download only explicitly published, immutable versions."""
    a = get_assessment(p, aid)
    with STORE.lock:
        inv = _inv(aid)
        release = next((r for r in inv["published_diagnostics"] if r["report_id"] == report_id), None) if report_id else None
        if report_id and not release:
            raise err(404, "not_found", "Report version not found")
        if not p.is_staff and not release:
            release = inv["published_diagnostics"][-1] if inv["published_diagnostics"] else None
            if not release:
                if format == "json":
                    return {"status": "AWAITING_PUBLICATION", "missing": [], "facts": None, "published": None}
                raise err(403, "report_not_published", "A reviewer has not published a diagnostic report yet")
        if release:
            if format == "json":
                return {"status": "FINAL", "missing": [], "facts": release["facts"], "published": _diagnostic_release_view(release, customer=not p.is_staff)}
            doc, digest, status, system_name = release["html"], release["content_digest"], "FINAL", release["system_name"]
        else:
            require(p, *STAFF_REVIEW)
            material = _diagnostic_material(inv)
            latest = _diagnostic_release_view(inv["published_diagnostics"][-1]) if inv["published_diagnostics"] else None
            status, missing = studio.report_status(material["use_cases"], material["maturity"], material["roadmap"])
            facts = studio.report_facts(material["use_cases"], material["gaps"], material["maturity"], material["roadmap"])
            if format == "json":
                return {"status": status, "missing": missing, "facts": facts, "source_digest": _diagnostic_source_digest(a, material),
                        "publication_blockers": _publication_blockers(aid, material), "published": latest,
                        "versions": [_diagnostic_release_view(r) for r in inv["published_diagnostics"]]}
            system_name = a["ai_system_name"]
    if not release:
        story = studio.draft_narrative(SWASKA_CLIENT, facts) if narrative else None
        doc, digest = studio.build_report_html(a, (STORE.tenants.get(a["tenant_id"]) or {}).get("name") or a["tenant_id"],
                                             material["use_cases"], material["gaps"], material["maturity"], material["roadmap"],
                                             story, p.sub, material["overlay"])
    audit(p, "report.diagnostic", f"{aid}/{digest[:12]}")
    name = re.sub(r"[^A-Za-z0-9_-]+", "_", system_name)[:60] or "assessment"
    return Response(doc, media_type="text/html; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="diagnostic_{name}_{status}.html"', "X-Report-Status": status, "X-Content-Digest": digest,
        **({"X-Report-Version": str(release["version"])} if release else {})})


# ---------- user and access administration (CloudSeals admins) ----------
STAFF_EMAIL_DOMAINS = [d.strip().lower() for d in re.split(r"[,;]", os.environ.get("TAAD_STAFF_EMAIL_DOMAINS", "")) if d.strip()]


class UserInvite(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    roles: list[str] = Field(min_length=1, max_length=6)
    tenant_id: Optional[str] = None


class UserRoles(BaseModel):
    roles: list[str] = Field(min_length=1, max_length=6)


def _check_membership(roles: list[str], tenant_id: Optional[str], email: Optional[str] = None) -> list[str]:
    from .security import ALL_ROLES
    roles = sorted(set(roles))
    if any(r not in ALL_ROLES for r in roles):
        raise err(422, "invalid_role", "Unknown role")
    staff = [r for r in roles if r in CLOUDSEALS_ROLES]
    if staff and (tenant_id or len(staff) != len(roles)):
        raise err(422, "invalid_membership", "CloudSeals roles cannot be combined with a customer workspace or customer roles")
    if not staff and (not tenant_id or tenant_id not in STORE.tenants):
        raise err(422, "invalid_tenant", "Customer users need an existing customer workspace")
    if staff and email and STAFF_EMAIL_DOMAINS and email.rsplit("@", 1)[-1] not in STAFF_EMAIL_DOMAINS:
        raise err(422, "email_domain_not_allowed", f"CloudSeals roles are limited to: {', '.join(STAFF_EMAIL_DOMAINS)}")
    return roles


def _admin_count() -> int:
    return sum("cloudseals_admin" in u.get("roles", []) for u in STORE.users.values())


@app.get("/v1/admin/users")
def list_users(p: Principal = Depends(principal)):
    require(p, "cloudseals_admin")
    members = [{"sub": sub, "email": u.get("email"), "roles": u["roles"], "tenant_id": u.get("tenant_id"),
                "tenant_name": (STORE.tenants.get(u.get("tenant_id") or "") or {}).get("name"), "is_self": sub == p.sub}
               for sub, u in sorted(STORE.users.items(), key=lambda kv: (kv[1].get("email") or kv[0]))]
    pending = [{"email": e, **v, "tenant_name": (STORE.tenants.get(v["tenant_id"] or "") or {}).get("name")} for e, v in sorted(STORE.pending_users.items())]
    return {"items": members, "pending": pending, "staff_email_domains": STAFF_EMAIL_DOMAINS,
            "sign_in": "google" if AUTH_PROVIDER == "google" else "other"}


@app.post("/v1/admin/users", status_code=201)
def invite_user(body: UserInvite, p: Principal = Depends(principal)):
    require(p, "cloudseals_admin")
    if AUTH_PROVIDER != "google":
        raise err(409, "not_supported", "Pre-registering by email needs Google sign-in; use workspace invitations instead")
    email = body.email.strip().lower()
    roles = _check_membership(body.roles, body.tenant_id, email)
    with STORE.lock:
        if any(u.get("email") == email for u in STORE.users.values()):
            raise err(409, "conflict", "This person already has access")
        STORE.pending_users[email] = {"roles": roles, "tenant_id": body.tenant_id, "invited_by": p.sub, "at": time.time()}
        audit(p, "user.invited", email)
    return {"email": email, "roles": roles, "tenant_id": body.tenant_id, "status": "pending_first_sign_in"}


@app.delete("/v1/admin/users/pending/{email}")
def cancel_invite(email: str, p: Principal = Depends(principal)):
    require(p, "cloudseals_admin")
    with STORE.lock:
        if STORE.pending_users.pop(email.lower(), None) is None:
            raise err(404, "not_found", "No pending invitation for this email")
        audit(p, "user.invite_cancelled", email.lower())
    return {"cancelled": email.lower()}


@app.patch("/v1/admin/users/{sub}")
def change_user_roles(sub: str, body: UserRoles, p: Principal = Depends(principal)):
    require(p, "cloudseals_admin")
    with STORE.lock:
        u = STORE.users.get(sub)
        if not u:
            raise err(404, "not_found", "User not found")
        roles = _check_membership(body.roles, u.get("tenant_id"), u.get("email"))
        if "cloudseals_admin" in u["roles"] and "cloudseals_admin" not in roles and (sub == p.sub or _admin_count() <= 1):
            raise err(409, "last_admin", "You cannot remove the admin role from yourself or from the last admin")
        u["roles"] = roles
        audit(p, "user.roles_changed", sub)
    return {"sub": sub, "roles": roles}


@app.delete("/v1/admin/users/{sub}")
def remove_user(sub: str, p: Principal = Depends(principal)):
    require(p, "cloudseals_admin")
    with STORE.lock:
        u = STORE.users.get(sub)
        if not u:
            raise err(404, "not_found", "User not found")
        if sub == p.sub or ("cloudseals_admin" in u["roles"] and _admin_count() <= 1):
            raise err(409, "last_admin", "You cannot remove yourself or the last admin")
        del STORE.users[sub]
        audit(p, "user.removed", sub)
    return {"removed": sub}


# ---------- engagement cases (CloudSeals staff) ----------
CASE_STATUSES = ("draft", "intake", "inventory", "gap", "review", "report", "delivered", "archived")
CASE_TIERS = ("tier_1", "tier_2", "tier_3")
CASE_STAFF = ("cloudseals_admin", "cloudseals_assessor", "cloudseals_reviewer")


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    customer_name: str = Field(min_length=2, max_length=200)
    tenant_id: Optional[str] = None
    industry: str = Field(default="other", max_length=40)
    region: str = Field(default="UK", max_length=40)
    frameworks_in_scope: list[str] = Field(default_factory=list, max_length=5)
    tier: Literal["tier_1", "tier_2", "tier_3"] = "tier_1"
    lead_architect: Optional[str] = None
    architects: list[str] = Field(default_factory=list, max_length=20)
    target_delivery_date: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    notes: str = Field(default="", max_length=4000)


class CasePatch(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=200)
    customer_name: Optional[str] = Field(default=None, min_length=2, max_length=200)
    tenant_id: Optional[str] = None
    industry: Optional[str] = Field(default=None, max_length=40)
    region: Optional[str] = Field(default=None, max_length=40)
    frameworks_in_scope: Optional[list[str]] = Field(default=None, max_length=5)
    tier: Optional[Literal["tier_1", "tier_2", "tier_3"]] = None
    lead_architect: Optional[str] = None
    architects: Optional[list[str]] = Field(default=None, max_length=20)
    target_delivery_date: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    notes: Optional[str] = Field(default=None, max_length=4000)


class CaseStatusChange(BaseModel):
    status: Literal["draft", "intake", "inventory", "gap", "review", "report", "delivered", "archived"]
    reason: str = Field(min_length=1, max_length=2000)


class CaseLink(BaseModel):
    assessment_id: str


def _staff_member(sub: str) -> bool:
    u = STORE.users.get(sub)
    return bool(u and set(u["roles"]) & set(CASE_STAFF))


def _case_for(p: Principal, cid: str, *, write: bool = False) -> dict:
    """Admins see every case; other staff only cases they are assigned to. Unknown and unassigned look the same (404)."""
    require(p, *CASE_STAFF)
    c = STORE.cases.get(cid)
    admin = "cloudseals_admin" in p.roles
    if not c or not (admin or p.sub in c["architects"]):
        raise err(404, "not_found", "Case not found")
    if write and not (admin or p.sub == c["lead_architect"]):
        raise err(403, "forbidden", "Only the lead architect or an admin can change this case")
    return c


def _case_people(c: dict) -> list[dict]:
    return [{"sub": s, "email": (STORE.users.get(s) or {}).get("email"), "is_lead": s == c["lead_architect"]} for s in c["architects"]]


def _case_progress(c: dict) -> dict:
    """What the linked assessments have achieved so far (reviewer-validated work only)."""
    uc = gaps = road = 0
    mat = None
    risk_rank = {"prohibited": 3, "high_risk": 2, "limited_risk": 1, "minimal_risk": 0}
    risk = None
    report = "none"
    for aid in c["assessment_ids"]:
        inv = STORE.inventory.get(aid) or {}
        ucs = [u for u in inv.get("use_cases", []) if u["status"] == "VALIDATED"]
        uc += len(ucs)
        gaps += sum(g["status"] == "VALIDATED" for g in inv.get("gaps", []))
        road += sum(i["status"] == "VALIDATED" for i in inv.get("roadmap", []))
        m = inv.get("maturity")
        if m and m["status"] == "VALIDATED":
            mat = m["overall_score"] if mat is None else round((mat + m["overall_score"]) / 2, 2)
        for u in ucs:
            if risk is None or risk_rank[u["risk_tier"]] > risk_rank[risk]:
                risk = u["risk_tier"]
        st, _ = studio.report_status(ucs, m if m and m["status"] == "VALIDATED" else None, [i for i in inv.get("roadmap", []) if i["status"] == "VALIDATED"])
        if st == "FINAL":
            report = "final"
        elif ucs and report == "none":
            report = "draft"
    return {"validated_use_cases": uc, "validated_gaps": gaps, "validated_roadmap_items": road, "maturity_score": mat, "risk_level": risk, "report": report}


def _case_view(c: dict, detail: bool = False) -> dict:
    out = {**{k: c[k] for k in ("case_id", "title", "customer_name", "tenant_id", "industry", "region", "frameworks_in_scope", "tier", "status",
                                "target_delivery_date", "created_at", "updated_at", "lead_architect")},
           "assessment_ids": c["assessment_ids"], "progress": _case_progress(c), "architects": _case_people(c)}
    if detail:
        out["notes"] = c["notes"]
        out["status_history"] = c["status_history"]
        out["assessments"] = [{"assessment_id": a["assessment_id"], "ai_system_name": a["ai_system_name"], "status": a["status"], "industry": a["industry"]}
                              for a in (STORE.assessments.get(x) for x in c["assessment_ids"]) if a]
    return out


def _validate_case_fields(frameworks: Optional[list[str]], architects: Optional[list[str]], lead: Optional[str], tenant_id: Optional[str]) -> None:
    if frameworks is not None and any(f not in use_cases.FRAMEWORKS for f in frameworks):
        raise err(422, "unknown_framework", "Unknown framework")
    if architects is not None and any(not _staff_member(a) for a in architects):
        raise err(422, "unknown_architect", "Architects must be CloudSeals staff")
    if lead and not _staff_member(lead):
        raise err(422, "unknown_architect", "The lead architect must be CloudSeals staff")
    if tenant_id and tenant_id not in STORE.tenants:
        raise err(422, "invalid_tenant", "Unknown customer workspace")


@app.get("/v1/staff")
def list_staff(p: Principal = Depends(principal)):
    require(p, *CASE_STAFF)
    members = sorted(STORE.users.items(), key=lambda kv: kv[1].get("email") or kv[0])
    return {"items": [{"sub": s, "email": u.get("email"), "roles": u["roles"]} for s, u in members if set(u["roles"]) & set(CASE_STAFF)]}


@app.post("/v1/cases", status_code=201)
def create_case(body: CaseCreate, p: Principal = Depends(principal)):
    require(p, "cloudseals_admin", "cloudseals_assessor")
    lead = body.lead_architect or p.sub
    architects = sorted(set(body.architects) | {lead, p.sub})
    _validate_case_fields(body.frameworks_in_scope, architects, lead, body.tenant_id)
    cid = "case_" + uuid.uuid4().hex[:12]
    now = time.time()
    with STORE.lock:
        STORE.cases[cid] = {"case_id": cid, "title": body.title.strip(), "customer_name": body.customer_name.strip(), "tenant_id": body.tenant_id,
                            "industry": body.industry, "region": body.region, "frameworks_in_scope": body.frameworks_in_scope, "tier": body.tier,
                            "lead_architect": lead, "architects": architects, "status": "draft", "target_delivery_date": body.target_delivery_date,
                            "notes": body.notes, "assessment_ids": [],
                            "status_history": [{"status": "draft", "by": p.sub, "at": now, "reason": "Case created"}],
                            "created_by": p.sub, "created_at": now, "updated_at": now}
        audit(p, "case.created", cid)
    return _case_view(STORE.cases[cid], detail=True)


@app.get("/v1/cases")
def list_cases(status: Optional[str] = None, q: Optional[str] = Query(default=None, max_length=100), p: Principal = Depends(principal)):
    require(p, *CASE_STAFF)
    admin = "cloudseals_admin" in p.roles
    items = [c for c in STORE.cases.values() if admin or p.sub in c["architects"]]
    if status:
        items = [c for c in items if c["status"] == status]
    if q:
        needle = q.casefold()
        items = [c for c in items if needle in c["title"].casefold() or needle in c["customer_name"].casefold()]
    items.sort(key=lambda c: c["created_at"], reverse=True)
    return {"items": [_case_view(c) for c in items], "total": len(items)}


@app.get("/v1/cases/{cid}")
def get_case(cid: str, p: Principal = Depends(principal)):
    return _case_view(_case_for(p, cid), detail=True)


@app.patch("/v1/cases/{cid}")
def patch_case(cid: str, body: CasePatch, p: Principal = Depends(principal)):
    c = _case_for(p, cid, write=True)
    changes = body.model_dump(exclude_unset=True)
    architects = changes.get("architects")
    lead = changes.get("lead_architect")
    if lead or architects is not None:
        architects = sorted(set(architects if architects is not None else c["architects"]) | {lead or c["lead_architect"]})
        changes["architects"] = architects
    _validate_case_fields(changes.get("frameworks_in_scope"), architects, lead, changes.get("tenant_id"))
    if lead and "cloudseals_admin" not in p.roles and p.sub != lead and lead != c["lead_architect"] and p.sub != c["lead_architect"]:
        raise err(403, "forbidden", "Only an admin or the current lead can hand the case over")
    with STORE.lock:
        c.update(changes)
        c["updated_at"] = time.time()
        audit(p, "case.updated", cid)
    return _case_view(c, detail=True)


@app.post("/v1/cases/{cid}/status")
def change_case_status(cid: str, body: CaseStatusChange, p: Principal = Depends(principal)):
    c = _case_for(p, cid, write=True)
    if body.status == "delivered":
        finals = [a for a in c["assessment_ids"] if _inv(a)["published_diagnostics"]]
        if not finals:
            raise err(409, "report_not_published", "Publish a diagnostic report to the customer before marking this case delivered")
    with STORE.lock:
        c["status"] = body.status
        c["status_history"].append({"status": body.status, "by": p.sub, "at": time.time(), "reason": body.reason})
        c["updated_at"] = time.time()
        audit(p, f"case.status.{body.status}", cid)
    return _case_view(c, detail=True)


@app.post("/v1/cases/{cid}/assessments")
def link_case_assessment(cid: str, body: CaseLink, p: Principal = Depends(principal)):
    c = _case_for(p, cid, write=True)
    a = STORE.assessments.get(body.assessment_id)
    if not a or (c["tenant_id"] and a["tenant_id"] != c["tenant_id"]):
        raise err(422, "invalid_assessment", "The assessment must exist and belong to this case's customer workspace")
    if any(body.assessment_id in x["assessment_ids"] for x in STORE.cases.values() if x["case_id"] != cid):
        raise err(409, "conflict", "This assessment is already linked to another case")
    with STORE.lock:
        if body.assessment_id not in c["assessment_ids"]:
            c["assessment_ids"].append(body.assessment_id)
        if not c["tenant_id"]:
            c["tenant_id"] = a["tenant_id"]
        c["updated_at"] = time.time()
        audit(p, "case.assessment_linked", f"{cid}/{body.assessment_id}")
    return _case_view(c, detail=True)


@app.delete("/v1/cases/{cid}/assessments/{aid}")
def unlink_case_assessment(cid: str, aid: str, p: Principal = Depends(principal)):
    c = _case_for(p, cid, write=True)
    with STORE.lock:
        if aid not in c["assessment_ids"]:
            raise err(404, "not_found", "Assessment is not linked to this case")
        c["assessment_ids"].remove(aid)
        c["updated_at"] = time.time()
        audit(p, "case.assessment_unlinked", f"{cid}/{aid}")
    return _case_view(c, detail=True)


@app.get("/v1/cases/{cid}/audit")
def case_audit_feed(cid: str, p: Principal = Depends(principal)):
    c = _case_for(p, cid)
    keys = [cid, *c["assessment_ids"]]
    rows = [a for a in STORE.audit if any(k in str(a.get("ref", "")) for k in keys)]
    return {"items": [{"at": a["at"], "sub": a["sub"], "email": (STORE.users.get(a["sub"]) or {}).get("email"), "action": a["action"], "ref": a["ref"]}
                      for a in reversed(rows[-300:])]}


@app.get("/v1/admin/workspaces")
def list_workspaces(p: Principal = Depends(principal)):
    require(p, *CASE_STAFF, *AUDIT_ROLES)
    out = []
    for t in STORE.tenants.values():
        tid = t["tenant_id"]
        runs = [r for r in STORE.workflow_runs.values() if r["tenant_id"] == tid]
        out.append({"tenant_id": tid, "name": t.get("name") or tid, "industry": t.get("industry"),
                    "users": sum(u.get("tenant_id") == tid for u in STORE.users.values()),
                    "assessments": sum(a["tenant_id"] == tid for a in STORE.assessments.values()),
                    "runs": len(runs), "pending_approvals": sum(r["status"] == "approval_required" for r in runs)})
    return {"items": sorted(out, key=lambda w: w["name"].casefold())}


@app.get("/v1/admin/workspaces/{tid}")
def get_workspace(tid: str, p: Principal = Depends(principal)):
    """Read-only view of a customer workspace for CloudSeals staff. Nothing here lets staff act as the customer."""
    require(p, *CASE_STAFF, *AUDIT_ROLES)
    t = STORE.tenants.get(tid)
    if not t:
        raise err(404, "not_found", "Workspace not found")
    runs = sorted((r for r in STORE.workflow_runs.values() if r["tenant_id"] == tid), key=lambda r: r.get("created_at", 0), reverse=True)
    return {"tenant": {k: t.get(k) for k in ("tenant_id", "name", "industry", "residency_profile")},
            "members": [{"sub": s, "email": u.get("email"), "roles": u["roles"]} for s, u in STORE.users.items() if u.get("tenant_id") == tid],
            "assessments": [{k: a[k] for k in ("assessment_id", "ai_system_name", "status", "industry")}
                            for a in STORE.assessments.values() if a["tenant_id"] == tid],
            "runs": [{"run_id": r["run_id"], "receipt_id": r.get("receipt_id"), "amount_minor": r.get("amount_minor"), "currency": r.get("currency"),
                      "status": r["status"], "created_by": r.get("created_by"), "created_at": r.get("created_at")} for r in runs[:25]],
            "pending_approvals": sum(r["status"] == "approval_required" for r in runs)}


@app.get("/v1/admin/metrics")
def metrics(p: Principal = Depends(principal)):
    require(p, "cloudseals_admin", "cloudseals_platform_ops", "cloudseals_reviewer", "cloudseals_assessor")
    return {"registrations": len(STORE.registrations), "assessments": len(STORE.assessments),
            "submitted": sum(a["status"] == "Submitted" for a in STORE.assessments.values()),
            "review_queue": sum(r["status"] == "draft" for r in STORE.reports.values()),
            "published_reports": sum(r["status"] == "published" for r in STORE.reports.values()),
            "poc_blueprints": len(STORE.blueprints)}


# ---------- identity, onboarding, invitations ----------
class InvitationAccept(BaseModel):
    token: str


class TenantInvitation(BaseModel):
    role: Literal["customer_architect", "customer_risk", "customer_controller", "customer_contributor"]


class RegistrationDecision(BaseModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=1)


class Assignment(BaseModel):
    sub: str
    sections: list[str]


class FindingReview(BaseModel):
    status: Literal["Confirmed gap", "Potential gap", "No gap evidenced", "Not applicable"]
    reason: str = Field(min_length=1, max_length=2000)


class TenantSettings(BaseModel):
    allow_preliminary_report: bool


class WorkflowRunRequest(BaseModel):
    receipt: dict[str, Any]
    invoices: list[dict[str, Any]] = Field(max_length=500)
    remittance: dict[str, Any] = Field(default_factory=dict)


class RuntimeApprovalDecision(BaseModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=1, max_length=2000)


class PrepareActionRequest(BaseModel):
    run_id: str


class ExecuteActionRequest(BaseModel):
    run_id: str
    action_token: str = Field(min_length=20, max_length=4096)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _invite(tenant_id: str, role: str, by: str) -> str:
    token = secrets.token_urlsafe(32)
    STORE.invitations[_hash(token)] = {"tenant_id": tenant_id, "role": role, "by": by,
                                       "expires_at": time.time() + INVITE_TTL, "used": False}
    return token


@app.get("/v1/me")
def me(p: Principal = Depends(principal)):
    return {"sub": p.sub, "email": (STORE.users.get(p.sub) or {}).get("email"), "tenant_id": p.tenant_id, "roles": p.roles,
            "is_staff": p.is_staff, "tenant": STORE.tenants.get(p.tenant_id or "")}


@app.post("/v1/invitations/accept")
def accept_invitation(body: InvitationAccept, sub: str = Depends(authenticated_sub)):
    inv = STORE.invitations.get(_hash(body.token))
    if not inv or inv["used"] or inv["expires_at"] < time.time():
        raise err(400, "invalid_invitation", "Invitation is invalid or expired")
    with STORE.lock:
        if sub in STORE.users:
            raise err(409, "already_member", "Identity already has a membership")
        roles = ["customer_admin", "customer_architect"] if inv["role"] == "customer_admin" else [inv["role"]]
        STORE.users[sub] = {"tenant_id": inv["tenant_id"], "roles": roles}
        inv["used"] = True
    STORE.audit.append({"at": time.time(), "sub": sub, "tenant_id": inv["tenant_id"], "action": "invitation.accept", "ref": inv["role"]})
    return {"tenant_id": inv["tenant_id"], "roles": roles}


@app.post("/v1/tenant/invitations", status_code=201)
def tenant_invite(body: TenantInvitation, p: Principal = Depends(principal)):
    require(p, "customer_admin")
    token = _invite(p.tenant_id, body.role, p.sub)
    audit(p, "tenant.invite", body.role)
    STORE.outbox.append({"to": "invitee", "kind": "tenant_invitation", "tenant_id": p.tenant_id})
    return {"role": body.role, "expires_in_seconds": INVITE_TTL, **({"invitation_token": token} if ENV == "local" else {})}


@app.get("/v1/admin/registrations")
def list_registrations(p: Principal = Depends(principal)):
    require(p, "cloudseals_admin")
    return {"items": [r for r in STORE.registrations]}


@app.get("/v1/admin/tenants")
def list_tenants(p: Principal = Depends(principal)):
    require(p, "cloudseals_admin")
    return {"items": list(STORE.tenants.values())}


@app.post("/v1/admin/registrations/{rid}/decision")
def decide_registration(rid: str, body: RegistrationDecision, p: Principal = Depends(principal)):
    require(p, "cloudseals_admin")
    reg = next((r for r in STORE.registrations if r.get("registration_id") == rid), None)
    if not reg:
        raise err(404, "not_found", "Registration not found")
    if reg["status"] != "pending_approval":
        raise err(409, "conflict", "Already decided")
    if body.decision == "reject":
        reg["status"] = "rejected"
        return {"status": "rejected"}
    if not reg["engagement_verified"]:
        raise err(409, "engagement_not_verified", "No approved engagement matches this registration")
    tid = f"t-{uuid.uuid4().hex[:12]}"
    STORE.tenants[tid] = {"tenant_id": tid, "name": reg["organisation_name"], "industry": reg["industry"],
                          "residency_profile": (reg["jurisdiction"] or ["UK"])[0], "allow_preliminary_report": False}
    token = _invite(tid, "customer_admin", p.sub)
    reg.update(status="approved", tenant_id=tid)
    STORE.outbox.append({"to": reg["work_email"], "kind": "tenant_activation", "tenant_id": tid})
    emit("taad.tenant.activated.v1", tid, {"tenant_id": tid, "organisation_ref": tid, "residency_profile": STORE.tenants[tid]["residency_profile"],
                                           "engagement_approval_ref": reg["engagement_reference"]})
    audit(p, "registration.approve", rid)
    return {"status": "approved", "tenant_id": tid, **({"invitation_token": token} if ENV == "local" else {})}


@app.put("/v1/admin/tenants/{tid}/settings")
def tenant_settings(tid: str, body: TenantSettings, p: Principal = Depends(principal)):
    require(p, "cloudseals_admin")
    if tid not in STORE.tenants:
        raise err(404, "not_found", "Tenant not found")
    STORE.tenants[tid]["allow_preliminary_report"] = body.allow_preliminary_report
    audit(p, "tenant.settings", tid)
    return STORE.tenants[tid]


# ---------- TrustOps Core bounded execution runtime ----------
def runtime_enabled() -> bool:
    # This implementation only ships a synthetic Mock SAP connector. It must never
    # masquerade as a production ERP connector when this TAAD service is deployed.
    return ENV in ("local", "dev") and os.environ.get("TRUSTOPS_RUNTIME_MODE", "sandbox") == "sandbox"


def runtime_run(p: Principal, run_id: str) -> dict[str, Any]:
    run = STORE.workflow_runs.get(run_id)
    if not run or (not p.is_staff and run["tenant_id"] != p.tenant_id):
        raise err(404, "not_found", "Workflow run not found")
    return run


@app.get("/v1/agentops")
def agentops(p: Principal = Depends(principal)):
    require(p, "cloudseals_admin", "cloudseals_platform_ops", "cloudseals_reviewer", "cloudseals_assessor",
            "customer_admin", "customer_architect", "customer_risk", "customer_controller", "customer_contributor", "auditor_readonly")
    runs = [r for r in STORE.workflow_runs.values() if p.is_staff or r["tenant_id"] == p.tenant_id]
    model_configured = bool(llm.provider())
    return {"mode": "sandbox" if runtime_enabled() else "unavailable",
            "agent_mode": f"{llm.provider()}_configured" if llm.provider() else "deterministic",
            "model_id": llm.configured_model_id() if model_configured else None,
            "evidence_signing": "cloud_kms" if os.environ.get("TAAD_KMS_SIGNING_KEY_VERSION") else "local_hash_chain",
            "agents": trustops_runtime.AGENT_MANIFESTS,
            "workflow_pack": trustops_runtime.PACK_ID, "workflow_version": trustops_runtime.PACK_VERSION,
            "global_prohibitions": trustops_runtime.PACK["global_prohibitions"],
            "connector": trustops_runtime.PACK["connector"],
            "connector_status": "mock_only",
            "runs": len(runs), "completed": sum(r["status"] == "completed" for r in runs),
            "approval_required": sum(r["status"] == "approval_required" for r in runs),
            "escalated": sum(r["status"] == "escalated" for r in runs)}


@app.get("/v1/runs")
def list_workflow_runs(limit: int = Query(default=25, ge=1, le=100), p: Principal = Depends(principal)):
    require(p, "cloudseals_admin", "cloudseals_platform_ops", "cloudseals_reviewer", "cloudseals_assessor",
            "customer_admin", "customer_architect", "customer_risk", "customer_controller", "customer_contributor", "auditor_readonly")
    runs = [r for r in STORE.workflow_runs.values() if p.is_staff or r["tenant_id"] == p.tenant_id]
    runs.sort(key=lambda r: (r.get("created_at", 0), r.get("run_id", "")), reverse=True)
    return {"items": [{k: r.get(k) for k in ("run_id", "workflow_id", "workflow_version", "receipt_id", "amount_minor",
             "currency", "status", "policy_decision", "created_at")} for r in runs[:limit]], "total": len(runs)}


def _start_workflow(pack_id: str, body: WorkflowRunRequest, p: Principal, idempotency_key: Optional[str], on_event=None):
    if not runtime_enabled():
        raise err(503, "runtime_unavailable", "Governed execution runtime is not enabled in this environment")
    require(p, "customer_admin", "customer_architect", "customer_risk", "customer_controller", "cloudseals_assessor", "cloudseals_admin")
    if pack_id != trustops_runtime.PACK_ID:
        raise err(404, "workflow_pack_not_found", "Workflow pack not found")

    def do():
        try:
            receipt_id = body.receipt.get("receipt_id")
            if any(x["tenant_id"] == p.tenant_id and x["receipt_id"] == receipt_id
                   for x in STORE.workflow_runs.values()):
                raise err(409, "duplicate_receipt", "Receipt has already been submitted for this tenant")
            model_client = trustops_runtime.configured_model_client()
            run = trustops_runtime.run_agents(p.tenant_id or "", p.sub, body.receipt, body.invoices, body.remittance,
                                              client=model_client, on_event=on_event)
        except trustops_runtime.RuntimeErrorCode as e:
            status = 503 if e.code == "agent_model_unavailable" else 502 if e.code == "agent_model_output_invalid" else 422
            raise err(status, e.code, str(e)) from e
        run_id = str(uuid.uuid4())
        run["run_id"] = run_id
        run["approval_id"] = run_id if run["policy_decision"]["approval_required"] else None
        STORE.workflow_runs[run_id] = run
        emit("trustops.workflow.run_started.v1", run["tenant_id"], {"run_id": run_id, "workflow_id": pack_id,
             "workflow_version": run["workflow_version"], "input_digest": run["input_digest"],
             "policy_decision": run["policy_decision"]["decision"]})
        audit(p, "trustops.workflow.start", run_id)
        return run
    return idempotent(p, idempotency_key, f"workflow:{pack_id}", do)


@app.post("/v1/workflows/{pack_id}/runs", status_code=201)
def start_workflow(pack_id: str, body: WorkflowRunRequest, p: Principal = Depends(principal),
                   idempotency_key: Optional[str] = Header(default=None)):
    return _start_workflow(pack_id, body, p, idempotency_key)


_STREAM_SLOTS = threading.BoundedSemaphore(4)


@app.post("/v1/workflows/{pack_id}/runs/stream", response_class=StreamingResponse,
          responses={200: {"content": {"text/event-stream": {}}}})
def stream_workflow(pack_id: str, body: WorkflowRunRequest, p: Principal = Depends(principal),
                    idempotency_key: Optional[str] = Header(default=None)):
    """Authenticated POST stream. Workers publish events at actual execution boundaries."""
    if not runtime_enabled():
        raise err(503, "runtime_unavailable", "Governed execution runtime is not enabled in this environment")
    require(p, "customer_admin", "customer_architect", "customer_risk", "customer_controller", "cloudseals_assessor", "cloudseals_admin")
    if pack_id != trustops_runtime.PACK_ID:
        raise err(404, "workflow_pack_not_found", "Workflow pack not found")
    if not idempotency_key or len(idempotency_key) > 128:
        raise err(400, "idempotency_key_required", "Idempotency-Key header required (max 128 chars)")
    if not _STREAM_SLOTS.acquire(blocking=False):
        raise err(429, "workflow_capacity", "Workflow capacity reached; try again shortly")
    events = queue.Queue(maxsize=64)

    def worker():
        try:
            run = _start_workflow(pack_id, body, p, idempotency_key, on_event=events.put_nowait)
            # The normal middleware must not block streaming until this worker ends.
            # Save here before announcing that the final result is available.
            if persist.enabled():
                with STORE.lock:
                    persist.save(STORE)
            events.put_nowait({"event": "run.completed", "at": time.time(), "run": run})
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
            events.put_nowait({"event": "run.failed", "at": time.time(), "error": detail})
        except Exception:
            events.put_nowait({"event": "run.failed", "at": time.time(), "error": {"code": "workflow_failed",
                                  "message": "Workflow could not be completed. No action was executed."}})
        finally:
            _STREAM_SLOTS.release()

    def generate():
        while True:
            try:
                event = events.get(timeout=10)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            yield "data: " + json.dumps(event, default=str) + "\n\n"
            if event["event"] in ("run.completed", "run.failed"):
                break

    try:
        threading.Thread(target=worker, daemon=True, name="trustops-workflow").start()
    except RuntimeError as exc:
        _STREAM_SLOTS.release()
        raise err(503, "workflow_unavailable", "Workflow could not be started") from exc
    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"X-Workflow-Stream": "1", "X-Accel-Buffering": "no", "Cache-Control": "no-store"})


@app.get("/v1/runs/{run_id}")
def get_workflow_run(run_id: str, p: Principal = Depends(principal)):
    run = runtime_run(p, run_id)
    return {k: v for k, v in run.items() if k != "created_by"}


@app.post("/v1/approvals/{approval_id}/decision")
def runtime_approval(approval_id: str, body: RuntimeApprovalDecision, p: Principal = Depends(principal),
                     idempotency_key: Optional[str] = Header(default=None)):
    run = runtime_run(p, approval_id)
    require(p, "customer_controller")
    if run.get("approval_id") != approval_id:
        raise err(409, "approval_not_pending", "No pending approval exists for this run")
    if p.sub == run["created_by"]:
        raise err(403, "maker_checker_violation", "The workflow initiator cannot approve their own action")

    def do():
        if run["status"] != "approval_required":
            raise err(409, "approval_not_pending", "No pending approval exists for this run")
        run["approval"] = {"decision": body.decision, "by": p.sub, "reason": body.reason, "at": time.time()}
        if body.decision == "approve":
            run["status"] = "approved_to_prepare"
        else:
            run["status"] = "rejected"
        append = trustops_runtime.append_evidence(STORE.runtime_evidence, run["tenant_id"], approval_id,
                                                 "approval.decision", run["approval"])
        audit(p, f"trustops.approval.{body.decision}", approval_id)
        emit("trustops.approval.decision.v1", run["tenant_id"], {"run_id": approval_id,
             "decision": body.decision, "evidence_hash": append["record_hash"]})
        return {"run_id": approval_id, "status": run["status"], "approval": run["approval"]}
    return idempotent(p, idempotency_key, f"runtime-approval:{approval_id}", do)


@app.post("/v1/execution/prepare")
def prepare_execution(body: PrepareActionRequest, p: Principal = Depends(principal),
                      idempotency_key: Optional[str] = Header(default=None)):
    run = runtime_run(p, body.run_id)
    require(p, "customer_admin", "customer_architect", "customer_risk", "customer_controller", "cloudseals_assessor", "cloudseals_admin")
    if not runtime_enabled():
        raise err(503, "runtime_unavailable", "Governed execution runtime is not enabled in this environment")
    if not idempotency_key or len(idempotency_key) > 128:
        raise err(400, "idempotency_key_required", "Idempotency-Key header required (max 128 chars)")
    key = (p.sub, f"runtime-prepare:{body.run_id}", idempotency_key)
    with STORE.lock:
        if key in STORE.idempotency:
            return {**STORE.idempotency[key], "action_token": None,
                    "note": "Token is returned only in the original response. Use a new idempotency key to rotate it."}
        if run["status"] not in ("ready_to_prepare", "approved_to_prepare", "prepared") or not run.get("proposal"):
            raise err(409, "policy_not_authorized", "Policy or approval state does not authorize preparation")

        def do():
            proposal = run["proposal"]
            digest = trustops_runtime.canonical_digest(proposal)
            now = int(time.time())
            nonce = secrets.token_urlsafe(18)
            claims = {"run_id": body.run_id, "tenant_id": run["tenant_id"], "sub": p.sub,
                      "proposal_digest": digest, "jti": nonce, "iat": now,
                      "exp": now + trustops_runtime.TOKEN_TTL_SECONDS}
            try:
                token = trustops_runtime.issue_action_token(trustops_runtime.token_secret(ENV), claims)
            except trustops_runtime.RuntimeErrorCode as e:
                raise err(503, e.code, str(e)) from e
            precommit = trustops_runtime.append_evidence(STORE.runtime_evidence, run["tenant_id"], body.run_id,
                "execution.pre_commit", {"proposal_digest": digest, "policy_id": run["policy_decision"]["policy_id"],
                "policy_version": run["policy_decision"]["policy_version"], "approval": run.get("approval"),
                "agent_trace": run["agent_trace"]})
            run["prepared_action"] = {"proposal_digest": digest, "prepared_by": p.sub, "prepared_at": time.time(),
                "pre_commit_evidence_hash": precommit["record_hash"], "expires_at": now + trustops_runtime.TOKEN_TTL_SECONDS}
            token_digest = hashlib.sha256(token.encode()).hexdigest()
            for old in STORE.action_tokens.values():
                if old["run_id"] == body.run_id:
                    old["used"] = True
            STORE.action_tokens[token_digest] = {"run_id": body.run_id, "tenant_id": run["tenant_id"],
                "sub": p.sub, "jti": nonce, "used": False, "expires_at": now + trustops_runtime.TOKEN_TTL_SECONDS}
            run["status"] = "prepared"
            audit(p, "trustops.execution.prepare", body.run_id)
            return {"run_id": body.run_id, "status": run["status"], "prepared_action": run["prepared_action"],
                    "action_token": token, "token_expires_in_seconds": trustops_runtime.TOKEN_TTL_SECONDS,
                    "connector": "mock_sap"}
        result = do()
        # Never persist bearer action tokens in the database/snapshot or idempotency record.
        STORE.idempotency[key] = {k: v for k, v in result.items() if k != "action_token"}
        return result


@app.post("/v1/execution/execute")
def execute_action(body: ExecuteActionRequest, p: Principal = Depends(principal),
                   idempotency_key: Optional[str] = Header(default=None)):
    run = runtime_run(p, body.run_id)
    require(p, "customer_admin", "customer_architect", "customer_risk", "customer_controller", "cloudseals_assessor", "cloudseals_admin")
    if not runtime_enabled():
        raise err(503, "runtime_unavailable", "Governed execution runtime is not enabled in this environment")
    if run["status"] == "completed" and run.get("execution"):
        return run["execution"]
    if run["status"] != "prepared" or not run.get("prepared_action"):
        raise err(409, "action_not_prepared", "Action must pass policy, approval, and evidence pre-commit")
    try:
        claims = trustops_runtime.verify_action_token(trustops_runtime.token_secret(ENV), body.action_token)
    except trustops_runtime.RuntimeErrorCode as e:
        raise err(403, e.code, str(e)) from e
    token_digest = hashlib.sha256(body.action_token.encode()).hexdigest()
    record = STORE.action_tokens.get(token_digest)
    proposal_digest = trustops_runtime.canonical_digest(run["proposal"])
    if (not record or record["used"] or claims.get("run_id") != body.run_id
            or claims.get("tenant_id") != run["tenant_id"] or claims.get("sub") != p.sub
            or claims.get("proposal_digest") != proposal_digest or claims.get("jti") != record["jti"]
            or record["run_id"] != body.run_id or record["tenant_id"] != run["tenant_id"]
            or record["sub"] != p.sub):
        raise err(403, "action_token_scope_mismatch", "Action token is invalid, used, or scoped to another action")
    if run["prepared_action"]["proposal_digest"] != proposal_digest:
        raise err(409, "prepared_action_changed", "Prepared payload changed after evidence pre-commit")

    def do():
        if run["status"] == "completed" and run.get("execution"):
            return run["execution"]
        if record["used"]:
            raise err(409, "action_token_used", "Action token was already consumed")
        record["used"] = True
        # This deterministic mock connector is the only executable adapter in this project.
        ack = STORE.mock_sap.get(body.run_id)
        if ack is None:
            ack = {"ack_id": "MOCK-SAP-" + body.run_id[:12], "status": "accepted",
                   "action_digest": proposal_digest, "connector": "mock_sap", "at": time.time()}
            STORE.mock_sap[body.run_id] = ack
        commit = trustops_runtime.append_evidence(STORE.runtime_evidence, run["tenant_id"], body.run_id,
            "execution.commit", {"acknowledgement": ack, "proposal_digest": proposal_digest,
                                  "pre_commit_hash": run["prepared_action"]["pre_commit_evidence_hash"]})
        result = {"run_id": body.run_id, "status": "completed", "connector": "mock_sap",
                  "acknowledgement": ack, "commit_evidence_hash": commit["record_hash"]}
        run["execution"] = result
        run["status"] = "completed"
        audit(p, "trustops.execution.complete", body.run_id)
        emit("trustops.execution.completed.v1", run["tenant_id"], result)
        return result
    return idempotent(p, idempotency_key, f"runtime-execute:{body.run_id}", do)


@app.post("/v1/evidence/{run_id}/verify")
def verify_runtime_evidence(run_id: str, p: Principal = Depends(principal)):
    run = runtime_run(p, run_id)
    records = [r for r in STORE.runtime_evidence if r["run_id"] == run_id and r["tenant_id"] == run["tenant_id"]]
    valid = trustops_runtime.verify_evidence(STORE.runtime_evidence, run["tenant_id"])
    sigs = trustops_runtime.verify_signatures(STORE.runtime_evidence, run["tenant_id"])
    return {"run_id": run_id, "valid": valid, "records": records, "signatures": sigs,
            "integrity": "kms_signed_hash_chain" if sigs["signed"] else "local_hash_chain_only",
            "production_signature": bool(sigs["signed"] and sigs["all_valid"])}


# ---------- assessment detail, progress, assignments ----------
def progress(a: dict) -> dict:
    ans = all_answers(a["assessment_id"])
    required = [q["question_id"] for q in REG.questions.values() if q["required"] == "yes" and q["enabled"] and q["scope"] == "org"]
    done = sum(q in ans for q in required)
    return {"required_total": len(required), "required_answered": done, "answers_total": len(ans)}


@app.get("/v1/assessments/{aid}")
def assessment_detail(aid: str, p: Principal = Depends(principal)):
    a = get_assessment(p, aid)
    return {**a, "progress": progress(a), "assignments": STORE.assignments.get(aid, {})}


@app.get("/v1/assessments/{aid}/answers")
def list_answers(aid: str, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    return {"items": [{k: v for k, v in rec.items()} for (x, _s, _q), rec in sorted(STORE.answers.items()) if x == aid]}


@app.post("/v1/assessments/{aid}/assignments")
def assign(aid: str, body: Assignment, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, "customer_admin", "customer_architect")
    target = STORE.users.get(body.sub)
    if not target or target["tenant_id"] != p.tenant_id:
        raise err(404, "not_found", "Member not found")
    valid = {q["section"] for q in REG.questions.values()}
    if not set(body.sections) <= valid:
        raise err(422, "unknown_section", "Unknown section")
    STORE.assignments.setdefault(aid, {})[body.sub] = body.sections
    audit(p, "assignment.set", f"{aid}/{body.sub}")
    return {"sub": body.sub, "sections": body.sections}


# ---------- reviewer finding adjustment ----------
@app.post("/v1/assessments/{aid}/findings/{rule_id}/review")
def review_finding(aid: str, rule_id: str, body: FindingReview, p: Principal = Depends(principal)):
    get_assessment(p, aid)
    require(p, "cloudseals_reviewer", "cloudseals_assessor")
    if any(r["assessment_id"] == aid and r["status"] == "published" for r in STORE.reports.values()):
        raise err(409, "published", "Published report findings are frozen; issue a new report version")
    f = next((x for x in STORE.findings.get(aid, []) if x["rule_id"] == rule_id), None)
    if not f:
        raise err(404, "not_found", "Finding not found")
    f.setdefault("review_history", []).append({"from": f["status"], "to": body.status, "by": p.sub,
                                               "reason": body.reason, "at": time.time()})
    f["status"], f["reviewer_status"] = body.status, "reviewed"
    audit(p, "finding.review", f"{aid}/{rule_id}")
    return f


# ---------- report download ----------
def render_model(a: dict, r: dict) -> dict:
    aid = a["assessment_id"]
    published = r["status"] == "published"
    findings = r["findings_snapshot"] if published else STORE.findings.get(aid, [])
    ans = all_answers(aid)
    meta: dict[str, dict] = {}
    for (x, _s, qid), rec in STORE.answers.items():
        if x == aid:
            meta[qid] = {"evidence_refs": rec["evidence_refs"], "comment": rec["comment"]}
    return reporting.build_model(REG, a, ans, meta, findings, STORE.not_assessed.get(aid, []), r["status"], r.get("review"))


@app.get("/v1/assessments/{aid}/reports/{rid}/download")
def download_report(aid: str, rid: str, format: Literal["docx", "pdf", "json"] = "pdf", p: Principal = Depends(principal)):
    a = get_assessment(p, aid)
    r = STORE.reports.get(rid)
    if not r or r["assessment_id"] != aid:
        raise err(404, "not_found", "Report not found")
    if not p.is_staff and r["status"] != "published":
        prelim = STORE.tenants.get(a["tenant_id"], {}).get("allow_preliminary_report") and r["status"] == "draft"
        if not prelim:
            raise err(404, "not_found", "Report not found")
    model = render_model(a, r)
    audit(p, "report.download", f"{rid}:{format}")
    if format == "json":
        return JSONResponse(model)
    body = reporting.render_docx(model) if format == "docx" else reporting.render_pdf(model)
    mime = ("application/vnd.openxmlformats-officedocument.wordprocessingml.document" if format == "docx" else "application/pdf")
    name = f"taad-{model['status'].lower()}-{rid[:8]}.{format}"
    return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}"',
                                                    "X-Report-Status": model["status"]})


# ---------- admin operations ----------
@app.get("/v1/admin/review-queue")
def review_queue(p: Principal = Depends(principal)):
    require(p, "cloudseals_admin", "cloudseals_reviewer", "cloudseals_assessor", "cloudseals_platform_ops")
    return {"items": [{"report_id": r["report_id"], "assessment_id": r["assessment_id"], "tenant_id": r["tenant_id"],
                       "finding_count": r["finding_count"], "status": r["status"]}
                      for r in STORE.reports.values() if r["status"] in ("draft", "clarification_requested")]}


AUDIT_ROLES = ("cloudseals_admin", "cloudseals_platform_ops", "auditor_readonly")
STARTED_AT = time.time()


def _audit_rows(q: Optional[str], action: Optional[str], actor: Optional[str], since: Optional[float], until: Optional[float]) -> list[dict]:
    rows = []
    needle = (q or "").casefold()
    who = (actor or "").casefold()
    for a in reversed(STORE.audit):
        email = (STORE.users.get(a.get("sub", "")) or {}).get("email") or ""
        if action and not a["action"].startswith(action):
            continue
        if who and who not in a.get("sub", "").casefold() and who not in email.casefold():
            continue
        if since is not None and a["at"] < since or until is not None and a["at"] > until:
            continue
        if needle and needle not in f"{a['action']} {a.get('ref', '')} {a.get('sub', '')} {email}".casefold():
            continue
        rows.append({**a, "email": email or None})
    return rows


@app.get("/v1/admin/activity")
def activity(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0), q: Optional[str] = Query(default=None, max_length=100),
             action: Optional[str] = Query(default=None, max_length=60), actor: Optional[str] = Query(default=None, max_length=120),
             since: Optional[float] = None, until: Optional[float] = None, p: Principal = Depends(principal)):
    require(p, *AUDIT_ROLES)
    rows = _audit_rows(q, action, actor, since, until)
    categories: dict[str, int] = {}
    for a in rows:
        key = a["action"].split(".", 1)[0]
        categories[key] = categories.get(key, 0) + 1
    return {"items": rows[offset:offset + limit], "total": len(rows), "offset": offset, "limit": limit,
            "categories": dict(sorted(categories.items(), key=lambda kv: -kv[1]))}


def _csv_cell(v: Any) -> str:
    t = str(v if v is not None else "")
    if t[:1] in ("=", "+", "-", "@", "\t", "\r"):
        t = "'" + t                      # spreadsheet formula injection: audit text includes user-chosen names
    return '"' + t.replace('"', '""') + '"'


@app.get("/v1/admin/activity/export")
def activity_export(q: Optional[str] = Query(default=None, max_length=100), action: Optional[str] = Query(default=None, max_length=60),
                    actor: Optional[str] = Query(default=None, max_length=120), since: Optional[float] = None, until: Optional[float] = None,
                    p: Principal = Depends(principal)):
    require(p, *AUDIT_ROLES)
    rows = _audit_rows(q, action, actor, since, until)[:20000]
    lines = ["when_utc,actor,email,tenant,action,reference"] + [
        ",".join(_csv_cell(x) for x in (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(a["at"])), a.get("sub"), a.get("email"),
                                        a.get("tenant_id"), a["action"], a.get("ref")))
        for a in rows]
    audit(p, "audit.exported", f"{len(rows)} rows")
    return Response("\n".join(lines) + "\n", media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="activity-log.csv"'})


@app.get("/v1/admin/health")
def service_health(probe: bool = False, p: Principal = Depends(principal)):
    """Component status for operators. `probe=true` makes tiny live calls (model, KMS) and reports their latency."""
    require(p, *AUDIT_ROLES)
    if probe:
        agent_throttle(p, "service-health")

    def timed(fn) -> dict:
        t = time.perf_counter()
        try:
            fn()
            return {"ok": True, "ms": round((time.perf_counter() - t) * 1000)}
        except Exception as exc:
            return {"ok": False, "ms": round((time.perf_counter() - t) * 1000), "error": f"{type(exc).__name__}: {str(exc)[:140]}"}

    provider = llm.provider()
    kms_key = os.environ.get("TAAD_KMS_SIGNING_KEY_VERSION", "")
    model_id = llm.configured_model_id()
    model = {"configured": bool(provider), "provider": provider or None, "model_id": model_id if provider else None}
    if probe and SWASKA_CLIENT is not None:
        model["probe"] = timed(lambda: SWASKA_CLIENT.complete("Reply with the JSON object {\"ok\": true}.", "ping", max_tokens=20))
    signing = {"configured": bool(kms_key), "key_version": kms_key or None}
    if probe and kms_key:
        from . import kms as kms_mod
        signer = kms_mod.from_env()
        signing["probe"] = timed(lambda: signer.sign(kms_mod.digest_of("health-probe")))
    day = time.time() - 86400
    agent_calls: dict[str, int] = {}
    for a in STORE.audit:
        if a["at"] >= day and a["action"].startswith("agent."):
            agent_calls[a["action"]] = agent_calls.get(a["action"], 0) + 1
    state_backend = "gcs" if os.environ.get("TAAD_STATE_GCS_URI") else "sql" if persist.enabled() else "memory"
    return {"service": {"revision": os.environ.get("K_REVISION"), "environment": ENV, "uptime_seconds": round(time.time() - STARTED_AT),
                        "auth": AUTH_PROVIDER or AUTH_MODE},
            "state": {"backend": state_backend, "durable": state_backend != "memory", **persist.STATUS},
            "evidence_store": {"backend": os.environ.get("TAAD_OBJECT_BACKEND") or "local-disk"},
            "malware_scanner": {"configured": scanner.from_env() is not None, "engine": "ClamAV" if scanner.from_env() else None,
                                **({"probe": timed(lambda: scanner.from_env().ping() or (_ for _ in ()).throw(RuntimeError("no PONG from clamd")))}
                                   if probe and scanner.from_env() else {})},
            "model": model, "evidence_signing": signing,
            "runtime": {"mode": "sandbox" if runtime_enabled() else "unavailable"},
            "agents": {"calls_last_24h": agent_calls, "advisory_agents": len(taad_agents.AGENTS)},
            "counts": {"users": len(STORE.users), "assessments": len(STORE.assessments), "cases": len(STORE.cases), "audit_events": len(STORE.audit)}}


# ---------- portal (static, same origin) ----------
_portal = ROOT / "apps" / "portal-web"
@app.get("/portal/config.json")
def portal_config():
    """Use seeded users only for local development; deployed portals require real OIDC config."""
    assessment_model = "demo" if getattr(SWASKA_CLIENT, "is_demo", False) else "configured" if SWASKA_CLIENT is not None else "unavailable"
    if ENV == "local" and AUTH_MODE == "dev":
        return {"mode": "dev", "oidc": {}, "assessment_model": assessment_model}
    if AUTH_MODE != "oidc":
        raise err(503, "portal_auth_misconfigured", "Portal requires OIDC authentication outside local development")
    google = AUTH_PROVIDER == "google"
    oidc = {
        "provider": "google" if google else "oidc",
        "authorize_url": GOOGLE_AUTHORIZE_URL if google else os.environ.get("TAAD_PORTAL_AUTHORIZE_URL", ""),
        # Google's web client needs a client secret at the token endpoint, so the portal exchanges the code via this API.
        "token_url": "/v1/auth/token" if google else os.environ.get("TAAD_PORTAL_TOKEN_URL", ""),
        "client_id": os.environ.get("TAAD_GOOGLE_CLIENT_ID" if google else "TAAD_PORTAL_CLIENT_ID", ""),
        "redirect_uri": os.environ.get("TAAD_PORTAL_REDIRECT_URI", ""),
        "logout_url": "" if google else os.environ.get("TAAD_PORTAL_LOGOUT_URL", ""),
        "scope": "openid email profile" if google else "openid email",
    }
    required = ("authorize_url", "redirect_uri") if google else ("authorize_url", "token_url", "logout_url", "redirect_uri")
    for key in required:
        parsed = urlparse(oidc[key])
        if parsed.scheme != "https" or not parsed.netloc:
            raise err(503, "portal_auth_misconfigured", "Sign-in is not fully configured for this portal")
    if not oidc["client_id"]:
        raise err(503, "portal_auth_misconfigured", "Sign-in is not fully configured for this portal")
    return {"mode": "oidc", "oidc": oidc, "assessment_model": assessment_model}


GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_CALLBACK_PARAMS = ("code", "state", "scope", "authuser", "prompt", "hd", "error", "error_description")


@app.get("/api/auth/callback/google", include_in_schema=False)
def google_callback_forward(request: Request):
    """The OAuth client already lists this path for the domain (it was the previous UI's callback). Forward only the
    expected OAuth parameters to the portal, which completes the PKCE exchange in the browser."""
    if AUTH_PROVIDER != "google":
        raise err(404, "not_found", "Not available")
    from urllib.parse import urlencode
    q = {k: v for k, v in request.query_params.items() if k in _CALLBACK_PARAMS}
    return Response(status_code=302, headers={"Location": "/portal/?" + urlencode(q)})
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


@app.post("/v1/auth/token")
async def google_token_exchange(request: Request):
    """Authorization-code exchange for Google sign-in. Adds the client secret server-side and returns the ID token
    (which is what this API verifies) as `access_token`. Only our own client ID and redirect URI are accepted."""
    if AUTH_PROVIDER != "google":
        raise err(404, "not_found", "Not available")
    import urllib.error
    import urllib.parse
    import urllib.request
    form = urllib.parse.parse_qs((await request.body()).decode(), keep_blank_values=True)
    one = lambda k: (form.get(k) or [""])[0]  # noqa: E731
    if one("grant_type") != "authorization_code" or one("client_id") != os.environ.get("TAAD_GOOGLE_CLIENT_ID") \
            or one("redirect_uri") != os.environ.get("TAAD_PORTAL_REDIRECT_URI") or not one("code") or not one("code_verifier"):
        raise err(400, "invalid_request", "Invalid token request")
    data = urllib.parse.urlencode({"grant_type": "authorization_code", "code": one("code"), "code_verifier": one("code_verifier"),
                                   "client_id": one("client_id"), "redirect_uri": one("redirect_uri"),
                                   "client_secret": os.environ["TAAD_GOOGLE_CLIENT_SECRET"]}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(GOOGLE_TOKEN_URL, data=data), timeout=10) as r:  # noqa: S310
            body = json.loads(r.read())
    except (urllib.error.URLError, ValueError):
        raise err(502, "token_exchange_failed", "Sign-in could not be completed") from None
    if not body.get("id_token"):
        raise err(502, "token_exchange_failed", "Sign-in could not be completed")
    return {"access_token": body["id_token"], "token_type": "Bearer", "expires_in": min(int(body.get("expires_in", 3600)), 3600)}


@app.get("/", include_in_schema=False)
def root():
    return Response(status_code=302, headers={"Location": "/portal/"})


application_evidence.register_routes(app, sys.modules[__name__])


if _portal.is_dir():
    app.mount("/portal", StaticFiles(directory=str(_portal), html=True), name="portal")


# ---------- local development helpers (never mounted outside ENV=local with dev auth) ----------
if ENV == "local" and AUTH_MODE == "dev":
    @app.get("/v1/dev/users")
    def dev_users():
        return {"items": [{"sub": s, "roles": u["roles"], "tenant_id": u["tenant_id"], "token": issue_token(s)}
                          for s, u in STORE.users.items()]}
