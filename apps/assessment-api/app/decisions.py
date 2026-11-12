"""TrustOps policy decision point.

Connected applications ask TrustOps before a consequential action:
    POST /v1/decisions   (header X-TrustOps-Key: the key issued when the application was registered)
TrustOps evaluates the tenant's policy rules in order and returns ALLOW, ESCALATE or DENY with the
policy that decided and a reason. Every decision is appended to a per-tenant SHA-256 hash chain.
ESCALATE decisions wait for a person (maker-checker: the requesting actor can never resolve its own).

Administrators can also run a decision from the UI ("simulate"); those records are flagged simulated.
Local storage: SQLite in the server data directory. Records are hash-chained, not KMS signed.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import threading
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Response

ADMIN = {"customer_admin", "cloudseals_admin"}
APPROVERS = {"customer_controller", "customer_admin"}
READ = ADMIN | APPROVERS | {"customer_architect", "customer_risk", "auditor_readonly", "cloudseals_platform_ops",
                            "cloudseals_reviewer", "customer_viewer", "customer_operator"}
DECISIONS = ("ALLOW", "ESCALATE", "DENY")

DEFAULT_RULES = [
    {"id": "FIN-00", "name": "Items submitted for review are approved in TrustOps", "actions": ["submit_for_review"],
     "actor_types": [], "min_amount_minor": None, "decision": "ESCALATE",
     "reason": "Submitted for approval", "enabled": True},
    {"id": "LS-01", "name": "Never post, pay, email clients or change credentials", "actions": ["ledger.post", "bank.payment", "email.send", "model_route.change", "credential.manage"],
     "actor_types": [], "min_amount_minor": None, "decision": "DENY",
     "reason": "Outside the product boundary: no postings, payments, client emails or credential changes", "enabled": True},
    {"id": "LS-02", "name": "Reconciliation agents may do their registered work", "actions": ["upload.parse", "upload.verify", "document.extract",
     "mapping.propose", "canonical.verify", "run.compute", "exception.triage", "exception.route", "report.compose", "query.index", "query.answer"],
     "actor_types": ["agent"], "min_amount_minor": None, "decision": "ALLOW",
     "reason": "Registered agent tool within the delegating person's scope", "enabled": True},
    {"id": "FIN-01", "name": "Agents never post ledger entries", "actions": ["post_journal_entry", "post_entry"],
     "actor_types": ["agent"], "min_amount_minor": None, "decision": "DENY",
     "reason": "Posting to the ledger is reserved for people", "enabled": True},
    {"id": "FIN-02", "name": "No outbound client email from agents", "actions": ["email_client", "send_external_email"],
     "actor_types": ["agent"], "min_amount_minor": None, "decision": "DENY",
     "reason": "Agents may not contact clients directly", "enabled": True},
    {"id": "FIN-03", "name": "No changes to policies or permissions from applications", "actions": ["change_policy", "grant_permission"],
     "actor_types": [], "min_amount_minor": None, "decision": "DENY",
     "reason": "Policies and permissions are managed only in TrustOps", "enabled": True},
    {"id": "FIN-04", "name": "Large or unknown deposits need a person", "actions": ["approve_match", "allocate_cash", "classify_deposit"],
     "actor_types": [], "min_amount_minor": 100000, "decision": "ESCALATE",
     "reason": "Amount is above the approval limit", "enabled": True},
    {"id": "FIN-05", "name": "Routine matches within limit", "actions": ["approve_match", "allocate_cash", "classify_deposit"],
     "actor_types": [], "min_amount_minor": None, "decision": "ALLOW",
     "reason": "Within the approval limit", "enabled": True},
    {"id": "FIN-06", "name": "Read-only access", "actions": ["read", "summarise", "generate_report"],
     "actor_types": [], "min_amount_minor": None, "decision": "ALLOW",
     "reason": "Read-only actions are permitted", "enabled": True},
]
DEFAULT_ID = "DEFAULT"


def _err(status, code, message):
    return HTTPException(status, {"code": code, "message": message})


def digest(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class _Mem:
    def __init__(self):
        self.lock = threading.RLock()
        self.decisions, self.policy_rules, self.agents, self.users, self.audit = [], {}, {}, {}, []


class DecisionStore:
    """Decisions and rules live in the shared Store (persisted with the rest of TrustOps state)."""

    def __init__(self, state=None):
        self.state = state if state is not None else _Mem()

    def rules(self, tenant):
        with self.state.lock:
            r = self.state.policy_rules.get(tenant)
        return [dict(x) for x in r] if r else [dict(x) for x in DEFAULT_RULES]

    def set_rules(self, tenant, rules):
        with self.state.lock:
            self.state.policy_rules[tenant] = [dict(x) for x in rules]

    def append(self, tenant, record):
        with self.state.lock:
            mine = [r for r in self.state.decisions if r["tenant_id"] == tenant]
            record["tenant_id"] = tenant
            record["previous_hash"] = mine[-1]["record_hash"] if mine else "0" * 64
            record["sequence"] = len(mine) + 1
            record["record_hash"] = digest({k: v for k, v in record.items() if k not in ("record_hash", "resolution", "loaded_details")})
            self.state.decisions.append(record)
        return dict(record)

    def update(self, tenant, record):
        with self.state.lock:
            for i, r in enumerate(self.state.decisions):
                if r["tenant_id"] == tenant and r["id"] == record["id"]:
                    self.state.decisions[i] = record
                    return

    def all(self, tenant):
        with self.state.lock:
            return [dict(r) for r in self.state.decisions if r["tenant_id"] == tenant]

    def get(self, tenant, did):
        with self.state.lock:
            return next((dict(r) for r in self.state.decisions if r["tenant_id"] == tenant and r["id"] == did), None)

    # authority registry
    @staticmethod
    def agent_id(tenant, app_id, actor_type, actor_id):
        return "agt_" + hashlib.sha256(f"{tenant}|{app_id}|{actor_type}|{actor_id}".encode()).hexdigest()[:14]

    def agent(self, tenant, aid):
        with self.state.lock:
            a = self.state.agents.get(aid)
        return dict(a) if a and a["tenant_id"] == tenant else None

    def agents(self, tenant):
        with self.state.lock:
            return [dict(a) for a in self.state.agents.values() if a["tenant_id"] == tenant]

    def touch_agent(self, tenant, application, actor):
        aid = self.agent_id(tenant, application["id"], actor["type"], actor["id"])
        with self.state.lock:
            a = self.state.agents.get(aid)
            if not a:
                a = self.state.agents[aid] = {"id": aid, "tenant_id": tenant, "application": dict(application), "actor_type": actor["type"],
                                              "actor_id": actor["id"], "status": "active", "owner": None, "allowed_clients": [],
                                              "first_seen": time.time(), "last_seen": None, "counts": {d: 0 for d in DECISIONS}}
            return dict(a)

    def count_agent(self, aid, decision):
        with self.state.lock:
            a = self.state.agents.get(aid)
            if a:
                a["last_seen"] = time.time()
                a["counts"][decision] = a["counts"].get(decision, 0) + 1

    def save_agent(self, a):
        with self.state.lock:
            self.state.agents[a["id"]] = a


def parse_details(body):
    """Validate the review details an application sends (at submission or when TrustOps loads them)."""
    link = str(body.get("link") or "").strip()
    if link and (not link.startswith("https://") or len(link) > 500 or any(ch in link for ch in ' "<>')):
        raise _err(422, "invalid_link", "link must be an https:// address of the item in the application")
    facts = body.get("facts") or []
    if not isinstance(facts, list) or len(facts) > 30 or not all(isinstance(f, dict) and str(f.get("label", "")).strip() for f in facts):
        raise _err(422, "invalid_facts", "facts must be a list of up to 30 {label, value} items")
    lines = body.get("lines")
    if lines is not None:
        cols, rows = lines.get("columns") if isinstance(lines, dict) else None, lines.get("rows") if isinstance(lines, dict) else None
        if not isinstance(cols, list) or not 1 <= len(cols) <= 8 or not isinstance(rows, list) or len(rows) > 50 \
                or not all(isinstance(r, list) and len(r) == len(cols) for r in rows):
            raise _err(422, "invalid_lines", "lines must be {columns: [...up to 8], rows: [[...], ...up to 50]} with one value per column")
        lines = {"title": str(lines.get("title") or "")[:80] or None, "columns": [str(c)[:40] for c in cols],
                 "rows": [[str(v)[:200] for v in r] for r in rows]}
    compare = body.get("compare")
    if compare is not None:
        rows = compare.get("rows") if isinstance(compare, dict) else None
        if not isinstance(rows, list) or not 1 <= len(rows) <= 30 or not all(isinstance(r, list) and len(r) == 3 for r in rows):
            raise _err(422, "invalid_compare", "compare must be {left_title, right_title, rows: [[field, left, right], ...up to 30]}")
        compare = {"left_title": str(compare.get("left_title") or "Source")[:60], "right_title": str(compare.get("right_title") or "Match")[:60],
                   "rows": [[str(v)[:200] for v in r] for r in rows]}
    docs = body.get("documents") or []
    if not isinstance(docs, list) or len(docs) > 20 or not all(isinstance(x, dict) and str(x.get("url", "")).startswith("https://") and len(str(x["url"])) <= 500 for x in docs):
        raise _err(422, "invalid_documents", "documents must be a list of up to 20 {name, url} with https:// urls")
    details = {"title": str(body.get("title") or "")[:140] or None, "summary": str(body.get("summary") or "")[:1000] or None,
               "link": link or None, "compare": compare,
               "recommendation": str(body.get("recommendation") or "")[:500] or None,
               "consequence": str(body.get("consequence") or "")[:500] or None,
               "documents": [{"name": str(x.get("name") or "Document")[:120], "url": str(x["url"])} for x in docs],
               "facts": [{"label": str(f["label"])[:60], "value": str(f.get("value", ""))[:500]} for f in facts],
               "lines": lines}
    return details


def evaluate(rules, actor_type, action, amount_minor):
    for rule in rules:
        if not rule.get("enabled", True) or action not in rule.get("actions", []):
            continue
        if rule.get("actor_types") and actor_type not in rule["actor_types"]:
            continue
        limit = rule.get("min_amount_minor")
        if limit is not None and (amount_minor is None or amount_minor <= limit):
            continue
        return rule["decision"], rule["id"], rule["reason"]
    return "ESCALATE", DEFAULT_ID, "No rule covers this action, so a person must decide"


def verify_chain(records):
    prev = "0" * 64
    for i, r in enumerate(records, 1):
        expected = digest({k: v for k, v in r.items() if k not in ("record_hash", "resolution", "loaded_details")})
        if r["previous_hash"] != prev or r["record_hash"] != expected or r["sequence"] != i:
            return {"valid": False, "checked": i, "broken_at": r["id"]}
        prev = r["record_hash"]
    return {"valid": True, "checked": len(records), "head": prev}


def stats(records):
    real = [r for r in records if not r.get("simulated") and not r["action"].startswith("resolve_escalation:") and r["action"] != "load_review_details"]
    n = len(real)
    count = {d: sum(r["decision"] == d for r in real) for d in DECISIONS}
    by_actor = {}
    for r in real:
        if r["decision"] == "DENY":
            k = f'{r["actor"]["type"]}:{r["actor"]["id"]}'
            by_actor[k] = by_actor.get(k, 0) + 1
    by_app = {}
    for r in real:
        by_app.setdefault(r["application"]["name"], {d: 0 for d in DECISIONS})[r["decision"]] += 1
    by_policy = {}
    for r in real:
        by_policy[r["policy_id"]] = by_policy.get(r["policy_id"], 0) + 1
    return {"total": n, "simulated": sum(bool(r.get("simulated")) for r in records), "counts": count,
            "escalation_rate": round(count["ESCALATE"] / n, 3) if n else None,
            "deny_rate": round(count["DENY"] / n, 3) if n else None,
            "pending_approvals": sum(r["decision"] == "ESCALATE" and not r.get("resolution") for r in records),
            "repeated_denials": [{"actor": k, "denials": v} for k, v in sorted(by_actor.items(), key=lambda x: -x[1]) if v >= 3],
            "by_application": by_app, "by_policy": by_policy,
            "cost_per_run": None, "cost_note": "Model cost is not tracked yet"}


def render_pdf(tenant_name, generated_by, records, rules, verification):
    """Governance report as PDF: summary, policies, items needing attention, decision log, integrity."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, PageBreak

    ink, panel, line = colors.HexColor("#172B4D"), colors.HexColor("#F0F3F9"), colors.HexColor("#E6EAF1")
    tone = {"ALLOW": colors.HexColor("#067647"), "ESCALATE": colors.HexColor("#B54708"), "DENY": colors.HexColor("#B42318")}
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("h1", parent=ss["Title"], textColor=ink, alignment=0, fontSize=22, spaceAfter=4)
    H2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=ink, fontSize=13, spaceBefore=10, spaceAfter=6)
    B = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12, textColor=colors.HexColor("#344054"))
    S = ParagraphStyle("s", parent=B, fontSize=7.5, leading=9.5)
    esc = lambda t: (str(t if t is not None else "–")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    when = lambda t: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t))
    amt = lambda r: "–" if r.get("amount_minor") is None else f'{r["amount_minor"] / 100:,.2f} {r.get("currency") or ""}'
    fin = lambda r: ({"approve": "APPROVED", "reject": "REJECTED"}[r["resolution"]["outcome"]] if r.get("resolution")
                     else "PENDING" if r["decision"] == "ESCALATE" else r["decision"])

    def grid(data, widths, header=True):
        t = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
        st = [("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
              ("LINEBELOW", (0, 0), (-1, -1), 0.4, line), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
        if header:
            st += [("BACKGROUND", (0, 0), (-1, 0), panel), ("TEXTCOLOR", (0, 0), (-1, 0), ink), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
        t.setStyle(TableStyle(st))
        return t

    real = [r for r in records if not r.get("simulated") and not r["action"].startswith("resolve_escalation:") and r["action"] != "load_review_details"]
    st = stats(records)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                            title="TrustOps governance report", author="CloudSeals TrustOps")

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#667085"))
        canvas.drawString(14 * mm, 8 * mm, f"CloudSeals TrustOps · Governance report · {esc(tenant_name)} · Records describe recorded activity only; this is not a compliance certification.")
        canvas.drawRightString(landscape(A4)[0] - 14 * mm, 8 * mm, f"Page {d.page}")
        canvas.restoreState()

    story = [Paragraph("TrustOps governance report", H1),
             Paragraph(f"{esc(tenant_name)} · generated {when(time.time())} by {esc(generated_by)}", B), Spacer(1, 8)]
    pct = lambda x: "–" if x is None else f"{round(x * 100)}%"
    story += [Paragraph("Summary", H2), grid([
        ["Decisions recorded", str(st["total"]), "Allowed", str(st["counts"]["ALLOW"])],
        ["Escalated to a person", f'{st["counts"]["ESCALATE"]} ({pct(st["escalation_rate"])})', "Denied", f'{st["counts"]["DENY"]} ({pct(st["deny_rate"])})'],
        ["Still waiting for a person", str(st["pending_approvals"]), "Simulated tests (excluded)", str(st["simulated"])],
        ["Evidence chain", ("Intact" if verification["valid"] else f'Broken at {verification.get("broken_at")}') + f' · {verification["checked"]} records',
         "Integrity", "SHA-256 hash chain (not KMS signed)"],
        ["Cost per run", "Not tracked yet", "Applications", ", ".join(st["by_application"]) or "–"],
    ], [55 * mm, 80 * mm, 55 * mm, 80 * mm], header=False)]
    if st["repeated_denials"]:
        story += [Paragraph("Repeated denials (3 or more)", H2),
                  grid([["Actor", "Denials"]] + [[esc(x["actor"]), str(x["denials"])] for x in st["repeated_denials"]], [120 * mm, 30 * mm])]
    story += [Paragraph("Policies in force", H2), grid([["On", "ID", "Rule", "Actions", "Who", "Amount limit", "Decision"]] + [
        ["Yes" if r.get("enabled", True) else "No", r["id"], Paragraph(esc(r["name"]), S), Paragraph(esc(", ".join(r["actions"])), S),
         ", ".join(r.get("actor_types") or []) or "anyone",
         "–" if r.get("min_amount_minor") is None else f'above {r["min_amount_minor"] / 100:,.2f}', r["decision"]] for r in rules],
        [12 * mm, 20 * mm, 70 * mm, 75 * mm, 25 * mm, 30 * mm, 25 * mm])]
    attention = [r for r in real if r["decision"] in ("ESCALATE", "DENY")]
    story += [Paragraph(f"Escalations and denials ({len(attention)})", H2)]
    story += [grid([["Time", "Application", "Actor", "Action", "Amount", "Decision", "Policy", "Outcome", "Resolved by"]] + [
        [when(r["at"]), Paragraph(esc(r["application"]["name"]), S), Paragraph(esc(f'{r["actor"]["type"]}: {r["actor"]["id"]}'), S),
         Paragraph(esc(r["action"]), S), amt(r), r["decision"], r["policy_id"], fin(r),
         Paragraph(esc((r.get("resolution") or {}).get("by", "")), S)] for r in attention],
        [30 * mm, 35 * mm, 38 * mm, 38 * mm, 25 * mm, 20 * mm, 22 * mm, 22 * mm, 38 * mm])] if attention else [Paragraph("None.", B)]
    story += [PageBreak(), Paragraph(f"Decision log ({len(records)} records, including resolutions and simulated tests)", H2)]
    rows = [["#", "Time", "Application", "Actor", "Action", "Client", "Amount", "Decision", "Policy", "Reason", "Record hash"]]
    for r in records:
        rows.append([str(r["sequence"]), when(r["at"]), Paragraph(esc(r["application"]["name"]), S),
                     Paragraph(esc(f'{r["actor"]["type"]}: {r["actor"]["id"]}'), S), Paragraph(esc(r["action"]), S),
                     Paragraph(esc(r.get("client")), S), amt(r), r["decision"], r["policy_id"], Paragraph(esc(r["reason"]), S),
                     Paragraph(r["record_hash"][:16] + "…", S)])
    log = grid(rows, [9 * mm, 28 * mm, 30 * mm, 32 * mm, 30 * mm, 20 * mm, 22 * mm, 18 * mm, 22 * mm, 40 * mm, 24 * mm])
    log.setStyle(TableStyle([("TEXTCOLOR", (7, i), (7, i), tone.get(rows[i][7], ink)) for i in range(1, len(rows))]))
    story += [log, Spacer(1, 10), Paragraph("Integrity", H2), Paragraph(
        "Each record stores the SHA-256 hash of the previous record. Changing any record breaks every hash after it. "
        f"Verification at generation time: {'intact' if verification['valid'] else 'BROKEN'} across {verification['checked']} records. "
        "Records are not signed with a cloud KMS key in this environment. The JSON audit pack contains the full records for independent re-verification.", B)]
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


def _public(r):
    return r


def make_router(principal, find_integration_by_key, audit=None, identity=None, store=None, state=None, tenant_name=None, integrations=None):
    router = APIRouter(tags=["Decisions"])
    db = store or DecisionStore(state)

    def need(p, roles, msg="Not permitted"):
        if not p.tenant_id or not set(p.roles) & roles:
            raise _err(403, "forbidden", msg)

    def decide(tenant, application, body, simulated, by=None):
        actor = body.get("actor") or {}
        a_type, a_id = str(actor.get("type", "")).strip(), str(actor.get("id", "")).strip()
        action = str(body.get("action", "")).strip()
        if a_type not in ("agent", "human", "service") or not a_id or not action or len(action) > 80:
            raise _err(422, "invalid_request", "actor.type (agent|human|service), actor.id and action are required")
        amount = body.get("amount_minor")
        if amount is not None and (not isinstance(amount, int) or amount < 0):
            raise _err(422, "invalid_amount", "amount_minor must be a non-negative integer")
        client = str(body.get("client", ""))[:120] or None
        details = parse_details(body)
        ident = None if simulated else db.touch_agent(tenant, application, {"type": a_type, "id": a_id[:120]})
        if ident and ident["status"] == "suspended":
            decision, policy, reason = "DENY", "AUTH-SUSPENDED", "This identity is suspended in the TrustOps authority registry"
        elif ident and ident["allowed_clients"] and client not in ident["allowed_clients"]:
            decision, policy, reason = "DENY", "AUTH-SCOPE", "This identity is not authorised for this client"
        else:
            decision, policy, reason = evaluate(db.rules(tenant), a_type, action, amount)
        rec = {"id": "dec_" + uuid.uuid4().hex[:16], "at": time.time(), "tenant_id": tenant,
               "application": application, "actor": {"type": a_type, "id": a_id[:120]},
               "action": action, "resource": str(body.get("resource", ""))[:200] or None,
               "client": str(body.get("client", ""))[:120] or None, "amount_minor": amount,
               "currency": str(body.get("currency", ""))[:3] or None,
               "context": {k: v for k, v in (body.get("context") or {}).items() if isinstance(v, (str, int, float, bool))} if isinstance(body.get("context"), dict) else {},
               "details": details,
               "decision": decision, "policy_id": policy, "reason": reason,
               "simulated": simulated, "requested_by": by}
        rec = db.append(tenant, rec)
        if ident:
            db.count_agent(ident["id"], decision)
        return {"decision_id": rec["id"], "decision": decision, "policy_id": policy, "reason": reason,
                "status": "pending_approval" if decision == "ESCALATE" else "final",
                "evidence_hash": rec["record_hash"], "evidence_sequence": rec["sequence"]}

    # ---- applications call this ----
    @router.post("/v1/decisions")
    def app_decision(body: dict = Body(...), x_trustops_key: Optional[str] = Header(default=None)):
        found = find_integration_by_key(x_trustops_key or "")
        if not found:
            raise _err(401, "invalid_key", "A valid X-TrustOps-Key is required")
        tenant, integ = found
        return decide(tenant, {"id": integ["id"], "name": integ["name"]}, body, False)

    @router.get("/v1/decisions/{did}/status")
    def app_status(did: str, x_trustops_key: Optional[str] = Header(default=None)):
        found = find_integration_by_key(x_trustops_key or "")
        if not found:
            raise _err(401, "invalid_key", "A valid X-TrustOps-Key is required")
        r = db.get(found[0], did)
        if not r or r["application"]["id"] != found[1]["id"]:
            raise _err(404, "not_found", "Decision not found")
        res = r.get("resolution")
        return {"decision_id": did, "decision": r["decision"], "policy_id": r["policy_id"],
                "final": ({"approve": "APPROVED", "reject": "REJECTED"}[res["outcome"]] if res else ("PENDING" if r["decision"] == "ESCALATE" else r["decision"])),
                "resolved_by": res["by"] if res else None, "resolved_at": res["at"] if res else None,
                "resolution_reason": res["reason"] if res else None}

    # ---- console ----
    @router.post("/v1/decisions/simulate")
    def simulate(body: dict = Body(...), p=Depends(principal)):
        need(p, ADMIN, "Only a workspace administrator can test policies")
        out = decide(p.tenant_id, {"id": "simulator", "name": "Policy test (simulated)"}, body, True,
                     identity(p) if identity else p.sub)
        if audit:
            audit(p, "decision.simulate", out["decision_id"])
        return out

    @router.get("/v1/decisions")
    def list_decisions(decision: Optional[str] = None, q: Optional[str] = None, application: Optional[str] = None,
                       pending: bool = False, include_simulated: bool = True, limit: int = Query(200, ge=1, le=1000),
                       p=Depends(principal)):
        need(p, READ)
        rows = list(reversed(db.all(p.tenant_id)))
        if decision:
            rows = [r for r in rows if r["decision"] == decision.upper()]
        if application:
            rows = [r for r in rows if r["application"]["id"] == application]
        if pending:
            rows = [r for r in rows if r["decision"] == "ESCALATE" and not r.get("resolution")]
        if not include_simulated:
            rows = [r for r in rows if not r.get("simulated")]
        if q:
            ql = q.lower()
            rows = [r for r in rows if ql in json.dumps(r).lower()]
        return {"items": rows[:limit], "total": len(rows)}

    @router.get("/v1/decisions/{did}")
    def one(did: str, p=Depends(principal)):
        need(p, READ)
        r = db.get(p.tenant_id, did)
        if not r:
            raise _err(404, "not_found", "Decision not found")
        return r

    @router.post("/v1/decisions/{did}/resolve")
    def resolve(did: str, body: dict = Body(...), p=Depends(principal)):
        need(p, APPROVERS, "Only a controller or administrator can resolve escalations")
        r = db.get(p.tenant_id, did)
        if not r:
            raise _err(404, "not_found", "Decision not found")
        if r["decision"] != "ESCALATE" or r.get("resolution"):
            raise _err(409, "not_pending", "This decision is not waiting for a person")
        who = identity(p) if identity else p.sub
        if who == r["actor"]["id"] or p.sub == r["actor"]["id"] or who == r.get("requested_by"):
            raise _err(403, "maker_checker_violation", "The requester cannot approve their own action")
        outcome, reason = body.get("outcome"), str(body.get("reason", "")).strip()
        if outcome not in ("approve", "reject") or not reason:
            raise _err(422, "invalid_request", "outcome (approve|reject) and a reason are required")
        d = r.get("details") or {}
        ld = r.get("loaded_details") or {}
        has_details = bool(d.get("facts") or d.get("lines") or d.get("compare") or ld.get("facts") or ld.get("lines") or ld.get("compare"))
        checked = bool(body.get("checked_in_app"))
        if outcome == "approve" and not has_details and not (checked and d.get("link")):
            raise _err(409, "details_required", "This item has no details. Check it in the application (link required) or reject it and ask for details")
        r["resolution"] = {"outcome": outcome, "reason": reason[:2000], "by": who, "at": time.time(),
                           "basis": "details_in_trustops" if has_details else ("checked_in_application" if checked else "none")}
        db.update(p.tenant_id, r)
        db.append(p.tenant_id, {"id": "dec_" + uuid.uuid4().hex[:16], "at": time.time(), "tenant_id": p.tenant_id,
                                "application": r["application"], "actor": {"type": "human", "id": who},
                                "action": f"resolve_escalation:{outcome}", "resource": did, "client": r.get("client"),
                                "amount_minor": r.get("amount_minor"), "currency": r.get("currency"), "context": {"reason": reason[:500]},
                                "decision": "ALLOW", "policy_id": "MAKER-CHECKER",
                                "reason": f"Escalation {did} {outcome}d by a different person",
                                "simulated": r.get("simulated", False), "requested_by": who})
        if audit:
            audit(p, f"decision.resolve.{outcome}", did)
        return r

    @router.get("/v1/decisions-stats")
    def get_stats(p=Depends(principal)):
        need(p, READ)
        return stats(db.all(p.tenant_id))

    @router.get("/v1/decisions-verify")
    def verify(p=Depends(principal)):
        need(p, READ)
        return {**verify_chain(db.all(p.tenant_id)), "integrity": "sha256_hash_chain",
                "signed": False, "note": "Records are hash-chained; they are not KMS signed in this environment."}

    @router.get("/v1/decisions-export")
    def export(fmt: str = Query("json", pattern="^(json|csv|pdf)$"), p=Depends(principal)):
        need(p, READ)
        records = db.all(p.tenant_id)
        if audit:
            audit(p, "decision.export", fmt)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if fmt == "pdf":
            body = render_pdf(tenant_name(p.tenant_id) if tenant_name else p.tenant_id, identity(p) if identity else p.sub,
                              records, db.rules(p.tenant_id), verify_chain(records))
            return Response(body, media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="trustops-governance-report-{stamp}.pdf"'})
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["sequence", "decision_id", "time_utc", "application", "actor_type", "actor_id", "action", "client",
                        "amount_minor", "currency", "decision", "policy_id", "reason", "final", "resolved_by", "simulated", "record_hash"])
            for r in records:
                res = r.get("resolution") or {}
                w.writerow([r["sequence"], r["id"], time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["at"])), r["application"]["name"],
                            r["actor"]["type"], r["actor"]["id"], r["action"], r.get("client") or "", r.get("amount_minor") if r.get("amount_minor") is not None else "",
                            r.get("currency") or "", r["decision"], r["policy_id"], r["reason"],
                            {"approve": "APPROVED", "reject": "REJECTED"}.get(res.get("outcome"), "") or ("PENDING" if r["decision"] == "ESCALATE" else r["decision"]),
                            res.get("by", ""), r.get("simulated", False), r["record_hash"]])
            return Response(buf.getvalue(), media_type="text/csv",
                            headers={"Content-Disposition": f'attachment; filename="trustops-decisions-{stamp}.csv"'})
        pack = {"format": "trustops.audit-pack.v1", "generated_at": time.time(), "tenant_id": p.tenant_id,
                "generated_by": identity(p) if identity else p.sub, "verification": verify_chain(records),
                "integrity": "sha256_hash_chain (not KMS signed)", "policies": db.rules(p.tenant_id),
                "summary": stats(records), "records": records}
        return Response(json.dumps(pack, indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="trustops-audit-pack-{stamp}.json"'})

    @router.get("/v1/policies")
    def get_rules(p=Depends(principal)):
        need(p, READ)
        return {"rules": db.rules(p.tenant_id), "default": {"decision": "ESCALATE", "policy_id": DEFAULT_ID},
                "can_edit": bool(set(p.roles) & ADMIN)}

    @router.put("/v1/policies")
    def put_rules(body: dict = Body(...), p=Depends(principal)):
        need(p, ADMIN, "Only a workspace administrator can change policies")
        rules = body.get("rules")
        if not isinstance(rules, list) or not 1 <= len(rules) <= 100:
            raise _err(422, "invalid_rules", "Provide 1–100 rules")
        clean, seen = [], set()
        for r in rules:
            rid = str(r.get("id", "")).strip()
            acts = [str(a).strip() for a in r.get("actions", []) if str(a).strip()]
            if not rid or rid in seen or not acts or r.get("decision") not in DECISIONS:
                raise _err(422, "invalid_rule", f"Rule {rid or '?'} needs a unique id, actions and a decision")
            limit = r.get("min_amount_minor")
            if limit not in (None, "") and (not isinstance(limit, int) or limit < 0):
                raise _err(422, "invalid_rule", f"Rule {rid}: amount limit must be a whole number")
            seen.add(rid)
            clean.append({"id": rid[:20], "name": str(r.get("name", rid))[:120], "actions": acts[:20],
                          "actor_types": [a for a in r.get("actor_types", []) if a in ("agent", "human", "service")],
                          "min_amount_minor": None if limit in (None, "") else limit, "decision": r["decision"],
                          "reason": str(r.get("reason", ""))[:200] or r["decision"].title(), "enabled": bool(r.get("enabled", True))})
        db.set_rules(p.tenant_id, clean)
        if audit:
            audit(p, "policy.update", ",".join(x["id"] for x in clean))
        return {"rules": clean}

    @router.post("/v1/policies/reset")
    def reset_rules(p=Depends(principal)):
        need(p, ADMIN, "Only a workspace administrator can change policies")
        db.set_rules(p.tenant_id, [dict(x) for x in DEFAULT_RULES])
        if audit:
            audit(p, "policy.reset", p.tenant_id)
        return {"rules": db.rules(p.tenant_id)}


    # ---- authority registry ----
    ROLE_CAPS = {
        "customer_admin": ("Administrator", ["View everything", "Register applications and rotate keys", "Edit policies", "Suspend agents and set client scope", "Resolve escalations"]),
        "customer_controller": ("Controller / approver", ["View everything", "Resolve escalations (never their own)"]),
        "customer_risk": ("Risk reviewer", ["View everything"]),
        "customer_architect": ("Technical user", ["View everything"]),
        "customer_operator": ("Operator", ["View everything"]),
        "customer_viewer": ("Viewer / auditor", ["View everything"]),
        "auditor_readonly": ("Auditor (read only)", ["View everything"]),
        "customer_contributor": ("Contributor", ["No governance access"]),
    }

    @router.get("/v1/authority")
    def authority(p=Depends(principal)):
        need(p, READ)
        rules = db.rules(p.tenant_id)
        actions = sorted({a for r in rules for a in r["actions"]})

        def cell(actor_type, action):
            parts = []
            for r in rules:
                if not r.get("enabled", True) or action not in r["actions"] or (r.get("actor_types") and actor_type not in r["actor_types"]):
                    continue
                if r.get("min_amount_minor") is None:
                    parts.append({"decision": r["decision"], "policy_id": r["id"], "when": "always" if not parts else "otherwise"})
                    break
                parts.append({"decision": r["decision"], "policy_id": r["id"], "when": f'above {r["min_amount_minor"] / 100:,.2f}'})
            return parts or [{"decision": "ESCALATE", "policy_id": DEFAULT_ID, "when": "no rule"}]
        users = getattr(db.state, "users", {})
        people = []
        for sub, u in users.items():
            if u.get("tenant_id") != p.tenant_id:
                continue
            roles = u.get("roles", [])
            caps = []
            for r in roles:
                caps += [c for c in ROLE_CAPS.get(r, (r, []))[1] if c not in caps]
            people.append({"user": u.get("email") or sub, "roles": [ROLE_CAPS.get(r, (r,))[0] for r in roles], "can": caps,
                           "client_scope": "All clients"})
        history = [e for e in getattr(db.state, "audit", []) if e.get("tenant_id") == p.tenant_id and
                   str(e.get("action", "")).startswith(("policy.", "authority.", "integration.", "decision.resolve"))][-100:]
        return {"agents": sorted(db.agents(p.tenant_id), key=lambda a: -(a.get("last_seen") or a["first_seen"])),
                "people": sorted(people, key=lambda x: x["user"]),
                "matrix": {"actor_types": ["agent", "human", "service"], "actions": actions,
                           "cells": {f"{t}|{a}": cell(t, a) for t in ("agent", "human", "service") for a in actions}},
                "separation_of_duties": [
                    "The person or agent that requested an escalated action can never approve it.",
                    "Only controllers and administrators can resolve escalations.",
                    "Only administrators can change policies, permissions, agents or applications — and only in TrustOps.",
                    "Applications cannot change policies or permissions (rule FIN-03 denies it)."],
                "history": list(reversed(history)), "can_edit": bool(set(p.roles) & ADMIN)}

    @router.patch("/v1/authority/agents/{aid}")
    def update_agent(aid: str, body: dict = Body(...), p=Depends(principal)):
        need(p, ADMIN, "Only a workspace administrator can change agent authority")
        a = db.agent(p.tenant_id, aid)
        if not a:
            raise _err(404, "not_found", "Agent not found")
        changes = []
        if "status" in body:
            if body["status"] not in ("active", "suspended"):
                raise _err(422, "invalid_status", "status must be active or suspended")
            reason = str(body.get("reason", "")).strip()
            if body["status"] == "suspended" and not reason:
                raise _err(422, "reason_required", "Give a reason for suspending this agent")
            if body["status"] != a["status"]:
                a["status"] = body["status"]
                a["status_changed"] = {"by": identity(p) if identity else p.sub, "at": time.time(), "reason": reason[:300] or None}
                changes.append(f"status={a['status']}")
        if "owner" in body:
            a["owner"] = str(body["owner"] or "").strip()[:120] or None
            changes.append("owner")
        if "allowed_clients" in body:
            cl = body["allowed_clients"]
            if not isinstance(cl, list) or len(cl) > 200 or not all(isinstance(x, str) and 0 < len(x.strip()) <= 120 for x in cl):
                raise _err(422, "invalid_scope", "allowed_clients must be a list of client IDs (empty = all clients)")
            a["allowed_clients"] = sorted({x.strip() for x in cl})
            changes.append("client_scope")
        db.save_agent(a)
        if audit and changes:
            audit(p, "authority.agent." + "+".join(changes), f'{a["actor_id"]}@{a["application"]["name"]}')
        return a


    # ---- risk: what needs attention ----
    @router.get("/v1/risk")
    def risk(p=Depends(principal)):
        need(p, READ)
        now = time.time()
        day, week = now - 86400, now - 7 * 86400
        recs = [r for r in db.all(p.tenant_id) if not r.get("simulated") and not r["action"].startswith("resolve_escalation:") and r["action"] != "load_review_details"]
        agents = {a["id"]: a for a in db.agents(p.tenant_id)}
        watch = []
        for a in agents.values():
            mine = [r for r in recs if r["application"]["id"] == a["application"]["id"] and r["actor"]["id"] == a["actor_id"]
                    and r["actor"]["type"] == a["actor_type"]]
            d24 = [r for r in mine if r["decision"] == "DENY" and r["at"] >= day]
            d7 = [r for r in mine if r["decision"] == "DENY" and r["at"] >= week]
            e24 = [r for r in mine if r["decision"] == "ESCALATE" and r["at"] >= day]
            if not d7 and len(e24) < 3:
                continue
            top = {}
            for r in d7 or e24:
                top[r["action"]] = top.get(r["action"], 0) + 1
            act = len(d24) >= 3
            watch.append({"agent_id": a["id"], "actor_id": a["actor_id"], "actor_type": a["actor_type"], "application": a["application"]["name"],
                          "status": a["status"], "level": "act" if act else "watch", "blocked_24h": len(d24), "blocked_7d": len(d7),
                          "escalated_24h": len(e24), "top_action": max(top, key=top.get),
                          "why": (f"blocked {len(d24)} times in 24 hours" if act else ("blocked once this week" if len(d7) == 1 else f"blocked {len(d7)} times this week") if d7
                                  else f"{len(e24)} escalations in 24 hours")})
        watch.sort(key=lambda x: (x["level"] != "act", -x["blocked_24h"], -x["blocked_7d"]))
        waiting = sorted([{"decision_id": r["id"], "title": (r.get("details") or {}).get("title") or r["action"].replace("_", " "),
                           "application": r["application"]["name"], "submitted_by": r["actor"]["id"], "hours": round((now - r["at"]) / 3600, 1)}
                          for r in db.all(p.tenant_id) if r["decision"] == "ESCALATE" and not r.get("resolution") and not r.get("simulated")],
                         key=lambda x: -x["hours"])
        late = [w for w in waiting if w["hours"] >= 24]
        trend = []
        for i in range(6, -1, -1):
            start = time.mktime(time.localtime(now)[:3] + (0, 0, 0, 0, 0, -1)) - i * 86400
            day_recs = [r for r in recs if start <= r["at"] < start + 86400]
            trend.append({"day": time.strftime("%a %d", time.localtime(start)), **{d: sum(r["decision"] == d for r in day_recs) for d in DECISIONS}})
        rules = {}
        for r in recs:
            if r["at"] >= week and r["decision"] != "ALLOW":
                k = (r["policy_id"], r["decision"])
                rules[k] = rules.get(k, 0) + 1
        week_recs = [r for r in recs if r["at"] >= week]
        esc_rate = sum(r["decision"] == "ESCALATE" for r in week_recs) / len(week_recs) if week_recs else 0
        reasons = [f'{w["actor_id"]} {w["why"]}' for w in watch if w["level"] == "act" and w["status"] == "active"]
        reasons += [f"{len(late)} approval{'s' if len(late) != 1 else ''} waiting more than 24 hours"] if late else []
        level = "act" if reasons else "normal"
        if level == "normal":
            reasons = [f'{w["actor_id"]} {w["why"]}' for w in watch if w["status"] == "active"]
            if esc_rate > 0.3:
                reasons.append(f"{round(esc_rate * 100)}% of this week's requests needed a person")
            level = "watch" if reasons else "normal"
        return {"level": level, "reasons": reasons, "agents_to_watch": watch, "waiting": waiting, "waiting_too_long": late,
                "trend": trend, "top_rules": [{"policy_id": k[0], "decision": k[1], "count": v} for k, v in sorted(rules.items(), key=lambda x: -x[1])][:6],
                "thresholds": "Act now: an active agent blocked 3+ times in 24 hours, or an approval waiting 24+ hours. "
                              "Watch: any block this week, 3+ escalations in 24 hours, or more than 30% of requests escalated. "
                              "These are simple rules, not anomaly detection."}


    # ---- load review details from the application on demand ----
    @router.post("/v1/decisions/{did}/load-details")
    def load_details(did: str, p=Depends(principal)):
        need(p, APPROVERS | ADMIN, "Only approvers can load details")
        r = db.get(p.tenant_id, did)
        if not r:
            raise _err(404, "not_found", "Decision not found")
        if integrations is None:
            raise _err(503, "unavailable", "Application connections are not available")
        body, secret = integrations.get(p.tenant_id, r["application"]["id"])
        if not body:
            raise _err(409, "no_application", "The application that sent this item is no longer registered")
        if not body.get("base_url"):
            raise _err(409, "no_address", f"Set {body['name']}'s address in Applications to load details from it")
        from urllib.parse import quote
        from .app_integrations import authed_client
        ref = r.get("resource") or r["id"]
        url = body["base_url"] + body.get("details_path", "/trustops/items/{ref}").replace("{ref}", quote(str(ref), safe=""))
        try:
            c, kw = authed_client(body, secret)
            with c:
                resp = c.get(url, **kw)
            if resp.status_code != 200:
                raise _err(502, "app_error", f"{body['name']} answered HTTP {resp.status_code} for this item")
            if len(resp.content) > 262144:
                raise _err(502, "too_large", "The application returned too much data")
            loaded = parse_details(resp.json())
        except HTTPException:
            raise
        except Exception:
            raise _err(502, "app_unreachable", f"Could not load details from {body['name']}")
        who = identity(p) if identity else p.sub
        r["loaded_details"] = {**loaded, "loaded_by": who, "loaded_at": time.time(), "source": url, "digest": digest(loaded)}
        db.update(p.tenant_id, r)
        db.append(p.tenant_id, {"id": "dec_" + uuid.uuid4().hex[:16], "at": time.time(), "tenant_id": p.tenant_id,
                                "application": r["application"], "actor": {"type": "human", "id": who},
                                "action": "load_review_details", "resource": did, "client": r.get("client"),
                                "amount_minor": None, "currency": None, "context": {"details_digest": r["loaded_details"]["digest"]},
                                "details": None, "decision": "ALLOW", "policy_id": "REVIEW", "reason": f"Details for {did} loaded from {body['name']}",
                                "simulated": r.get("simulated", False), "requested_by": who})
        if audit:
            audit(p, "decision.load_details", did)
        return r

    return router
