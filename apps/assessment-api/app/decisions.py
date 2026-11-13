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

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, Response

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


# Fields that change after a record is written (who resolved it, details loaded later, who it is assigned to).
UNHASHED = ("record_hash", "resolution", "loaded_details", "assignment", "attachments")


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
            record["record_hash"] = digest({k: v for k, v in record.items() if k not in UNHASHED})
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
        expected = digest({k: v for k, v in r.items() if k not in UNHASHED})
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


def render_pdf(tenant_name, generated_by, records, rules, verification, scope=None):
    """Governance report as PDF (2026-11-13 layout): cover summary, outcomes, policies, items needing attention,
    the decision log and integrity. Every table spans the full text width; long values wrap inside their cell;
    times are UTC. `scope` describes a filtered download (who / what / when) and is printed under the title."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from reporting import LOGO_PNG, logo_header

    PAGE = landscape(A4)
    M = 14 * mm
    W = PAGE[0] - 2 * M                                   # usable width; every table is sized to exactly this
    ink, muted, line, band = colors.HexColor("#172B4D"), colors.HexColor("#5F6B80"), colors.HexColor("#E3E8F0"), colors.HexColor("#F2F5FA")
    tone = {"ALLOW": colors.HexColor("#0F7F52"), "ESCALATE": colors.HexColor("#9A6210"), "DENY": colors.HexColor("#C03D3D"),
            "APPROVED": colors.HexColor("#0F7F52"), "REJECTED": colors.HexColor("#C03D3D"), "PENDING": colors.HexColor("#9A6210")}
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("h1", parent=ss["Title"], textColor=ink, alignment=0, fontSize=22, leading=26, spaceAfter=2)
    H2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=ink, fontSize=13, leading=16, spaceBefore=12, spaceAfter=6, keepWithNext=1)
    B = ParagraphStyle("b", parent=ss["BodyText"], fontName="Helvetica", fontSize=9, leading=12, textColor=colors.HexColor("#344054"))
    S = ParagraphStyle("s", parent=B, fontSize=7.6, leading=9.6)
    SB = ParagraphStyle("sb", parent=S, fontName="Helvetica-Bold", textColor=ink)
    HD = ParagraphStyle("hd", parent=S, fontName="Helvetica-Bold", textColor=muted, fontSize=7.2, leading=9)
    MONO = ParagraphStyle("mono", parent=S, fontName="Courier", fontSize=7, leading=9, textColor=muted)
    KV = ParagraphStyle("kv", parent=B, fontSize=8, leading=10, textColor=muted)
    KN = ParagraphStyle("kn", parent=B, fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=ink)
    esc = lambda t: (str(t if t is not None else "–")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    when = lambda t: time.strftime("%d %b %Y %H:%M", time.gmtime(t)) if t else "–"
    amt = lambda r: "–" if r.get("amount_minor") is None else f'{r["amount_minor"] / 100:,.2f} {r.get("currency") or ""}'.strip()
    who = lambda r: (f'Agent {r["actor"]["id"].split(":", 1)[1]}' if r["actor"]["id"].startswith("agent:") else f'Agent {r["actor"]["id"]}') \
        if r["actor"]["type"] == "agent" else r["actor"]["id"]
    fin = lambda r: ({"approve": "APPROVED", "reject": "REJECTED"}[r["resolution"]["outcome"]] if r.get("resolution")
                     else "PENDING" if r["decision"] == "ESCALATE" else r["decision"])
    col = lambda word: f'<font color="{tone[word].hexval().replace("0x", "#")}"><b>{word}</b></font>' if word in tone else esc(word)
    P = lambda t, st=S: Paragraph(esc(t), st)

    def grid(head, rows, fracs, zebra=True):
        """A full-width table: `fracs` are relative column widths (they are scaled to the text width)."""
        tot = sum(fracs)
        t = Table([[Paragraph(h, HD) for h in head]] + rows, colWidths=[W * f / tot for f in fracs], repeatRows=1, hAlign="LEFT")
        st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
              ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
              ("BACKGROUND", (0, 0), (-1, 0), band), ("LINEBELOW", (0, 0), (-1, 0), 0.6, line), ("LINEBELOW", (0, 1), (-1, -1), 0.3, line)]
        if zebra:
            st += [("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FAFBFD")) for i in range(2, len(rows) + 1, 2)]
        t.setStyle(TableStyle(st))
        return t

    real = [r for r in records if not r.get("simulated") and not r["action"].startswith("resolve_escalation:") and r["action"] != "load_review_details"]
    st = stats(records)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=PAGE, leftMargin=M, rightMargin=M, topMargin=18 * mm, bottomMargin=15 * mm,
                            title="TrustOps governance report", author="CloudSeals TrustOps")

    def chrome(canvas, d, first):
        canvas.saveState()
        canvas.setStrokeColor(line)
        if not first:                                   # running header on every page after the first
            x = M
            try:
                if LOGO_PNG.is_file():
                    canvas.drawImage(str(LOGO_PNG), x, PAGE[1] - 12.5 * mm, width=6 * mm, height=6 * mm, mask="auto"); x += 8 * mm
            except Exception:
                pass
            canvas.setFont("Helvetica-Bold", 8.5); canvas.setFillColor(ink)
            canvas.drawString(x, PAGE[1] - 10.5 * mm, "TrustOps governance report")
            canvas.setFont("Helvetica", 8); canvas.setFillColor(muted)
            canvas.drawRightString(PAGE[0] - M, PAGE[1] - 10.5 * mm, f"{tenant_name} · generated {when(time.time())} UTC")
            canvas.line(M, PAGE[1] - 14 * mm, PAGE[0] - M, PAGE[1] - 14 * mm)
        canvas.line(M, 11 * mm, PAGE[0] - M, 11 * mm)
        fx = M
        try:
            if LOGO_PNG.is_file():
                canvas.drawImage(str(LOGO_PNG), fx, 6.2 * mm, width=4 * mm, height=4 * mm, mask="auto"); fx += 5.5 * mm
        except Exception:
            pass
        canvas.setFont("Helvetica", 7); canvas.setFillColor(muted)
        canvas.drawString(fx, 7.5 * mm, f"CloudSeals TrustOps · {tenant_name} · Records describe recorded activity only; this is not a compliance certification.")
        canvas.drawRightString(PAGE[0] - M, 7.5 * mm, f"Page {d.page}")
        canvas.restoreState()

    sub = f"{esc(tenant_name)} · generated {when(time.time())} UTC by {esc(generated_by)}"
    story = logo_header([Paragraph("TrustOps governance report", H1), Paragraph(sub, B)], logo_mm=18, width_mm=W / mm) + [Spacer(1, 8)]
    if scope:
        story += [Table([[Paragraph(f"<b>Filtered download</b> · {esc(scope)}", B)]], colWidths=[W],
                        style=[("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EDF3FF")), ("LEFTPADDING", (0, 0), (-1, -1), 8),
                               ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]), Spacer(1, 8)]

    # summary: six figure boxes in one row
    pct = lambda x: "–" if x is None else f"{round(x * 100)}%"
    box = lambda n, k: [Paragraph(esc(n), KN), Paragraph(esc(k), KV)]
    figs = [box(st["total"], "decisions recorded"), box(st["counts"]["ALLOW"], "allowed"),
            box(f'{st["counts"]["ESCALATE"]}', f'sent to a person ({pct(st["escalation_rate"])})'),
            box(f'{st["counts"]["DENY"]}', f'blocked ({pct(st["deny_rate"])})'), box(st["pending_approvals"], "still waiting"),
            box("Intact" if verification["valid"] else "BROKEN", f'evidence chain · {verification["checked"]} records')]
    kt = Table([[f[0] for f in figs], [f[1] for f in figs]], colWidths=[W / 6] * 6, hAlign="LEFT")
    kt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), band), ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, 0), 9),
                            ("BOTTOMPADDING", (0, 1), (-1, 1), 9), ("LINEAFTER", (0, 0), (-2, -1), 3, colors.white)]))
    story += [Paragraph("Summary", H2), kt, Spacer(1, 4),
              Paragraph(f'Applications: {esc(", ".join(st["by_application"]) or "–")} · simulated tests excluded from the figures: {st["simulated"]} · '
                        "integrity: SHA-256 hash chain (not KMS signed) · cost per run: not tracked yet", S)]
    if st["repeated_denials"]:
        story += [KeepTogether([Paragraph("Repeated denials (3 or more)", H2),
                                grid(["Who", "Denials"], [[P(x["actor"].replace("agent:agent:", "agent:")), P(str(x["denials"]))] for x in st["repeated_denials"]], [5, 1])])]

    story += [Paragraph("Policies in force", H2), grid(["On", "Policy", "Rule", "Actions", "Who", "Amount limit", "Decision"], [
        [P("Yes" if r.get("enabled", True) else "No"), P(r["id"], SB), P(r["name"]), P(", ".join(r["actions"])),
         P(", ".join(r.get("actor_types") or []) or "anyone"),
         P("–" if r.get("min_amount_minor") is None else f'above {r["min_amount_minor"] / 100:,.2f}'), Paragraph(col(r["decision"]), S)] for r in rules],
        [3, 6, 20, 28, 7, 9, 8])]

    attention = [r for r in real if r["decision"] in ("ESCALATE", "DENY")]
    story += [Paragraph(f"Escalations and denials ({len(attention)})", H2)]
    story += [grid(["Time (UTC)", "Application", "Who", "Action", "Amount", "Decision", "Policy", "Outcome", "Decided by"], [
        [P(when(r["at"])), P(r["application"]["name"]), P(who(r)), P(r["action"]), P(amt(r)), Paragraph(col(r["decision"]), S),
         P(r["policy_id"]), Paragraph(col(fin(r)), S), P((r.get("resolution") or {}).get("by", ""))] for r in attention],
        [11, 10, 13, 13, 9, 8, 9, 8, 13])] if attention else [Paragraph("None.", B)]

    story += [PageBreak(), Paragraph(f"Decision log ({len(records)} records, including resolutions and simulated tests)", H2)]
    story += [grid(["#", "Time (UTC)", "Application", "Who", "Action", "Amount", "Decision", "Policy", "Reason", "Record hash"], [
        [P(str(r["sequence"])), P(when(r["at"])), P(r["application"]["name"]), P(who(r)), P(r["action"].replace("resolve_escalation:", "resolve: ")),
         P(amt(r)), Paragraph(col(r["decision"]), S), P(r["policy_id"]), P(r["reason"]), Paragraph(r["record_hash"][:12] + "…", MONO)] for r in records],
        [3, 10, 9, 11, 12, 8, 7, 11, 19, 9])]
    story += [KeepTogether([Paragraph("Integrity", H2), Paragraph(
        "Each record stores the SHA-256 hash of the previous record, so changing any record breaks every hash after it. "
        f"Verification when this report was generated: <b>{'intact' if verification['valid'] else 'BROKEN'}</b> across {verification['checked']} records"
        f"{' (the whole chain, not only the records in this download)' if scope else ''}. "
        "Records are not signed with a cloud KMS key in this environment. The JSON audit pack holds the full records for independent re-verification.", B)])]
    doc.build(story, onFirstPage=lambda c, d: chrome(c, d, True), onLaterPages=lambda c, d: chrome(c, d, False))
    return buf.getvalue()


def insights(records, rules, now=None):
    """Overview charts (2026-11-13): decision mix, approval outcomes, time to decide, policies that decide most."""
    now = now or time.time()
    real = [r for r in records if not r.get("simulated") and not r["action"].startswith("resolve_escalation:") and r["action"] != "load_review_details"]
    mix = {d: sum(r["decision"] == d for r in real) for d in DECISIONS}
    esc = [r for r in real if r["decision"] == "ESCALATE"]
    res = [r for r in esc if r.get("resolution")]
    outcomes = {"approved": sum(r["resolution"]["outcome"] == "approve" for r in res),
                "rejected": sum(r["resolution"]["outcome"] == "reject" for r in res), "waiting": len(esc) - len(res)}
    hours = sorted(max(0.0, (r["resolution"]["at"] - r["at"]) / 3600) for r in res)
    pick = lambda q: round(hours[min(len(hours) - 1, int(q * (len(hours) - 1) + 0.5))], 1) if hours else None
    waiting_ages = [(now - r["at"]) / 3600 for r in esc if not r.get("resolution")]
    names = {x["id"]: x["name"] for x in rules}
    by_policy = {}
    for r in real:
        by_policy[r["policy_id"]] = by_policy.get(r["policy_id"], 0) + 1
    top = sorted(by_policy.items(), key=lambda kv: -kv[1])
    policies = [{"id": k, "name": names.get(k, "No policy covered it" if k == DEFAULT_ID else k), "count": v} for k, v in top[:4]]
    if len(top) > 4:
        policies.append({"id": "OTHER", "name": f"{len(top) - 4} other policies", "count": sum(v for _, v in top[4:])})
    return {"total": len(real), "mix": mix, "outcomes": outcomes,
            "turnaround": {"decided": len(hours), "median_hours": pick(0.5), "p90_hours": pick(0.9), "target_hours": 24,
                           "within_target": sum(h <= 24 for h in hours), "oldest_waiting_hours": round(max(waiting_ages), 1) if waiting_ages else None},
            "policies": policies,
            "actors": {t: sum(r["actor"]["type"] == t for r in real) for t in ("agent", "human", "service")}}


def _public(r):
    return r


# Files an approver attaches to an item waiting for them (2026-11-13 action items: "Upload button for reviewers").
ATTACH_TYPES = {"application/pdf", "text/plain", "text/csv", "application/json", "image/png", "image/jpeg",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
ATTACH_MAX = 10 * 1024 * 1024
ATTACH_PER_ITEM = 10
_BAD_NAME = set('<>:"|?*')


def _safe_name(filename):
    base = str(filename or "").replace("\\", "/").split("/")[-1]
    return "".join(ch for ch in base if ch.isprintable() and ch not in _BAD_NAME).strip()[:120] or "file"


def make_router(principal, find_integration_by_key, audit=None, identity=None, store=None, state=None, tenant_name=None, integrations=None, reviewers=None,
                files=None):
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
        if decision == "ESCALATE":
            rec["assignment"] = {"to": check_reviewer(tenant, body.get("assign_to")), "by": by or f"{application['name']}", "at": time.time(), "history": []}
        rec = db.append(tenant, rec)
        if ident:
            db.count_agent(ident["id"], decision)
        return {"decision_id": rec["id"], "decision": decision, "policy_id": policy, "reason": reason,
                "status": "pending_approval" if decision == "ESCALATE" else "final",
                "evidence_hash": rec["record_hash"], "evidence_sequence": rec["sequence"]}

    def reviewer_list(tenant):
        return reviewers(tenant) if reviewers else []

    def check_reviewer(tenant, email):
        email = (str(email or "")).strip().lower() or None
        if email and email not in {r["email"] for r in reviewer_list(tenant)}:
            raise _err(422, "not_a_reviewer", "This person is not an Admin or Approver in TrustOps")
        return email

    def assign(tenant, did, to, by, app_id=None):
        r = db.get(tenant, did)
        if not r or (app_id and r["application"]["id"] != app_id):
            raise _err(404, "not_found", "Decision not found")
        if r["decision"] != "ESCALATE" or r.get("resolution"):
            raise _err(409, "not_pending", "This item is no longer waiting for review")
        to = check_reviewer(tenant, to)
        prev = r.get("assignment") or {"history": []}
        r["assignment"] = {"to": to, "by": by, "at": time.time(),
                           "history": (prev.get("history") or []) + ([{k: prev.get(k) for k in ("to", "by", "at")}] if "at" in prev else [])}
        db.update(tenant, r)
        return {"decision_id": did, "assigned_to": to}

    # ---- applications call this ----
    @router.get("/v1/reviewers")
    def app_reviewers(x_trustops_key: Optional[str] = Header(default=None)):
        found = find_integration_by_key(x_trustops_key or "")
        if not found:
            raise _err(401, "invalid_key", "A valid X-TrustOps-Key is required")
        return {"items": reviewer_list(found[0])}

    @router.post("/v1/decisions/{did}/app-assign")
    def app_assign(did: str, body: dict = Body(...), x_trustops_key: Optional[str] = Header(default=None)):
        found = find_integration_by_key(x_trustops_key or "")
        if not found:
            raise _err(401, "invalid_key", "A valid X-TrustOps-Key is required")
        by = str(body.get("by") or found[1]["name"])[:200]
        return assign(found[0], did, body.get("to"), by, app_id=found[1]["id"])

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
                "resolution_reason": res["reason"] if res else None,
                "assigned_to": (r.get("assignment") or {}).get("to")}

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

    @router.get("/v1/decisions-reviewers")
    def console_reviewers(p=Depends(principal)):
        need(p, READ)
        return {"items": reviewer_list(p.tenant_id)}

    @router.post("/v1/decisions/{did}/assign")
    def console_assign(did: str, body: dict = Body(...), p=Depends(principal)):
        need(p, APPROVERS, "Only an approver or administrator can assign reviews")
        out = assign(p.tenant_id, did, body.get("to"), identity(p) if identity else p.sub)
        if audit:
            audit(p, "decision.assign", did)
        return out

    @router.post("/v1/decisions/{did}/resolve")
    def resolve(did: str, body: dict = Body(...), p=Depends(principal)):
        need(p, APPROVERS, "Only a controller or administrator can resolve escalations")
        r = db.get(p.tenant_id, did)
        if not r:
            raise _err(404, "not_found", "Decision not found")
        if r["decision"] != "ESCALATE" or r.get("resolution"):
            raise _err(409, "not_pending", "This decision is not waiting for a person")
        who = identity(p) if identity else p.sub
        own = who == r["actor"]["id"] or p.sub == r["actor"]["id"] or who == r.get("requested_by")
        # Approvers can never resolve their own items. Administrators can, and the record says so openly.
        if own and "customer_admin" not in p.roles:
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
                           "basis": "details_in_trustops" if has_details else ("checked_in_application" if checked else "none"),
                           "self_resolved": own}
        db.update(p.tenant_id, r)
        db.append(p.tenant_id, {"id": "dec_" + uuid.uuid4().hex[:16], "at": time.time(), "tenant_id": p.tenant_id,
                                "application": r["application"], "actor": {"type": "human", "id": who},
                                "action": f"resolve_escalation:{outcome}", "resource": did, "client": r.get("client"),
                                "amount_minor": r.get("amount_minor"), "currency": r.get("currency"), "context": {"reason": reason[:500]},
                                "decision": "ALLOW", "policy_id": "MAKER-CHECKER",
                                "reason": (f"Escalation {did} {outcome}d by the administrator who submitted it (self-approval)" if own
                                           else f"Escalation {did} {outcome}d by a different person"),
                                "simulated": r.get("simulated", False), "requested_by": who})
        if audit:
            audit(p, f"decision.resolve.{outcome}", did)
        return r

    # ---- attachments: an approver uploads a supporting file (receipt, remittance, ...) to an item waiting for them ----
    # The bytes are checked (type, content, malware scan) by `files` (main.py) and kept in object storage; the record
    # keeps the file's name, size, SHA-256, who and when. Attachments sit outside the hash (like the resolution), so
    # adding one never breaks the evidence chain; each upload is in the audit log.
    @router.post("/v1/decisions/{did}/attachments", status_code=201)
    async def attach(did: str, request: Request, filename: str = Query(..., min_length=1, max_length=200), p=Depends(principal)):
        need(p, APPROVERS, "Only an approver or administrator can attach files")
        if files is None or not files.available():
            raise _err(501, "not_available", "File uploads are not available in this environment")
        r = db.get(p.tenant_id, did)
        if not r:
            raise _err(404, "not_found", "Decision not found")
        if r["decision"] != "ESCALATE" or r.get("resolution"):
            raise _err(409, "not_pending", "Files can be attached only while the item is waiting for a decision")
        if len(r.get("attachments") or []) >= ATTACH_PER_ITEM:
            raise _err(409, "too_many", f"An item can have at most {ATTACH_PER_ITEM} files")
        ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
        if ctype not in ATTACH_TYPES:
            raise _err(422, "type_not_allowed", "Attach a PDF, image (PNG or JPEG), Word, Excel, CSV, text or JSON file")
        data = b""
        async for chunk in request.stream():
            data += chunk
            if len(data) > ATTACH_MAX:
                raise _err(422, "too_large", "Files can be at most 10 MB")
        if not data:
            raise _err(422, "empty", "The file is empty")
        verdict = files.check(ctype, data)
        if verdict["state"] != "clean":
            if audit:
                audit(p, f"decision.attach.{verdict['state']}", did)
            raise _err(422, "file_rejected", f"The file was not accepted ({verdict.get('reason') or verdict['state']})")
        fid = "att_" + uuid.uuid4().hex[:16]
        files.put(p.tenant_id, fid, data)
        meta = {"id": fid, "filename": _safe_name(filename), "content_type": ctype, "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "by": identity(p) if identity else p.sub, "at": time.time()}
        r["attachments"] = list(r.get("attachments") or []) + [meta]
        db.update(p.tenant_id, r)
        if audit:
            audit(p, "decision.attach", f"{did}/{fid}")
        return meta

    @router.get("/v1/decisions/{did}/attachments/{fid}")
    def attachment(did: str, fid: str, p=Depends(principal)):
        need(p, READ)
        r = db.get(p.tenant_id, did)
        meta = next((a for a in (r or {}).get("attachments") or [] if a["id"] == fid), None)
        if not meta or files is None:
            raise _err(404, "not_found", "File not found")
        data = files.get(p.tenant_id, fid)
        safe = meta["filename"].encode("ascii", "replace").decode().replace('"', "'")
        return Response(data, media_type=meta["content_type"], headers={"Content-Disposition": f'attachment; filename="{safe}"',
                                                                       "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

    # ---- TrustTwin (the console's read-only assistant; answers come from the records, see assistant.py) ----
    @router.get("/v1/assistant/suggestions")
    def assistant_suggestions(p=Depends(principal)):
        need(p, READ)
        from .assistant import SUGGESTIONS
        return {"suggestions": SUGGESTIONS, "name": "TrustTwin"}

    @router.post("/v1/assistant/ask")
    def assistant_ask(body: dict = Body(...), p=Depends(principal)):
        need(p, READ)
        from .assistant import answer
        q = body.get("question")
        if not isinstance(q, str) or not q.strip():
            raise _err(422, "invalid_request", "question is required")
        recs = db.all(p.tenant_id)
        out = answer(q, records=recs, rules=db.rules(p.tenant_id), verification=verify_chain(recs),
                     me={p.sub, identity(p) if identity else p.sub}, roles=p.roles, approvers=APPROVERS)
        if audit:   # who asked and how it was answered; the question text itself is not stored
            audit(p, "assistant.ask", out["status"])
        return out

    # ---- notifications: what happened in the decision log that this person should know about ----
    # Read from the hash-chained decision records, so every browser sees the same list. Approvers and administrators
    # are told when an application sends an item for approval or an agent's action is escalated to a person; everyone
    # is told when someone else approves or rejects an item, and when an agent is blocked. Your own actions never
    # notify you. Only "seen" is stored (per person, per workspace, on the user record).
    def notification_items(p):
        me = {p.sub, identity(p) if identity else p.sub}
        recs = db.all(p.tenant_id)
        by_id = {r["id"]: r for r in recs}
        approver = bool(set(p.roles) & APPROVERS)
        items = []
        for r in recs:
            a = r["action"]
            if r.get("simulated") or a == "load_review_details":
                continue
            # Your own clicks in TrustOps never notify you. An item an application sent and assigned to you does, even
            # when the same person sent it from that application (one account signed in to both apps). Live issue 2026-11-13.
            mine_in_app = r["decision"] == "ESCALATE" and not a.startswith("resolve_escalation:") and (r.get("assignment") or {}).get("to") in me
            if (r["actor"]["id"] in me or r.get("requested_by") in me) and not mine_in_app:
                continue
            if a.startswith("resolve_escalation:"):
                src, kind = by_id.get(r.get("resource")) or {}, ("APPROVED" if a.endswith(":approve") else "REJECTED")
                note = (r.get("context") or {}).get("reason")
            elif r["decision"] == "ESCALATE" and approver:
                kind = ("RESUBMITTED" if (r.get("context") or {}).get("resubmission") else "SUBMITTED") if a == "submit_for_review" else "ESCALATED"
                src, note = r, (None if kind in ("SUBMITTED", "RESUBMITTED") else r.get("reason"))   # "Submitted for approval" adds nothing
            elif r["decision"] == "DENY":
                src, kind, note = r, "DENIED", r.get("reason")
            else:
                continue
            to = (src.get("assignment") or {}).get("to")
            items.append({"seq": r["sequence"], "kind": kind, "at": r["at"], "by": r["actor"]["id"], "by_type": r["actor"]["type"],
                          "application": r["application"]["name"], "decision_id": src.get("id") or r.get("resource"),
                          "title": (src.get("details") or {}).get("title") or str(src.get("action") or a).replace("_", " "),
                          "action": src.get("action"), "policy_id": src.get("policy_id"), "client": src.get("client"),
                          "amount_minor": src.get("amount_minor"), "currency": src.get("currency"), "note": (note or "")[:300],
                          "for_me": bool(to) and to in me, "pending": src.get("decision") == "ESCALATE" and not src.get("resolution")})
        return items, (recs[-1]["sequence"] if recs else 0)

    def seen_marks(p):
        users = getattr(db.state, "users", {})
        return users[p.sub].setdefault("notif_seen", {}) if p.sub in users else {}

    @router.get("/v1/notifications")
    def notifications(limit: int = Query(30, ge=1, le=100), p=Depends(principal)):
        need(p, READ)
        items, _ = notification_items(p)
        seen = int(seen_marks(p).get(p.tenant_id, 0))
        for it in items:
            it["unread"] = it["seq"] > seen
        return {"unread": sum(it["unread"] for it in items), "items": list(reversed(items))[:limit], "seen": seen,
                "for": "approver" if set(p.roles) & APPROVERS else "viewer"}

    @router.post("/v1/notifications/seen")
    def notifications_seen(body: dict = Body(...), p=Depends(principal)):
        need(p, READ)
        try:
            upto = int(body.get("upto"))
        except (TypeError, ValueError):
            raise _err(422, "invalid_request", "upto must be a record number") from None
        _, newest = notification_items(p)
        marks = seen_marks(p)
        with db.state.lock:
            marks[p.tenant_id] = max(int(marks.get(p.tenant_id, 0)), max(0, min(upto, newest)))
        return {"seen": marks.get(p.tenant_id, 0)}

    @router.get("/v1/decisions-stats")
    def get_stats(p=Depends(principal)):
        need(p, READ)
        return stats(db.all(p.tenant_id))

    @router.get("/v1/decisions-insights")
    def get_insights(p=Depends(principal)):
        need(p, READ)
        return insights(db.all(p.tenant_id), db.rules(p.tenant_id))

    @router.get("/v1/decisions-verify")
    def verify(p=Depends(principal)):
        need(p, READ)
        return {**verify_chain(db.all(p.tenant_id)), "integrity": "sha256_hash_chain",
                "signed": False, "note": "Records are hash-chained; they are not KMS signed in this environment."}

    # Evidence downloads (2026-11-13 action items): everything, or only what one person / agent did (asked, approved or
    # rejected), one application, one outcome or a date range. The chain is always verified over ALL records.
    def _who_did(r):
        return {r["actor"]["id"]} | ({r["resolution"]["by"]} if r.get("resolution") else set())

    @router.get("/v1/decisions-people")
    def people(p=Depends(principal)):
        need(p, READ)
        seen = {}
        for r in db.all(p.tenant_id):
            if r["action"] == "load_review_details":
                continue
            for pid in _who_did(r):
                kind = "agent" if (r["actor"]["id"] == pid and r["actor"]["type"] == "agent") else "person"
                e = seen.setdefault(pid, {"id": pid, "kind": kind, "records": 0})
                e["records"] += 1
        apps = sorted({r["application"]["name"] for r in db.all(p.tenant_id)})
        return {"people": sorted(seen.values(), key=lambda e: (e["kind"] != "person", e["id"])), "applications": apps}

    @router.get("/v1/decisions-export")
    def export(fmt: str = Query("json", pattern="^(json|csv|pdf)$"), person: Optional[str] = Query(None, max_length=200),
               application: Optional[str] = Query(None, max_length=200), outcome: Optional[str] = Query(None, pattern="^(ALLOW|ESCALATE|DENY|APPROVED|REJECTED|PENDING)$"),
               since: Optional[str] = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"), until: Optional[str] = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
               p=Depends(principal)):
        need(p, READ)
        everything = db.all(p.tenant_id)
        import calendar
        day = lambda d, end=False: calendar.timegm(time.strptime(d, "%Y-%m-%d")) + (86400 if end else 0)   # UTC days
        final = lambda r: ({"approve": "APPROVED", "reject": "REJECTED"}[r["resolution"]["outcome"]] if r.get("resolution")
                           else "PENDING" if r["decision"] == "ESCALATE" else r["decision"])
        records = [r for r in everything
                   if (not person or person in _who_did(r)) and (not application or r["application"]["name"] == application)
                   and (not outcome or r["decision"] == outcome or final(r) == outcome)
                   and (not since or r["at"] >= day(since)) and (not until or r["at"] < day(until, True))]
        scope = " · ".join(x for x in [f"person or agent: {person}" if person else "", f"application: {application}" if application else "",
                                       f"outcome: {outcome.lower()}" if outcome else "",
                                       f"from {since}" if since else "", f"to {until}" if until else ""] if x)
        scope = f"{scope} · {len(records)} of {len(everything)} records" if scope else None
        if audit:
            audit(p, "decision.export", f"{fmt}{' filtered' if scope else ''}")
        stamp = time.strftime("%Y%m%d-%H%M%S")
        tag = "".join(ch if ch.isalnum() else "-" for ch in (person or "")).strip("-")[:40]
        tag = f"-{tag}" if tag else ("-filtered" if scope else "")
        if fmt == "pdf":
            body = render_pdf(tenant_name(p.tenant_id) if tenant_name else p.tenant_id, identity(p) if identity else p.sub,
                              records, db.rules(p.tenant_id), verify_chain(everything), scope=scope)
            return Response(body, media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="trustops-governance-report{tag}-{stamp}.pdf"'})
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
                            headers={"Content-Disposition": f'attachment; filename="trustops-decisions{tag}-{stamp}.csv"'})
        pack = {"format": "trustops.audit-pack.v1", "generated_at": time.time(), "tenant_id": p.tenant_id,
                "generated_by": identity(p) if identity else p.sub, "verification": verify_chain(everything), "filter": scope,
                "integrity": "sha256_hash_chain (not KMS signed)", "policies": db.rules(p.tenant_id),
                "summary": stats(records), "records": records}
        return Response(json.dumps(pack, indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="trustops-audit-pack{tag}-{stamp}.json"'})

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
