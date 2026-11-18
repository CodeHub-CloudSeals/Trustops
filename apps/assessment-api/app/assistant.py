"""TrustTwin - Your Governance Digital Twin (the TrustOps counterpart of LedgerSight's FinTwin).

Read-only. Every fact in an answer comes from this workspace's decision records, policies and the hash chain, looked
up by the fixed rules below, and the answer names the records it used. Nothing is changed: requests to approve,
reject, assign or edit are refused by rule (before any model is asked) with a pointer to the page where a person does
that. Greetings, thanks and "help" are answered without a model.

Optional AI phrasing (2026-11-16, TRUSTOPS_ASSISTANT_MODEL=vertex, Gemini on Vertex AI in TAAD_VERTEX_LOCATION):
1. understand - the model sees only the question and the list of supported intents and returns {intent, params};
   anything outside that list, or an id that is not in the question, is ignored and the rules read the question;
2. the intent runs through exactly the same rules as a typed question (same records, same citations);
3. phrase - the model sees the question and that exact result and writes a short reply. Every number and id in the
   reply must appear in the result, otherwise the rules' own text is shown. Timeouts and errors fall back silently.
Without the setting (or if the model is unavailable) TrustTwin answers exactly as before. Other model settings
(TAAD_LLM_PROVIDER, assessment agents) are not affected.
"""
from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, InvalidOperation

SUGGESTIONS = [
    "What is waiting for approval?",
    "What is assigned to me?",
    "What was blocked recently?",
    "What was approved or rejected?",
    "Give me a summary",
    "Is the evidence chain intact?",
    "Which policies are on?",
    "Which agents are most active?",
]

WRITE = re.compile(r"^\s*(?:please\s+|can you\s+|could you\s+|go\s+)?(approve|reject|decline|assign|reassign|delete|remove|"
                   r"edit|change|update|disable|enable|turn (?:on|off)|grant|revoke|resolve|send)\b", re.I)
DEC_ID = re.compile(r"\bdec_[0-9a-f]{6,}\b", re.I)
POLICY_ID = re.compile(r"\b(?:FIN|LS|POL|DEFAULT|MAKER)-?\d*\b", re.I)
ITEM_REF = re.compile(r"\b[A-Z]{2,4}-[A-Z0-9]{2,}(?:-[A-Z0-9]+)?\b", re.I)
MAX_ROWS = 12
WORD = {"ALLOW": "allowed", "ESCALATE": "escalated", "DENY": "blocked"}


def _when(t):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "–"


def _short(t):
    """Table dates (the panel is narrow): "13 Nov 07:19" in UTC."""
    return time.strftime("%d %b %H:%M", time.gmtime(t)).lstrip("0") if t else "–"


def _money(r):
    return "–" if r.get("amount_minor") is None else f'{r["amount_minor"] / 100:,.2f} {r.get("currency") or ""}'.strip()


def _title(r):
    return (r.get("details") or {}).get("title") or str(r.get("action") or "").replace("_", " ")


def _agent(aid):
    """LedgerSight sends agent ids as "agent:recon"; show "recon"."""
    return str(aid or "").split(":", 1)[1] if str(aid or "").startswith("agent:") else str(aid or "")


def _who(r):
    a = r.get("actor") or {}
    return f'Agent {_agent(a.get("id"))}' if a.get("type") == "agent" else (a.get("id") or "someone")


def _link(r):
    return f'#/approval/{r["id"]}' if r.get("decision") == "ESCALATE" else ("#/decisions/deny" if r.get("decision") == "DENY" else "#/decisions")


def _cite(r):
    return {"ref": r["id"], "kind": "decision record", "source": f'record #{r["sequence"]} · {r["application"]["name"]}',
            "sha256": r.get("record_hash"), "link": _link(r)}


def _outcome(r):
    res = r.get("resolution")
    if res:
        return "Approved" if res["outcome"] == "approve" else "Rejected"
    return "Waiting" if r["decision"] == "ESCALATE" else r["decision"].title()


def _since(q, now):
    if re.search(r"\btoday\b", q):
        return now - (now % 86400), "today"
    if re.search(r"\byesterday\b", q):
        return now - (now % 86400) - 86400, "since yesterday"
    if re.search(r"\b(this|last|past) week\b|\b7 days\b", q):
        return now - 7 * 86400, "in the last 7 days"
    if re.search(r"\b(this|last|past) month\b|\b30 days\b", q):
        return now - 30 * 86400, "in the last 30 days"
    return None, ""


def _answer(status, text, columns=(), rows=(), links=(), cites=(), suggestions=None):
    return {"status": status, "answer": text, "columns": list(columns), "rows": [list(r) for r in rows], "links": list(links),
            "citations": list(cites)[:MAX_ROWS], "suggestions": suggestions or []}


def _rules(question, *, records, rules, verification, me, roles, approvers, now=None):
    """The fixed rules (unchanged before 16/11): one question in, one exact answer out. `records` are this workspace's
    decision records (oldest first); `me` is the set of ids that mean "this person"; `approvers` is the role set that
    may approve. Returns the FinTwin answer shape."""
    now = now or time.time()
    q = " ".join(str(question or "").split())[:500]
    ql = q.lower()
    if not q:
        return _answer("NO_MATCH", "Ask me about approvals, decisions, blocked actions, policies, agents or the evidence chain.",
                       suggestions=SUGGESTIONS[:4])
    if WRITE.search(q):
        verb = WRITE.search(q).group(1).lower()
        where = ("Approvals" if verb in ("approve", "reject", "decline", "resolve", "assign", "reassign") else
                 "Policies" if verb in ("disable", "enable", "turn on", "turn off", "edit", "change", "update") else
                 "Team & access" if verb in ("grant", "revoke", "remove") else "the page for it")
        return _answer("REFUSED", f"I'm read-only, so I can't {verb} anything. A person does that in {where}, and it is "
                       "recorded in the evidence chain under their name.", suggestions=["What is waiting for approval?", "What is assigned to me?"])

    real = [r for r in records if not r.get("simulated") and r["action"] != "load_review_details"]
    decisions = [r for r in real if not r["action"].startswith("resolve_escalation:")]
    by_id = {r["id"]: r for r in records}
    since, span = _since(ql, now)
    recent = (lambda rs: [r for r in rs if r["at"] >= since]) if since else (lambda rs: rs)

    # 1. one record by its id
    m = DEC_ID.search(q)
    if m:
        r = by_id.get(m.group(0).lower())
        if not r:
            return _answer("NO_DATA", f"There is no decision {m.group(0)} in this workspace.", suggestions=SUGGESTIONS[:3])
        res = r.get("resolution") or {}
        assigned = (r.get("assignment") or {}).get("to")
        text = (f'{_who(r)} asked to {r["action"].replace("_", " ")} in {r["application"]["name"]}'
                f'{" for " + _money(r) if r.get("amount_minor") is not None else ""} on {_when(r["at"])}. '
                f'TrustOps decided {r["decision"]} under {r["policy_id"]}: {r["reason"]}.')
        if r["decision"] == "ESCALATE":
            text += (f' {res.get("by")} {"approved" if res.get("outcome") == "approve" else "rejected"} it on {_when(res.get("at"))}'
                     f'{": “" + res["reason"] + "”" if res.get("reason") else ""}.' if res else
                     f' It is still waiting for {assigned if assigned else "an approver"}.')
        return _answer("ANSWERED", text, ["Field", "Value"],
                       [["Item", _title(r)], ["Decision", r["decision"]], ["Policy", r["policy_id"]], ["Outcome", _outcome(r)],
                        ["Record", f'#{r["sequence"]}'], ["Record hash", r["record_hash"][:16] + "…"]],
                       cites=[_cite(r)], suggestions=["Is the evidence chain intact?", "What is waiting for approval?"])

    # 2. a policy by its id
    pm = POLICY_ID.search(q)
    if pm and any(x["id"].lower() == pm.group(0).lower() for x in rules):
        rule = next(x for x in rules if x["id"].lower() == pm.group(0).lower())
        hits = recent([r for r in decisions if r["policy_id"] == rule["id"]])
        counts = {d: sum(r["decision"] == d for r in hits) for d in ("ALLOW", "ESCALATE", "DENY")}
        limit = f' above {rule["min_amount_minor"] / 100:,.2f}' if rule.get("min_amount_minor") is not None else ""
        text = (f'{rule["id"]} “{rule["name"]}” is {"on" if rule.get("enabled", True) else "off"}. It decides {rule["decision"]}'
                f'{limit} for {", ".join(rule["actions"])}'
                f'{" by " + ", ".join(rule["actor_types"]) if rule.get("actor_types") else ""}. '
                f'It has applied to {len(hits)} decision{"s" if len(hits) != 1 else ""}{" " + span if span else ""}'
                f'{" (" + ", ".join(f"{v} {WORD[k]}" for k, v in counts.items() if v) + ")" if hits else ""}.')
        last = list(reversed(hits))[:MAX_ROWS]
        return _answer("ANSWERED", text, ["When", "Who", "Action", "Decision"],
                       [[_short(r["at"]), _who(r), r["action"], r["decision"]] for r in last], [_link(r) for r in last],
                       [_cite(r) for r in last], ["Which policies are on?", "What was blocked recently?"])

    # 3. items mentioned by their reference (EX-003, CA-TAX-01, INV-1001 ...)
    ref = ITEM_REF.search(q)
    if ref and not pm:
        needle = ref.group(0).lower()
        hits = [r for r in decisions if needle in _title(r).lower() or needle in str(r.get("client") or "").lower()
                or needle in str(r.get("details") or "").lower()]
        if hits:
            last = list(reversed(hits))[:MAX_ROWS]
            return _answer("ANSWERED", f'{len(hits)} decision{"s mention" if len(hits) != 1 else " mentions"} {ref.group(0)}.',
                           ["Item", "When", "Decision", "Outcome"], [[_title(r), _short(r["at"]), r["decision"], _outcome(r)] for r in last],
                           [_link(r) for r in last], [_cite(r) for r in last], ["What is waiting for approval?"])

    pending = [r for r in decisions if r["decision"] == "ESCALATE" and not r.get("resolution")]

    # 4. assigned to me
    if re.search(r"\b(assigned to me|for me|my (approvals|queue|items|work)|do i need|should i)\b", ql):
        mine = [r for r in pending if (r.get("assignment") or {}).get("to") in me]
        if not set(roles) & approvers:
            return _answer("ANSWERED", "You are not an approver in this workspace, so nothing is assigned to you. "
                           f'{len(pending)} item{"s are" if len(pending) != 1 else " is"} waiting for the approvers.',
                           suggestions=["What is waiting for approval?"])
        if not mine:
            return _answer("ANSWERED", "Nothing is assigned to you right now. "
                           f'{len(pending)} item{"s are" if len(pending) != 1 else " is"} waiting for any approver.',
                           suggestions=["What is waiting for approval?"])
        return _rows_answer(f'{len(mine)} item{"s are" if len(mine) != 1 else " is"} waiting for you.', mine, now, pending_cols=True)

    # 5. waiting for approval
    if re.search(r"\b(pending|waiting|wait|queue|approval queue|needs? (a person|approval|a decision)|to approve|outstanding|open items?)\b", ql) \
            or re.search(r"\bwhat.*(approve|review)\b", ql) and not re.search(r"\b(approved|rejected|reviewed)\b", ql):
        items = recent(pending)
        if not items:
            return _answer("ANSWERED", f"Nothing is waiting for approval{' ' + span if span else ''}.", suggestions=["What was approved or rejected?"])
        oldest = min(items, key=lambda r: r["at"])
        days = int((now - oldest["at"]) // 86400)
        return _rows_answer(f'{len(items)} item{"s are" if len(items) != 1 else " is"} waiting for a person{" " + span if span else ""}. '
                            f'The oldest has waited {days} day{"s" if days != 1 else ""}' if days else
                            f'{len(items)} item{"s are" if len(items) != 1 else " is"} waiting for a person{" " + span if span else ""}', items, now, pending_cols=True)

    # 6. approved / rejected
    if re.search(r"\b(approved|rejected|declined|decided|resolved|resolutions?|outcomes?)\b", ql):
        want = "approve" if re.search(r"\bapproved\b", ql) and not re.search(r"\b(rejected|declined)\b", ql) else \
            "reject" if re.search(r"\b(rejected|declined)\b", ql) and not re.search(r"\bapproved\b", ql) else None
        done = recent([r for r in decisions if r.get("resolution") and (not want or r["resolution"]["outcome"] == want)])
        done.sort(key=lambda r: r["resolution"]["at"], reverse=True)
        if not done:
            return _answer("ANSWERED", f'Nothing has been {"approved" if want == "approve" else "rejected" if want == "reject" else "approved or rejected"}'
                           f'{" " + span if span else " yet"}.', suggestions=["What is waiting for approval?"])
        n_app = sum(r["resolution"]["outcome"] == "approve" for r in done)
        last = done[:MAX_ROWS]
        return _answer("ANSWERED", f'{n_app} approved and {len(done) - n_app} rejected{" " + span if span else ""}. Newest first:',
                       ["Item", "Outcome", "By", "Reason"],
                       [[_title(r), f'{_outcome(r)} · {_short(r["resolution"]["at"])}', r["resolution"]["by"], r["resolution"].get("reason") or "–"] for r in last],
                       [_link(r) for r in last], [_cite(r) for r in last], ["What is waiting for approval?", "What was blocked recently?"])

    # 7. blocked
    if re.search(r"\b(block(ed|s)?|den(y|ied|ials?)|refused|stopped|prevented)\b", ql):
        items = recent([r for r in decisions if r["decision"] == "DENY"])
        if not items:
            return _answer("ANSWERED", f"Nothing was blocked{' ' + span if span else ''}.", suggestions=["Which policies are on?"])
        by_pol, by_actor = {}, {}
        for r in items:
            by_pol[r["policy_id"]] = by_pol.get(r["policy_id"], 0) + 1
            by_actor[_who(r)] = by_actor.get(_who(r), 0) + 1
        top_pol = ", ".join(f"{k} ({v})" for k, v in sorted(by_pol.items(), key=lambda x: -x[1])[:3])
        top_act = max(by_actor.items(), key=lambda x: x[1])
        last = list(reversed(items))[:MAX_ROWS]
        return _answer("ANSWERED", f'{len(items)} action{"s were" if len(items) != 1 else " was"} blocked{" " + span if span else ""}, '
                       f'mostly by {top_pol}. {top_act[0]} was blocked most ({top_act[1]}).',
                       ["When", "Who", "Action", "Policy"],
                       [[_short(r["at"]), _who(r), r["action"], r["policy_id"]] for r in last], [_link(r) for r in last],
                       [_cite(r) for r in last], ["Which policies are on?", "Which agents are most active?"])

    # 8. evidence chain
    if re.search(r"\b(chain|integrity|tamper\w*|hash(es)?|evidence|intact|verify|verified|audit trail)\b", ql):
        v = verification
        head = records[-1] if records else None
        text = (f'Yes. All {v["checked"]} records verify: each one carries the SHA-256 hash of the record before it, so changing any '
                f'record would break every hash after it.' if v["valid"] else
                f'No. The chain breaks at {v.get("broken_at")} (record {v["checked"]}). Records after that point cannot be trusted '
                'until this is investigated.')
        text += " Records are hash-chained, not KMS signed, in this environment."
        return _answer("ANSWERED" if v["valid"] else "ATTENTION", text, ["Check", "Result"],
                       [["Records checked", str(v["checked"])], ["Chain", "Intact" if v["valid"] else "Broken"],
                        ["Latest record", f'#{head["sequence"]} · {_when(head["at"])}' if head else "–"],
                        ["Head hash", (v.get("head") or "–")[:16] + "…" if v.get("head") else "–"]],
                       cites=[_cite(head)] if head else [], suggestions=["Give me a summary"])

    # 9. policies
    if re.search(r"\b(polic(y|ies)|rules?|guardrails?|limits?)\b", ql):
        on = [x for x in rules if x.get("enabled", True)]
        return _answer("ANSWERED", f'{len(on)} of {len(rules)} policies are on. Anything no policy covers is escalated to a person (DEFAULT).',
                       ["Policy", "Rule", "Decision", "On"],
                       [[x["id"], x["name"], x["decision"] + (f' above {x["min_amount_minor"] / 100:,.0f}' if x.get("min_amount_minor") is not None else ""),
                         "Yes" if x.get("enabled", True) else "No"] for x in rules],
                       ["#/policies"] * len(rules), suggestions=[f'What does {rules[0]["id"]} do?' if rules else "Give me a summary", "What was blocked recently?"])

    # 10. agents
    if re.search(r"\b(agents?|bots?|automations?)\b", ql):
        agents = {}
        for r in recent(decisions):
            if r["actor"]["type"] != "agent":
                continue
            a = agents.setdefault(_agent(r["actor"]["id"]), {"ALLOW": 0, "ESCALATE": 0, "DENY": 0, "app": r["application"]["name"], "last": 0})
            a[r["decision"]] += 1
            a["last"] = max(a["last"], r["at"])
        if not agents:
            return _answer("ANSWERED", f"No agent has asked TrustOps anything{' ' + span if span else ' yet'}.", suggestions=["Give me a summary"])
        ranked = sorted(agents.items(), key=lambda kv: -(kv[1]["ALLOW"] + kv[1]["ESCALATE"] + kv[1]["DENY"]))
        return _answer("ANSWERED", f'{len(agents)} agent{"s have" if len(agents) != 1 else " has"} asked TrustOps for decisions{" " + span if span else ""}. Busiest first:',
                       ["Agent", "Allowed", "Escalated", "Blocked"],
                       [[f'{k} · {a["app"]}', a["ALLOW"], a["ESCALATE"], a["DENY"]] for k, a in ranked[:MAX_ROWS]],
                       ["#/authority"] * min(len(ranked), MAX_ROWS), suggestions=["What was blocked recently?"])

    # 11. applications
    if re.search(r"\b(applications?|apps?|connected|systems?|ledgersight)\b", ql):
        apps = {}
        for r in recent(decisions):
            a = apps.setdefault(r["application"]["name"], {"ALLOW": 0, "ESCALATE": 0, "DENY": 0, "last": 0})
            a[r["decision"]] += 1
            a["last"] = max(a["last"], r["at"])
        if not apps:
            return _answer("ANSWERED", "No application has sent anything to TrustOps yet.", suggestions=["Which policies are on?"])
        return _answer("ANSWERED", f'{len(apps)} application{"s have" if len(apps) != 1 else " has"} sent decisions{" " + span if span else ""}.',
                       ["Application", "Allowed", "Escalated", "Blocked"],
                       [[f'{k} · last {_short(a["last"])}', a["ALLOW"], a["ESCALATE"], a["DENY"]] for k, a in sorted(apps.items())],
                       ["#/connected-systems"] * len(apps), suggestions=["Which agents are most active?"])

    # 12. summary
    if re.search(r"\b(summary|summarise|summarize|overview|status|stats|statistics|how many|how much|numbers|report|today|this week|how are we)\b", ql):
        ds = recent(decisions)
        c = {d: sum(r["decision"] == d for r in ds) for d in ("ALLOW", "ESCALATE", "DENY")}
        n = len(ds)
        pct = lambda x: f"{round(100 * x / n)}%" if n else "–"
        text = (f'{n} decision{"s" if n != 1 else ""}{" " + span if span else " so far"}: {c["ALLOW"]} allowed, {c["ESCALATE"]} escalated to a person '
                f'({pct(c["ESCALATE"])}) and {c["DENY"]} blocked ({pct(c["DENY"])}). {len(pending)} '
                f'{"are" if len(pending) != 1 else "is"} still waiting for approval. The evidence chain is '
                f'{"intact" if verification["valid"] else "BROKEN at " + str(verification.get("broken_at"))}.')
        return _answer("ANSWERED", text, ["Measure", "Value"],
                       [["Decisions", n], ["Allowed", c["ALLOW"]], ["Escalated", c["ESCALATE"]], ["Blocked", c["DENY"]],
                        ["Waiting for approval", len(pending)], ["Evidence chain", "Intact" if verification["valid"] else "Broken"]],
                       suggestions=["What is waiting for approval?", "What was blocked recently?"])

    # 13. help
    if re.search(r"\b(help|what can you|who are you|how do(es)? (this|it|you) work)\b", ql):
        return _answer("ANSWERED", "I'm TrustTwin. I answer questions about this workspace's governance from the decision records: "
                       "approvals waiting or decided, blocked actions, policies, agents, applications and the evidence chain. "
                       "I'm read-only and every answer lists the records it used.", suggestions=SUGGESTIONS[:6])

    return _answer("NO_MATCH", "I'm not sure what you mean yet. I can tell you what is waiting for approval, what was approved, "
                   "rejected or blocked, how policies and agents are doing, and whether the evidence chain is intact. Try one of "
                   "these, or name a decision (dec_…), a policy (FIN-04) or an item (EX-003).", suggestions=SUGGESTIONS[:6])


def _rows_answer(text, items, now, pending_cols=False):
    items = sorted(items, key=lambda r: r["at"])[:MAX_ROWS]
    age = lambda r: (f'{int((now - r["at"]) // 86400)} d' if now - r["at"] >= 86400 else
                     f'{max(1, int((now - r["at"]) // 3600))} h' if now - r["at"] >= 3600 else "< 1 h")
    return _answer("ANSWERED", text + ".", ["Item", "From", "Assigned to", "Waiting"],
                   [[_title(r), r["application"]["name"], (r.get("assignment") or {}).get("to") or "Any approver", age(r)] for r in items],
                   [_link(r) for r in items], [_cite(r) for r in items], ["What is assigned to me?", "What was approved or rejected?"])


# ---------------------------------------------------------------------------------------------------------------------
# Conversation layer (2026-11-16): small talk without a model, and optional AI phrasing over the exact rule results.
# ---------------------------------------------------------------------------------------------------------------------
GREETING = re.compile(r"^(?:hi+|hello|hey+|hiya|howdy|yo|greetings|good\s+(?:morning|afternoon|evening|day))"
                      r"(?:\s+(?:there|trusttwin|team|all|everyone))?(?:[\s!.,?:;-]+|$)", re.I)
THANKS = re.compile(r"(?:thanks|thank\s+you|thx|ty|cheers|great|perfect|ok(?:ay)?|cool|nice|got\s+it|awesome|brilliant)"
                    r"(?:\s+(?:a\s+lot|so\s+much|very\s+much|trusttwin))?[\s!.,]*", re.I)
BYE = re.compile(r"(?:bye|goodbye|see\s+you|see\s+ya|later|that'?s\s+all)[\s!.,]*", re.I)
HELP = re.compile(r"(?:help|\?|what\s+can\s+you\s+do|who\s+are\s+you|what\s+are\s+you|what\s+do\s+you\s+do|"
                  r"how\s+(?:do|does)\s+(?:this|it|you)\s+work)[\s!.?]*", re.I)

# What the model may choose. Each intent becomes a plain question the rules already answer, so a routed question gets
# exactly the same records, numbers and citations as a typed one.
INTENTS = {
    "pending": ("items waiting for a person to approve (open, outstanding, stuck, in the queue)", "what is waiting for approval"),
    "assigned_to_me": ("items waiting for the person who is asking", "what is assigned to me"),
    "approved": ("items that were approved", "what was approved"),
    "rejected": ("items that were rejected", "what was rejected"),
    "decided": ("items that were approved or rejected (outcomes)", "what was approved or rejected"),
    "blocked": ("actions TrustOps blocked or denied", "what was blocked"),
    "evidence": ("whether the evidence / hash chain is intact (tamper check)", "is the evidence chain intact"),
    "policies": ("the list of policies (rules) and whether each is on", "which policies are on"),
    "policy": ("one specific policy; needs params.policy_id", "what does {policy_id} do"),
    "decision": ("one decision record; needs params.decision_id", "tell me about {decision_id}"),
    "item": ("decisions about an item reference such as EX-003; needs params.item_ref", "decisions about {item_ref}"),
    "agents": ("which agents asked TrustOps for decisions, most active first", "which agents are most active"),
    "applications": ("connected applications and their decisions", "which applications are connected"),
    "summary": ("overall numbers / overview of decisions", "give me a summary"),
    "smalltalk": ("greeting, thanks or chit-chat", None),
    "help": ("what TrustTwin can do", None),
    "unknown": ("anything else, including requests to approve, change or do something", None),
}
SPANS = {"today": " today", "yesterday": " yesterday", "week": " this week", "month": " this month"}
POLICY_ONLY = re.compile(r"(?:FIN|LS|POL|DEFAULT|MAKER)-?\d*", re.I)
ITEM_ONLY = re.compile(r"[A-Z]{2,5}(?:-[A-Z0-9]{2,})+", re.I)

# Grounding check: every number and identifier the model writes must already be in the facts it was given.
# A number is a free-standing figure: digits inside ids (EX-003, FIN-04, dec_…, hashes) do not count, so an id in the
# facts cannot "ground" an invented count. A date such as 2026-11-16 is one token.
NUMBER = re.compile(r"(?<![\w.-])\d[\d,]*(?:\.\d+)?(?:-\d+)*(?![\w-])")
IDENTS = [re.compile(r"\bdec_[0-9a-f]{6,}\b", re.I), re.compile(r"\b[A-Z]{2,5}(?:-[A-Z0-9]{2,})+\b"),
          re.compile(r"\b(?:FIN|LS|POL|MAKER)-\d+\b"), re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\b"),
          re.compile(r"\b[0-9a-f]{12,}\b", re.I)]

UNDERSTAND_SYSTEM = (
    "You route questions for TrustTwin, a read-only assistant that answers from an organisation's AI-governance decision "
    "records. Choose exactly one intent from `intents` for the user's question and fill `params` only when the intent "
    "needs them. Copy ids exactly as they appear in the question; never invent one. If the question asks to approve, "
    "reject, change, send or do anything, or is about something else, choose \"unknown\". "
    'Reply with JSON only: {"intent": "<name>", "params": {"span": "today|yesterday|week|month" or null, '
    '"decision_id": null, "policy_id": null, "item_ref": null}}')
PHRASE_SYSTEM = (
    "You are TrustTwin, a friendly, read-only governance assistant. Write a short, natural reply (at most three "
    "sentences) to the user's question using ONLY the facts provided. Do not add any number, name, id, date, total or "
    "claim that is not in the facts, and do not guess. Do not describe the data format; a table with the records is "
    "shown under your reply, so summarise rather than list every row. Never say you approved, rejected or changed "
    'anything. Reply with JSON only: {"answer": "<your reply>"}')

BUDGET_SECONDS = float(os.environ.get("TRUSTOPS_ASSISTANT_TIMEOUT", "8"))
_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="trusttwin-model")
_client_cache: dict = {"client": None, "failed_at": 0.0}


def model_client():
    """The model TrustTwin may use, or None. Its own switch, TRUSTOPS_ASSISTANT_MODEL=vertex, so turning it on changes
    nothing else in TrustOps (TAAD_LLM_PROVIDER and the assessment agents keep their own settings)."""
    if os.environ.get("TRUSTOPS_ASSISTANT_MODEL", "").strip().lower() != "vertex":
        return None
    if _client_cache["client"] is not None:
        return _client_cache["client"]
    if _client_cache["failed_at"] and time.monotonic() - _client_cache["failed_at"] < 60:   # don't retry a broken set-up per question
        return None
    try:
        from google import genai
        from google.genai import types

        from .llm import VertexModelClient
        raw = genai.Client(vertexai=True, project=os.environ["GOOGLE_CLOUD_PROJECT"],
                           location=os.environ.get("TAAD_VERTEX_LOCATION", "europe-west1"),
                           http_options=types.HttpOptions(timeout=int(BUDGET_SECONDS * 1000)))
        _client_cache["client"] = VertexModelClient(client=raw)
    except Exception as e:  # noqa: BLE001 - any set-up failure means "no model"; the rules still answer
        _client_cache["failed_at"] = time.monotonic()
        _log("client", e)
        return None
    return _client_cache["client"]


def model_name(model) -> str:
    return f"vertex:{getattr(model, 'model_id', 'model')}" if model is not None else "deterministic"


def _log(stage, err):
    # Only the stage and the error type: never the question, the records or the model's words.
    print(json.dumps({"event": "TRUSTTWIN_MODEL_FALLBACK", "stage": stage, "error_type": type(err).__name__}), flush=True)


def _ask_model(model, system, user, max_tokens, deadline):
    left = deadline - time.monotonic()
    if left <= 0.2:
        raise TimeoutError("assistant model budget used up")
    raw = _POOL.submit(model.complete, system, user, max_tokens).result(timeout=left)
    raw = str(raw or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`").split("\n", 1)[-1]
    out = json.loads(raw)
    if not isinstance(out, dict):
        raise ValueError("model reply is not a JSON object")
    return out


def _nums(text):
    out = set()
    for m in NUMBER.findall(text):
        if "-" in m:          # a date: compared as written
            out.add(m)
            continue
        try:
            out.add(str(Decimal(m.replace(",", "")).normalize()))
        except InvalidOperation:
            continue
    return out


def grounded(reply, *sources):
    """True when every number and every identifier in `reply` also appears in one of `sources`."""
    src = " ".join(sources)
    if not _nums(reply) <= _nums(src):
        return False
    low = src.lower()
    return all(m.lower() in low for rx in IDENTS for m in rx.findall(reply))


def _route(model, q, rules, deadline):
    """Ask the model which supported question this is. Returns a plain question for the rules, "smalltalk", "help" or
    None (use the rules on the original text). Ids must be in the question and in the expected form."""
    user = json.dumps({"question": q, "intents": {k: v[0] for k, v in INTENTS.items()}})
    got = _ask_model(model, UNDERSTAND_SYSTEM, user, 150, deadline)
    intent = got.get("intent")
    params = got.get("params") if isinstance(got.get("params"), dict) else {}
    if intent not in INTENTS or intent == "unknown":
        return None
    if intent in ("smalltalk", "help"):
        return intent
    vals = {}
    for key, rx in (("decision_id", DEC_ID), ("policy_id", POLICY_ONLY), ("item_ref", ITEM_ONLY)):
        if "{" + key + "}" in INTENTS[intent][1]:
            v = str(params.get(key) or "").strip()
            if not v or not rx.fullmatch(v) or v.lower() not in q.lower():
                return None
            if key == "policy_id" and not any(x["id"].lower() == v.lower() for x in rules):
                return None
            vals[key] = v
    return INTENTS[intent][1].format(**vals) + SPANS.get(str(params.get("span") or ""), "")


def _phrase(model, q, det, deadline):
    facts = {"summary": det["answer"], "columns": det["columns"], "rows": det["rows"][:MAX_ROWS]}
    got = _ask_model(model, PHRASE_SYSTEM, json.dumps({"question": q, "facts": facts}, default=str), 300, deadline)
    reply = " ".join(str(got.get("answer") or "").split())
    if not reply or len(reply) > 700:
        raise ValueError("empty or overlong reply")
    if not grounded(reply, json.dumps(facts, default=str), q):
        raise ValueError("reply not grounded in the records")
    return reply


def _smalltalk(kind, records):
    pending = sum(1 for r in records if r["decision"] == "ESCALATE" and not r.get("resolution") and not r.get("simulated")
                  and not str(r.get("action", "")).startswith("resolve_escalation:"))
    if kind == "greeting":
        now = (f" Right now {pending} item{'s are' if pending != 1 else ' is'} waiting for approval." if pending
               else " Nothing is waiting for approval right now.")
        text = ("Hi! I'm TrustTwin. I can tell you what is waiting for approval, what was approved, rejected or blocked, how "
                "policies and agents are doing, and whether the evidence chain is intact." + now + " What would you like to know?")
    elif kind == "thanks":
        text = "You're welcome! Anything else you'd like to know?"
    elif kind == "bye":
        text = "Bye for now. I'm here whenever you need me (Ctrl K)."
    else:
        text = ("I'm TrustTwin. I answer questions about this workspace's governance from the decision records: approvals "
                "waiting or decided, blocked actions, policies, agents, applications and the evidence chain. I'm read-only, "
                "and every answer lists the records it used.")
    return _answer("SMALLTALK", text, suggestions=SUGGESTIONS[:6 if kind == "help" else 4])


def answer(question, *, records, rules, verification, me, roles, approvers, now=None, model=None):
    """One question in, one answer out (the FinTwin answer shape plus `written_by` and `model`).

    Order: a greeting in front of a question is set aside; requests to act are refused by rule; small talk is
    answered without a model; with a model, it routes the question to a supported intent and then rephrases the exact
    result. Any model failure falls back to the rules' own answer."""
    ctx = dict(records=records, rules=rules, verification=verification, me=me, roles=roles, approvers=approvers, now=now)
    q = " ".join(str(question or "").split())[:500]
    g = GREETING.match(q)
    rest = q[g.end():].strip(" ,.!?;:-") if g else q

    def done(out, written_by="rules", used=None):
        return {**out, "written_by": written_by, "model": model_name(used)}

    if g and not rest:
        return done(_smalltalk("greeting", records))
    acting = bool(WRITE.search(rest))
    if not acting:
        for rx, kind in ((THANKS, "thanks"), (BYE, "bye"), (HELP, "help")):
            if rx.fullmatch(rest):
                return done(_smalltalk(kind, records))
    if model is None or acting or not rest:   # requests to act always go to the rules, which refuse them
        return done(_rules(rest, **ctx))

    deadline = time.monotonic() + BUDGET_SECONDS
    asked = rest
    pm = POLICY_ID.search(rest)
    explicit = DEC_ID.search(rest) or ITEM_REF.search(rest) or (pm and any(x["id"].lower() == pm.group(0).lower() for x in rules))
    if not explicit:      # an exact id in the question is read by the rules directly; anything else is routed first
        try:
            routed = _route(model, rest, rules, deadline)
        except Exception as e:  # noqa: BLE001
            _log("understand", e)
            routed = None
        if routed in ("smalltalk", "help"):
            return done(_smalltalk("help" if routed == "help" else "greeting", records), used=model)
        asked = routed or rest
    det = _rules(asked, **ctx)
    if det["status"] not in ("ANSWERED", "ATTENTION", "NO_DATA"):
        return done(det, used=model)
    try:
        return done({**det, "answer": _phrase(model, rest, det, deadline)}, written_by="ai", used=model)
    except Exception as e:  # noqa: BLE001
        _log("phrase", e)
        return done(det, used=model)
