"""Four bounded advisory agents: evidence extraction, findings summary, POC draft notes, approval summary.

Deterministic first; an optional model may rephrase, but its JSON is schema-checked, grounded in existing
IDs/excerpts and rejected (deterministic fallback) on any violation. Nothing here writes to storage.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Optional

from .swaska import INJECTION, ModelClient

ROOT = Path(__file__).resolve().parents[3]
CATALOG = json.loads((ROOT / "taad_agent_manifests_v1.json").read_text())
AGENTS = {a["agent_id"]: {**a, "prohibited_capabilities": CATALOG["common_prohibited_capabilities"],
                          "behavior_policy": CATALOG["common_behavior_policy"], "version": CATALOG["version"],
                          "owner": CATALOG["owner"]} for a in CATALOG["agents"]}
CLAIM = re.compile(r"\b(legally compliant|compliant with|is compliant|are compliant|verified|certified)\b", re.I)
QLINE = re.compile(r"^\s*(Q-[A-Z]+-\d{3})\s*[:=]\s*(.+?)\s*$", re.M)
INVENTORY, GAP = "trustops.inventory_agent", "trustops.gap_analysis_agent"
MATURITY, ROADMAP, REPORT = "trustops.maturity_scorer", "trustops.roadmap_agent", "trustops.report_writer"
OVERLAY = "trustops.architecture_overlay"
EXTRACTION, FINDINGS, DRAFTER, APPROVAL = "cloudseals.swaska.evidence_extractor", "cloudseals.swaska.findings_summarizer", \
    "cloudseals.swaska.poc_drafter", "trustops.approval_summarizer"


class Tools:
    """Callable tools restricted to the agent manifest allowlist."""

    def __init__(self, agent_id: str, tools: dict[str, Callable[..., Any]]) -> None:
        self.allowed, self.tools = set(AGENTS[agent_id]["tool_allowlist"]), tools

    def call(self, name: str, **kw: Any) -> Any:
        if name not in self.allowed or name not in self.tools:
            raise PermissionError(f"tool not allowed: {name}")
        return self.tools[name](**kw)


def _ask(client: ModelClient, agent_id: str, task: str, data: dict) -> Any:
    system = (f"You are {agent_id}, a read-only advisory agent. {task} Output ONE JSON value only. "
              + " ".join(CATALOG["common_behavior_policy"]))
    return json.loads(client.complete(system, f"<untrusted>{json.dumps(data)[:20000]}</untrusted>", max_tokens=1500))


def _clean(text: Any, limit: int = 1500) -> str:
    if not isinstance(text, str) or not text.strip() or len(text) > limit or CLAIM.search(text):
        raise ValueError("invalid or non-compliant text")
    return text


def _envelope(agent_id: str, mode: str, **out: Any) -> dict:
    return {"agent_id": agent_id, "agent_version": AGENTS[agent_id]["version"], "mode": mode,
            "advisory_only": True, "persisted": False, **out}


def extract_candidates(client: Optional[ModelClient], tools: Tools, evidence_id: str, known_qids: set[str]) -> dict:
    text = tools.call("get_evidence_text", evidence_id=evidence_id)
    flagged = bool(INJECTION.search(text))
    items = [{"question_id": q, "candidate_value": v[:500], "excerpt": m.group(0).strip()[:600],
              "evidence_id": evidence_id, "status": "UNVERIFIED_CANDIDATE"}
             for m in QLINE.finditer(text) for q, v in [m.groups()] if q in known_qids]
    mode = "deterministic"
    if client is not None:
        try:
            raw = _ask(client, EXTRACTION, "Extract candidate answers as a JSON list with keys "
                       + ", ".join(AGENTS[EXTRACTION]["output_item_required"]) + ". excerpt must be quoted verbatim.",
                       {"evidence_id": evidence_id, "text": text[:15000], "question_ids": sorted(known_qids)[:400]})
            checked = []
            for it in raw:
                if set(it) != set(AGENTS[EXTRACTION]["output_item_required"]) or it["question_id"] not in known_qids \
                        or it["evidence_id"] != evidence_id or it["status"] != "UNVERIFIED_CANDIDATE" \
                        or not isinstance(it["excerpt"], str) or it["excerpt"] not in text:
                    raise ValueError("ungrounded item")  # excerpt must literally exist in the evidence
                _clean(it["candidate_value"], 500)
                checked.append(it)
            items, mode = checked[:50], "model"
        except Exception:
            pass
    return _envelope(EXTRACTION, mode, items=items, injection_flagged=flagged,
                     note="Candidates are self-attested until a human accepts them and evidence is reviewed.")


def summarize_findings(client: Optional[ModelClient], tools: Tools) -> dict:
    findings = tools.call("get_candidate_findings")
    ids = {f["rule_id"] for f in findings}
    items = [{"rule_id": f["rule_id"], "summary": f"Candidate finding {f['rule_id']}: {f.get('recommendation', 'review required')}",
              "uncertainty": "Candidate for human review; no regulatory determination is made."} for f in findings]
    mode = "deterministic"
    if client is not None and findings:
        try:
            raw = _ask(client, FINDINGS, "Return a JSON list, one item per finding, keys rule_id, summary, uncertainty.",
                       {"findings": findings})
            if {i["rule_id"] for i in raw} != ids or len(raw) != len(ids) \
                    or any(set(i) != {"rule_id", "summary", "uncertainty"} for i in raw):
                raise ValueError("rule ids do not match")
            for i in raw:
                _clean(i["summary"]), _clean(i["uncertainty"])
            items, mode = raw, "model"
        except Exception:
            pass
    return _envelope(FINDINGS, mode, items=items)


def draft_notes(client: Optional[ModelClient], tools: Tools) -> dict:
    bp = tools.call("get_draft_blueprint")
    out = {"scope_summary": f"{len(bp['connector_drafts'])} read-only connector draft(s), {len(bp['policy_candidates_draft'])} policy "
                            f"candidate(s), {len(bp['approval_matrix_draft'])} human-approval rule(s); runtime activation is blocked.",
           "open_questions": ["Which systems are in POC scope?", "Who owns approval for each write action?",
                              "What baseline will shadow ROI be measured against?"],
           "uncertainty": "Draft notes only; all objects require human review before any activation."}
    mode = "deterministic"
    if client is not None:
        try:
            raw = _ask(client, DRAFTER, "Return one JSON object with keys scope_summary, open_questions (list of strings), uncertainty.",
                       {k: bp[k] for k in ("finding_refs", "connector_drafts", "policy_candidates_draft", "approval_matrix_draft")})
            if set(raw) != set(out) or not isinstance(raw["open_questions"], list) or len(raw["open_questions"]) > 10:
                raise ValueError("schema")
            _clean(raw["scope_summary"]), _clean(raw["uncertainty"])
            [_clean(q, 300) for q in raw["open_questions"]]
            out, mode = raw, "model"
        except Exception:
            pass
    return _envelope(DRAFTER, mode, **out)


def summarize_approval(client: Optional[ModelClient], tools: Tools) -> dict:
    run = tools.call("get_workflow_run")
    pd = run["policy_decision"]
    out = {"summary": f"Receipt {run['receipt_id']} for {run['amount_minor'] / 100:.2f} {run['currency']}: status {run['status']}.",
           "decision_reason": f"{pd['decision']} ({pd['reason_code']}); approval_required={pd['approval_required']}.",
           "uncertainty": "Policy decision comes from the deterministic gate; this summary does not alter it."}
    mode = "deterministic"
    if client is not None:
        try:
            raw = _ask(client, APPROVAL, "Return one JSON object with keys summary, decision_reason, uncertainty.",
                       {"run": {k: run[k] for k in ("receipt_id", "amount_minor", "currency", "status", "policy_decision", "exception")}})
            if set(raw) != set(out):
                raise ValueError("schema")
            [_clean(raw[k]) for k in raw]
            # the model may not contradict the gate's reason code
            if pd["reason_code"] not in raw["decision_reason"]:
                raise ValueError("decision reason mismatch")
            out, mode = raw, "model"
        except Exception:
            pass
    return _envelope(APPROVAL, mode, **out)
