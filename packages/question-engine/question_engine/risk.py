"""Deterministic risk rules -> candidate findings with citations and unknown handling.

A finding is never a legal determination: it is a *candidate* for reviewer adjustment.
"""
from __future__ import annotations

from typing import Any

from .branching import evaluate
from .registry import Registry


def candidate_findings(reg: Registry, answers: dict[str, Any],
                       evidence: dict[str, list[str]] | None = None) -> dict[str, list[dict]]:
    evidence = evidence or {}
    findings, not_assessed = [], []
    for r in reg.risk_rules:
        refs = r["question_refs"].split("|")
        missing = [x for x in refs if x not in answers]
        unknown = [x for x in refs if answers.get(x) == "Unknown"]
        if evaluate(r["condition"], answers):
            ev = sorted({e for x in refs for e in evidence.get(x, [])})
            # Self-attested answers without evidence stay low confidence.
            confidence = "medium" if ev else "low"
            findings.append({
                "rule_id": r["rule_id"], "rule_version": r["rule_version"],
                "title": r["title"], "severity_hint": r["severity_hint"],
                "status": r["default_finding_status"],
                "recommendation": r["recommendation"],
                "control_ids": r["control_ids"].split("|"),
                "citations": [{"question_id": x, "answer": answers[x]} for x in refs if x in answers],
                "evidence_refs": ev, "confidence": confidence,
                "requires_evidence_review": r["requires_evidence_review"],
                "unknown_inputs": unknown, "reviewer_status": "pending_review",
            })
        elif missing or unknown:
            not_assessed.append({"rule_id": r["rule_id"], "title": r["title"],
                                 "missing": missing, "unknown": unknown, "status": "Not assessed"})
    return {"findings": findings, "not_assessed": not_assessed}
