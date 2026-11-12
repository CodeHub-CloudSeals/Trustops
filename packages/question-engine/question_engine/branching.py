"""Declarative branching interpreter. No eval/exec; unknown operators raise."""
from __future__ import annotations

from typing import Any

from .registry import Registry


def evaluate(node: dict, answers: dict[str, Any]) -> bool:
    if "eq" in node:
        x = node["eq"]
        return answers.get(x["question_id"]) == x["value"]
    if "in" in node:
        x = node["in"]
        return answers.get(x["question_id"]) in x["values"]
    if "all" in node:
        return all(evaluate(n, answers) for n in node["all"])
    if "any" in node:
        return any(evaluate(n, answers) for n in node["any"])
    raise ValueError(f"unsupported branch operator: {sorted(node)}")


def is_eligible(reg: Registry, question_id: str, answers: dict[str, Any]) -> bool:
    b = reg.questions[question_id].get("branch_rule_id", "")
    return not b or evaluate(reg.branch_rules[b]["condition"], answers)


def eligible_questions(reg: Registry, scope: str, answers: dict[str, Any]) -> list[dict[str, Any]]:
    """Questions for a scope: enabled, matching scope type, with branch rule satisfied."""
    return [q for q in reg.questions.values()
            if q["enabled"] and q["scope"] == scope and is_eligible(reg, q["question_id"], answers)]
