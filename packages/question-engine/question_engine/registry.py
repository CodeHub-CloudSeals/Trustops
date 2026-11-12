"""Registry import with SHA256 pinning and referential-integrity validation."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class RegistryError(Exception):
    pass


@dataclass(frozen=True)
class Registry:
    version: str
    sha256: str
    questions: dict[str, dict[str, Any]]
    controls: dict[str, dict[str, Any]]
    branch_rules: dict[str, dict[str, Any]]
    risk_rules: list[dict[str, Any]]
    option_sets: dict[str, list[str]]
    report_sections: list[dict[str, Any]]
    crosswalk: list[dict[str, Any]]
    raw: dict[str, Any]


def _check_condition(node: dict, q: dict, opts: dict) -> None:
    if "eq" in node or "in" in node:
        k = node["eq"] if "eq" in node else node["in"]
        ref = k["question_id"]
        if ref not in q:
            raise RegistryError(f"dangling question ref {ref}")
        if q[ref]["response_type"] not in ("select_one", "select_multi"):
            raise RegistryError(f"condition on non-select question {ref}")
        values = [k["value"]] if "value" in k else k["values"]
        if not set(values) <= set(opts[q[ref]["option_set"]]):
            raise RegistryError(f"invalid option value for {ref}: {values}")
    elif "all" in node or "any" in node:
        for child in node["all"] if "all" in node else node["any"]:
            _check_condition(child, q, opts)
    else:
        raise RegistryError(f"unsupported operator {sorted(node)}")


def load_registry(path: str | Path, checksum_file: str | Path | None = None, pin: str | None = None) -> Registry:
    """Load registry; refuse to activate when the pinned/recorded SHA256 does not match."""
    path = Path(path)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    expected = pin
    if expected is None and checksum_file is not None:
        expected = Path(checksum_file).read_text().split()[0]
    if expected is not None and expected != digest:
        raise RegistryError(f"registry checksum mismatch: expected {expected}, got {digest}")
    raw = json.loads(data)
    q = {x["question_id"]: x for x in raw["question_bank"]}
    if len(q) != len(raw["question_bank"]):
        raise RegistryError("duplicate question_id")
    if len(q) != raw["question_count"]:
        raise RegistryError("question_count mismatch")
    controls = {x["control_id"]: x for x in raw["control_library"]}
    br = {x["rule_id"]: x for x in raw["branch_rules"]}
    opts = raw["option_sets"]
    for x in q.values():
        if x["control_id"] not in controls:
            raise RegistryError(f"{x['question_id']}: dangling control {x['control_id']}")
        if x["option_set"] and x["option_set"] not in opts:
            raise RegistryError(f"{x['question_id']}: unknown option set")
        if x["branch_rule_id"] and x["branch_rule_id"] not in br:
            raise RegistryError(f"{x['question_id']}: unknown branch rule")
    for x in br.values():
        _check_condition(x["condition"], q, opts)
    for r in raw["risk_rules"]:
        if not set(r["question_refs"].split("|")) <= set(q):
            raise RegistryError(f"{r['rule_id']}: dangling question ref")
        if not set(r["control_ids"].split("|")) <= set(controls):
            raise RegistryError(f"{r['rule_id']}: dangling control ref")
        _check_condition(r["condition"], q, opts)
    return Registry(raw["version"], digest, q, controls, br, raw["risk_rules"], opts,
                    raw["report_sections"], raw["regulatory_crosswalk"], raw)
