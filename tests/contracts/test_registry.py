import json
import shutil

import pytest
from question_engine import RegistryError, candidate_findings, eligible_questions, load_registry
from question_engine.branching import evaluate

ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
REG = load_registry(ROOT / "taad_question_control_registry_v1.0.0.json", ROOT / "taad_catalog_sha256.txt")


def test_counts_and_stable_ids():
    assert (len(REG.questions), len(REG.controls), len(REG.risk_rules)) == (318, 66, 18)
    assert len({q["question_id"] for q in REG.questions.values()}) == 318


def test_no_dangling_control_refs():
    assert all(q["control_id"] in REG.controls for q in REG.questions.values())


def test_checksum_pin_enforced(tmp_path):
    p = tmp_path / "r.json"
    shutil.copy(ROOT / "taad_question_control_registry_v1.0.0.json", p)
    p.write_text(p.read_text().replace("Organisation legal name", "Organisation legal name!"))
    with pytest.raises(RegistryError):
        load_registry(p, ROOT / "taad_catalog_sha256.txt")


def test_dangling_ref_rejected(tmp_path):
    raw = json.loads((ROOT / "taad_question_control_registry_v1.0.0.json").read_text())
    raw["question_bank"][0]["control_id"] = "CTL-NOPE"
    p = tmp_path / "r.json"
    p.write_text(json.dumps(raw))
    with pytest.raises(RegistryError):
        load_registry(p)


def test_branching_fixtures():
    bank = {"Q-BASE-002": "banking", "Q-BASE-005": "Agentic AI", "Q-BASE-006": "Yes"}
    health = {"Q-BASE-002": "healthcare", "Q-BASE-005": "Generative AI or copilot", "Q-BASE-006": "No", "Q-BASE-007": "No"}
    ids = lambda a: {q["question_id"] for s in ("org", "ai_system", "agent", "workflow", "system") for q in eligible_questions(REG, s, a)}  # noqa: E731
    assert {"Q-BANK-001", "Q-AGT-001"} <= ids(bank)
    assert "Q-HCR-001" not in ids(bank)
    assert "Q-AGT-001" not in ids(health) and "Q-HCR-001" in ids(health)


def test_unknown_operator_raises_no_eval():
    with pytest.raises(ValueError):
        evaluate({"__import__('os')": 1}, {})


def test_risk_unknown_handling_not_asserted_as_gap():
    res = candidate_findings(REG, {"Q-AIA-017": "Unknown"})
    assert all(f["rule_id"] != "R-013" for f in res["findings"])
    assert any(n["rule_id"] == "R-013" for n in res["not_assessed"])


def test_risk_candidates_have_citations_and_low_confidence_without_evidence():
    res = candidate_findings(REG, {"Q-AIA-017": "No", "Q-BASE-006": "Yes", "Q-HIT-015": "No"})
    ids = {f["rule_id"] for f in res["findings"]}
    assert {"R-013", "R-002"} <= ids
    for f in res["findings"]:
        assert f["citations"] and f["confidence"] == "low" and f["reviewer_status"] == "pending_review"
