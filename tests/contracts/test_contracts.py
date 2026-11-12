import json
import re

import yaml
from app.main import ROOT, app

from tests.conftest import BANK, fill_required, new_assessment


def test_every_documented_endpoint_exists_in_running_app():
    spec = yaml.safe_load((ROOT / "taad_assessment_api_v1.yaml").read_text())
    norm = lambda p: re.sub(r"\{[^}]+\}", "{}", p)  # noqa: E731  (parameter names may differ)
    live = {norm(p): m for p, m in app.openapi()["paths"].items()}
    for path, methods in spec["paths"].items():
        for m in methods:
            assert m in live.get(norm(path), {}), f"{m.upper()} {path} documented but not implemented"


def test_blueprint_contains_every_contract_field_and_is_inert(env):
    c, h = env
    contract = json.loads((ROOT / "taad_integration_contracts_v1.json").read_text())
    aid = new_assessment(c, h, "admin@t-bank")
    fill_required(c, h, "admin@t-bank", aid, BANK)
    c.post(f"/v1/assessments/{aid}/submit", headers=h("admin@t-bank", **{"Idempotency-Key": "s"}))
    rid = c.get(f"/v1/assessments/{aid}/reports", headers=h("reviewer@cloudseals")).json()["items"][0]["report_id"]
    c.post(f"/v1/assessments/{aid}/reviews/{rid}/decision", headers=h("reviewer@cloudseals", **{"Idempotency-Key": "d"}),
           json={"decision": "approve", "reviewer_reason": "ok"})
    body = {"report_id": rid, "workflow_pack_id": "wp", "customer_security_signoff_ref": "S", "cloudseals_architect_signoff_ref": "A"}
    assert c.post(f"/v1/assessments/{aid}/poc-blueprints", headers=h("architect@cloudseals", **{"Idempotency-Key": "n"}), json=body).status_code == 422
    bp = c.post(f"/v1/assessments/{aid}/poc-blueprints", headers=h("architect@cloudseals", **{"Idempotency-Key": "y"}),
                json={**body, "success_criteria": ["x"]}).json()
    for f in contract["poc_blueprint_required_fields"]:
        assert any(k == f or k == f.replace("_ref", "") for k in bp), f
    assert bp["state"] == "DRAFT" and bp["credentials_provisioned"] is False and bp["blueprint_digest"]
    assert all(m["state"] == "DRAFT" and "EXECUTE" in m["prohibited_capabilities"] for m in bp["agent_manifests_draft"])
    assert {x["action"]: x["default"] for x in bp["authority_matrix_draft"]}["EXECUTE"] == "DENY"
    # event envelope matches contract
    ev = [e for e in __import__("app.main", fromlist=["STORE"]).STORE.events if e["type"] == "taad.poc.blueprint_approved.v1"][0]
    assert ev["payload"]["blueprint_digest"] == bp["blueprint_digest"]
