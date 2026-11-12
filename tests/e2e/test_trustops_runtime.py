from copy import deepcopy

from app.main import STORE


class AgentModelStub:
    model_id = "test-bedrock-model"

    def __init__(self, *, disagree=False, broken=False):
        self.calls = []
        self.disagree = disagree
        self.broken = broken

    def complete(self, system, user, max_tokens=400):
        import json
        agent_id = user.split("AGENT ID: ", 1)[1].splitlines()[0]
        source = json.loads(user.split("<untrusted_source_json>", 1)[1].split("</untrusted_source_json>", 1)[0])
        self.calls.append(agent_id)
        if self.broken:
            return "not-json"
        policy = source.get("policy_decision", {})
        outputs = {
            "ledgersight.intake": {"valid": True, "anomalies": [], "rationale": "Required fields are present."},
            "ledgersight.match": {"selected_invoice_id": "I-2" if self.disagree else "I-1",
                                  "confidence": 0.99, "evidence_fields": ["reference", "amount_minor", "currency"],
                                  "rationale": "The supplied evidence supports this candidate."},
            "ledgersight.reconciliation": {"explanation": "The normalized values were compared.",
                                           "evidence_fields": ["reference", "amount_minor", "currency"]},
            "ledgersight.cash_allocation": {"recommendation": "hold" if policy.get("decision") != "ALLOW" else "prepare_proposal",
                                            "invoice_id": None if policy.get("decision") != "ALLOW" else "I-1",
                                            "rationale": "The deterministic gate controls the proposal."},
            "ledgersight.exception": {"queue": "none" if source.get("decision") == "ALLOW" else "controller_review",
                                      "summary": "The policy result is routed for review."},
            "ledgersight.audit": {"summary": "The runtime will hash the evidence.", "evidence_refs": []},
        }
        return json.dumps(outputs[agent_id])


def test_six_bedrock_workers_receive_allowlisted_inputs_and_keep_policy_authority():
    from app import trustops_runtime

    model = AgentModelStub()
    run = trustops_runtime.run_agents("tenant", "actor", request_body()["receipt"],
                                      request_body()["invoices"], request_body()["remittance"], client=model)
    assert len(model.calls) == 6
    assert run["agent_mode"] == "bedrock" and run["model_id"] == model.model_id
    assert run["policy_decision"]["decision"] == "ALLOW"
    assert all("recommendation" in step and step["model"] == model.model_id for step in run["agent_trace"])


def test_model_disagreement_escalates_and_invalid_output_fails_closed():
    from app import trustops_runtime

    body = request_body()
    invoices = body["invoices"] + [{"invoice_id": "I-2", "amount_minor": 25000, "currency": "USD", "reference": "INV-2"}]
    run = trustops_runtime.run_agents("tenant", "actor", body["receipt"], invoices, body["remittance"],
                                      client=AgentModelStub(disagree=True))
    assert run["policy_decision"]["decision"] == "ESCALATE"
    assert run["proposal"] is None and run["status"] == "escalated"
    try:
        trustops_runtime.run_agents("tenant", "actor", body["receipt"], body["invoices"], body["remittance"],
                                    client=AgentModelStub(broken=True))
    except trustops_runtime.RuntimeErrorCode as exc:
        assert exc.code == "agent_model_output_invalid"
    else:
        raise AssertionError("invalid model output must fail closed")


def test_workflow_api_uses_configured_model_and_reports_provider_mode(env, monkeypatch):
    from app import trustops_runtime

    c, h = env
    model = AgentModelStub()
    monkeypatch.setenv("TRUSTOPS_AGENT_MODEL_ID", model.model_id)
    monkeypatch.setattr(trustops_runtime, "configured_model_client", lambda: model)
    overview = c.get("/v1/agentops", headers=h("admin@t-bank")).json()
    assert overview["agent_mode"] == "bedrock_configured"
    assert overview["connector_status"] == "mock_only"
    response = c.post("/v1/workflows/ledgersight.ar_cash/runs", headers=h("admin@t-bank", **{"Idempotency-Key": "model-run"}),
                      json=request_body("R-MODEL"))
    assert response.status_code == 201, response.text
    assert response.json()["agent_mode"] == "bedrock"
    assert len(model.calls) == 6

    monkeypatch.setattr(trustops_runtime, "configured_model_client",
                        lambda: (_ for _ in ()).throw(trustops_runtime.RuntimeErrorCode(
                            "agent_model_unavailable", "TrustOps Bedrock model client could not be initialized")))
    unavailable = c.post("/v1/workflows/ledgersight.ar_cash/runs",
                          headers=h("admin@t-bank", **{"Idempotency-Key": "model-unavailable"}),
                          json=request_body("R-MODEL-UNAVAILABLE"))
    assert unavailable.status_code == 503
    assert unavailable.json()["code"] == "agent_model_unavailable"


def request_body(receipt_id="R-1", amount=25000, invoices=None):
    return {"receipt": {"receipt_id": receipt_id, "amount_minor": amount, "currency": "USD", "reference": "INV-1"},
            "invoices": invoices or [{"invoice_id": "I-1", "amount_minor": amount, "currency": "USD", "reference": "INV-1"}],
            "remittance": {"reference": "INV-1"}}


def test_six_agents_low_value_policy_precommit_gateway_and_evidence(env):
    c, h = env
    started = c.post("/v1/workflows/ledgersight.ar_cash/runs", headers=h("admin@t-bank", **{"Idempotency-Key": "run-1"}),
                     json=request_body())
    assert started.status_code == 201, started.text
    run = started.json()
    assert len(run["agent_trace"]) == 6
    assert run["policy_decision"]["decision"] == "ALLOW"
    assert run["status"] == "ready_to_prepare"

    prepared = c.post("/v1/execution/prepare", headers=h("admin@t-bank", **{"Idempotency-Key": "prepare-1"}),
                      json={"run_id": run["run_id"]})
    assert prepared.status_code == 200, prepared.text
    token = prepared.json()["action_token"]
    assert token and prepared.json()["connector"] == "mock_sap"
    assert prepared.json()["prepared_action"]["pre_commit_evidence_hash"]
    assert all(token not in str(v) for v in STORE.idempotency.values())
    idem_retry = c.post("/v1/execution/prepare", headers=h("admin@t-bank", **{"Idempotency-Key": "prepare-1"}),
                        json={"run_id": run["run_id"]})
    assert idem_retry.status_code == 200 and idem_retry.json()["action_token"] is None
    altered = token[:-1] + ("0" if token[-1] != "0" else "1")
    rejected = c.post("/v1/execution/execute", headers=h("admin@t-bank", **{"Idempotency-Key": "bad-token"}),
                      json={"run_id": run["run_id"], "action_token": altered})
    assert rejected.status_code == 403 and len(STORE.mock_sap) == 0

    executed = c.post("/v1/execution/execute", headers=h("admin@t-bank", **{"Idempotency-Key": "execute-1"}),
                      json={"run_id": run["run_id"], "action_token": token})
    assert executed.status_code == 200, executed.text
    assert executed.json()["acknowledgement"]["connector"] == "mock_sap"
    assert len(STORE.mock_sap) == 1
    retry = c.post("/v1/execution/execute", headers=h("admin@t-bank", **{"Idempotency-Key": "execute-1"}),
                   json={"run_id": run["run_id"], "action_token": token})
    assert retry.status_code == 200 and len(STORE.mock_sap) == 1
    assert c.post(f"/v1/evidence/{run['run_id']}/verify", headers=h("admin@t-bank")).json()["valid"] is True
    assert c.get(f"/v1/runs/{run['run_id']}", headers=h("admin@t-health")).status_code == 404


def test_high_value_requires_distinct_human_approval_and_precommit(env):
    c, h = env
    started = c.post("/v1/workflows/ledgersight.ar_cash/runs", headers=h("controller@t-bank", **{"Idempotency-Key": "run-hi"}),
                     json=request_body(receipt_id="R-HIGH", amount=150000))
    run = started.json()
    assert run["status"] == "approval_required"
    self_approval = c.post(f"/v1/approvals/{run['run_id']}/decision", headers=h("controller@t-bank", **{"Idempotency-Key": "self"}),
                           json={"decision": "approve", "reason": "I approve"})
    assert self_approval.status_code == 403 and self_approval.json()["code"] == "maker_checker_violation"
    assert c.post("/v1/execution/prepare", headers=h("controller@t-bank", **{"Idempotency-Key": "blocked"}),
                  json={"run_id": run["run_id"]}).status_code == 409

    risk_decision = c.post(f"/v1/approvals/{run['run_id']}/decision", headers=h("risk@t-bank", **{"Idempotency-Key": "risk"}),
                           json={"decision": "approve", "reason": "Risk review approved"})
    assert risk_decision.status_code == 403
    approval = c.post(f"/v1/approvals/{run['run_id']}/decision", headers=h("controller2@t-bank", **{"Idempotency-Key": "approve"}),
                      json={"decision": "approve", "reason": "Controller review approved"})
    assert approval.status_code == 200 and approval.json()["status"] == "approved_to_prepare"
    prepared = c.post("/v1/execution/prepare", headers=h("controller@t-bank", **{"Idempotency-Key": "prepare-hi"}),
                      json={"run_id": run["run_id"]})
    assert prepared.status_code == 200
    executed = c.post("/v1/execution/execute", headers=h("controller@t-bank", **{"Idempotency-Key": "execute-hi"}),
                      json={"run_id": run["run_id"], "action_token": prepared.json()["action_token"]})
    assert executed.status_code == 200


def test_ambiguous_duplicate_and_tampered_evidence_fail_closed(env):
    c, h = env
    invoices = [{"invoice_id": "I-1", "amount_minor": 25000, "currency": "USD", "reference": "INV-1"},
                {"invoice_id": "I-2", "amount_minor": 25000, "currency": "USD", "reference": "INV-1"}]
    started = c.post("/v1/workflows/ledgersight.ar_cash/runs", headers=h("admin@t-bank", **{"Idempotency-Key": "run-amb"}),
                     json=request_body("R-AMB", invoices=invoices))
    assert started.status_code == 201 and started.json()["status"] == "escalated"
    assert started.json()["policy_decision"]["decision"] == "ESCALATE"
    blocked = c.post("/v1/execution/prepare", headers=h("admin@t-bank", **{"Idempotency-Key": "prepare-amb"}),
                     json={"run_id": started.json()["run_id"]})
    assert blocked.status_code == 409
    dupe = c.post("/v1/workflows/ledgersight.ar_cash/runs", headers=h("admin@t-bank", **{"Idempotency-Key": "run-amb-2"}),
                  json=request_body("R-AMB", invoices=invoices))
    assert dupe.status_code == 409 and dupe.json()["code"] == "duplicate_receipt"

    valid_run = c.post("/v1/workflows/ledgersight.ar_cash/runs", headers=h("admin@t-bank", **{"Idempotency-Key": "run-clean"}),
                       json=request_body("R-CLEAN" )).json()
    prepared = c.post("/v1/execution/prepare", headers=h("admin@t-bank", **{"Idempotency-Key": "prepare-clean"}),
                      json={"run_id": valid_run["run_id"]}).json()
    c.post("/v1/execution/execute", headers=h("admin@t-bank", **{"Idempotency-Key": "execute-clean"}),
           json={"run_id": valid_run["run_id"], "action_token": prepared["action_token"]})
    original = deepcopy(STORE.runtime_evidence[0]["payload"])
    STORE.runtime_evidence[0]["payload"]["tampered"] = True
    result = c.post(f"/v1/evidence/{valid_run['run_id']}/verify", headers=h("admin@t-bank")).json()
    assert result["valid"] is False
    STORE.runtime_evidence[0]["payload"] = original


def test_only_sandbox_runtime_can_run_agents(env, monkeypatch):
    c, h = env
    from app import main
    monkeypatch.setattr(main, "ENV", "prod")
    assert main.runtime_enabled() is False
    monkeypatch.setattr(main, "ENV", "local")
    monkeypatch.setenv("TRUSTOPS_RUNTIME_MODE", "disabled")
    r = c.post("/v1/workflows/ledgersight.ar_cash/runs", headers=h("admin@t-bank", **{"Idempotency-Key": "disabled"}),
               json=request_body())
    assert r.status_code == 503 and r.json()["code"] == "runtime_unavailable"


def test_run_history_is_tenant_scoped_and_available_to_read_only_roles(env):
    c, h = env
    bank = c.post("/v1/workflows/ledgersight.ar_cash/runs", headers=h("admin@t-bank", **{"Idempotency-Key": "list-bank"}),
                  json=request_body("R-LIST-BANK")).json()
    health = c.post("/v1/workflows/ledgersight.ar_cash/runs", headers=h("admin@t-health", **{"Idempotency-Key": "list-health"}),
                    json=request_body("R-LIST-HEALTH")).json()

    listed = c.get("/v1/runs?limit=1", headers=h("contrib@t-bank"))
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["run_id"] == bank["run_id"]
    assert "tenant_id" not in listed.json()["items"][0]
    assert c.get(f"/v1/runs/{health['run_id']}", headers=h("admin@t-bank")).status_code == 404
    assert c.get("/v1/agentops", headers=h("contrib@t-bank")).json()["agents"]
