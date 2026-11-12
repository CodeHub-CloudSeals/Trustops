from tests.conftest import BANK, fill_required, new_assessment

H = lambda c: c  # noqa: E731


def test_bank_end_to_end(env):
    c, h = env
    aid = new_assessment(c, h, "admin@t-bank")
    # idempotency: same key returns same assessment
    assert new_assessment(c, h, "admin@t-bank") == aid
    fill_required(c, h, "admin@t-bank", aid, BANK)
    r = c.post(f"/v1/assessments/{aid}/submit", headers=h("admin@t-bank", **{"Idempotency-Key": "s1"}))
    assert r.status_code == 202, r.text
    digest = r.json()["answer_manifest_digest"]
    assert c.post(f"/v1/assessments/{aid}/submit", headers=h("admin@t-bank", **{"Idempotency-Key": "s1"})).json()["answer_manifest_digest"] == digest
    # answers frozen after submit
    r = c.put(f"/v1/assessments/{aid}/answers/Q-BASE-001", headers=h("admin@t-bank", **{"If-Match": "1"}),
              json={"scope_id": "org", "value": "x", "answer_status": "answered"})
    assert r.status_code == 409
    # customer cannot see draft findings/reports
    assert c.get(f"/v1/assessments/{aid}/findings", headers=h("admin@t-bank")).json()["items"] == []
    assert c.get(f"/v1/assessments/{aid}/reports", headers=h("admin@t-bank")).json()["items"] == []
    staff = c.get(f"/v1/assessments/{aid}/findings", headers=h("reviewer@cloudseals")).json()["items"]
    assert {"R-001", "R-002", "R-013"} <= {f["rule_id"] for f in staff}
    rep = c.get(f"/v1/assessments/{aid}/reports", headers=h("reviewer@cloudseals")).json()["items"][0]
    assert rep["status"] == "draft" and rep["provenance"]["registry_sha256"]
    # blueprint blocked before approval
    bp = {"report_id": rep["report_id"], "workflow_pack_id": "wp-1",
          "customer_security_signoff_ref": "SEC-1", "cloudseals_architect_signoff_ref": "ARCH-1", "success_criteria": ["Cut manual review time 30%"]}
    assert c.post(f"/v1/assessments/{aid}/poc-blueprints", headers=h("architect@cloudseals", **{"Idempotency-Key": "b0"}), json=bp).status_code == 409
    # reviewer approves -> customer sees
    d = c.post(f"/v1/assessments/{aid}/reviews/{rep['report_id']}/decision", headers=h("reviewer@cloudseals", **{"Idempotency-Key": "d1"}),
               json={"decision": "approve", "reviewer_reason": "Reviewed"})
    assert d.status_code == 200
    assert len(c.get(f"/v1/assessments/{aid}/reports", headers=h("admin@t-bank")).json()["items"]) == 1
    assert c.get(f"/v1/assessments/{aid}/findings", headers=h("admin@t-bank")).json()["items"]
    # blueprint requires both sign-offs, then is DRAFT only with runtime blocked
    nosign = dict(bp, cloudseals_architect_signoff_ref=None)
    assert c.post(f"/v1/assessments/{aid}/poc-blueprints", headers=h("architect@cloudseals", **{"Idempotency-Key": "b1"}), json=nosign).status_code == 409
    ok = c.post(f"/v1/assessments/{aid}/poc-blueprints", headers=h("architect@cloudseals", **{"Idempotency-Key": "b2"}), json=bp)
    assert ok.status_code == 201
    j = ok.json()
    assert j["state"] == "DRAFT" and j["credentials_provisioned"] is False and j["external_writes_enabled"] is False
    m = c.get("/v1/admin/metrics", headers=h("architect@cloudseals")).json()
    assert m["published_reports"] == 1 and m["poc_blueprints"] == 1


def test_missing_mandatory_blocks_submit(env):
    c, h = env
    aid = new_assessment(c, h, "admin@t-bank")
    r = c.post(f"/v1/assessments/{aid}/submit", headers=h("admin@t-bank", **{"Idempotency-Key": "s"}))
    assert r.status_code == 409 and r.json()["code"] == "missing_mandatory_answers"


def test_healthcare_branching_via_api(env):
    c, h = env
    aid = new_assessment(c, h, "admin@t-health", industry="healthcare")
    from tests.conftest import put
    put(c, h, "admin@t-health", aid, "Q-BASE-002", "healthcare")
    put(c, h, "admin@t-health", aid, "Q-BASE-005", "Generative AI or copilot")
    ids = {q["question_id"] for q in c.get(f"/v1/assessments/{aid}/questions", params={"scope_id": "org", "scope_type": "workflow"},
                                          headers=h("admin@t-health")).json()["questions"]}
    assert "Q-HCR-001" in ids and "Q-BANK-001" not in ids
