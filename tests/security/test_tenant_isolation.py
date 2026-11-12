from tests.conftest import new_assessment, put


def REG_SECTION(qid):
    from app.main import REG
    return REG.questions[qid]["section"]


def test_cross_tenant_is_indistinguishable_from_missing(env):
    c, h = env
    aid = new_assessment(c, h, "admin@t-bank")
    other = h("admin@t-health")
    for method, url, kw in [
        ("get", f"/v1/assessments/{aid}/questions", {"params": {"scope_id": "org"}}),
        ("get", f"/v1/assessments/{aid}/findings", {}),
        ("get", f"/v1/assessments/{aid}/reports", {}),
        ("post", f"/v1/assessments/{aid}/evidence/upload-url", {"json": {"filename": "a.pdf", "content_type": "application/pdf", "file_size_bytes": 5, "claimed_sha256": "a" * 64}}),
        ("post", f"/v1/assessments/{aid}/swaska/turns", {"json": {"scope_id": "org", "user_message": "hi", "parent_question_id": "Q-BASE-001"}}),
    ]:
        real = getattr(c, method)(url, headers=other, **kw)
        ghost = getattr(c, method)(url.replace(aid, "00000000-0000-0000-0000-000000000000"), headers=other, **kw)
        assert real.status_code == ghost.status_code == 404
        assert real.json()["code"] == ghost.json()["code"] and real.json()["message"] == ghost.json()["message"]
    assert c.get("/v1/assessments", headers=other).json()["items"] == []


def test_tenant_header_is_ignored(env):
    c, h = env
    aid = new_assessment(c, h, "admin@t-bank")
    r = c.get(f"/v1/assessments/{aid}/findings", headers=h("admin@t-health", **{"X-Tenant-Id": "t-bank"}))
    assert r.status_code == 404


def test_auth_required_and_forged_token_rejected(env):
    c, h = env
    assert c.get("/v1/assessments").status_code == 401
    assert c.get("/v1/assessments", headers={"Authorization": "Bearer forged.token"}).status_code == 401
    from app.security import issue_token
    t = issue_token("nobody@x")
    assert c.get("/v1/assessments", headers={"Authorization": f"Bearer {t}"}).status_code == 401


def test_role_permissions(env):
    c, h = env
    aid = new_assessment(c, h, "admin@t-bank")
    # contributor cannot create / submit
    assert c.post("/v1/assessments", headers=h("contrib@t-bank", **{"Idempotency-Key": "x"}),
                  json={"ai_system_name": "a", "industry": "banking", "questionnaire_version": "1.0.0"}).status_code == 403
    assert c.post(f"/v1/assessments/{aid}/submit", headers=h("contrib@t-bank", **{"Idempotency-Key": "x"})).status_code == 403
    # contributor cannot answer an unassigned section, can answer once assigned
    r = c.put(f"/v1/assessments/{aid}/answers/Q-BASE-002", headers=h("contrib@t-bank", **{"If-Match": "0"}),
              json={"scope_id": "org", "value": "banking", "answer_status": "answered"})
    assert r.status_code == 403 and r.json()["code"] == "not_assigned"
    sec = REG_SECTION("Q-BASE-002")
    assert c.post(f"/v1/assessments/{aid}/assignments", headers=h("contrib@t-bank"),
                  json={"sub": "contrib@t-bank", "sections": [sec]}).status_code == 403
    assert c.post(f"/v1/assessments/{aid}/assignments", headers=h("admin@t-bank"),
                  json={"sub": "contrib@t-bank", "sections": [sec]}).status_code == 200
    put(c, h, "contrib@t-bank", aid, "Q-BASE-002", "banking")
    # customers cannot review, see admin metrics, or create blueprints
    assert c.post(f"/v1/assessments/{aid}/reviews/x/decision", headers=h("admin@t-bank", **{"Idempotency-Key": "r"}),
                  json={"decision": "approve", "reviewer_reason": "x"}).status_code == 403
    assert c.get("/v1/admin/metrics", headers=h("admin@t-bank")).status_code == 403
    assert c.post(f"/v1/assessments/{aid}/poc-blueprints", headers=h("admin@t-bank", **{"Idempotency-Key": "p"}),
                  json={"report_id": "x", "workflow_pack_id": "w"}).status_code == 403


def test_optimistic_locking(env):
    c, h = env
    aid = new_assessment(c, h, "admin@t-bank")
    put(c, h, "admin@t-bank", aid, "Q-BASE-002", "banking")
    stale = c.put(f"/v1/assessments/{aid}/answers/Q-BASE-002", headers=h("admin@t-bank", **{"If-Match": "0"}),
                  json={"scope_id": "org", "value": "insurance", "answer_status": "answered"})
    assert stale.status_code == 409
    from app.main import STORE
    assert len([r for r in STORE.revisions if r["question_id"] == "Q-BASE-002"]) == 1


def test_idempotency_key_required(env):
    c, h = env
    assert c.post("/v1/assessments", headers=h("admin@t-bank"),
                  json={"ai_system_name": "a", "industry": "banking", "questionnaire_version": "1.0.0"}).status_code == 400


def test_tenant_settings_listing_is_cloudseals_admin_only(env):
    c, h = env
    response = c.get("/v1/admin/tenants", headers=h("architect@cloudseals"))
    assert response.status_code == 200
    assert {tenant["tenant_id"] for tenant in response.json()["items"]} >= {"t-bank", "t-health", "t-logistics"}
    assert c.get("/v1/admin/tenants", headers=h("admin@t-bank")).status_code == 403
