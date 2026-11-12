import pytest
from app import main

from tests.conftest import new_assessment


def staff_sub(email):
    return email                       # dev tokens use the email as the subject


def create(c, h, who="architect@cloudseals", **kw):
    body = {"title": "Demo Bank AI review", "customer_name": "Demo Bank plc", "frameworks_in_scope": ["eu_ai_act"], **kw}
    return c.post("/v1/cases", headers=h(who), json=body)


def test_case_lifecycle_acl_and_links(env):
    c, h = env
    r = create(c, h, tenant_id="t-bank", architects=["reviewer@cloudseals"])
    assert r.status_code == 201, r.text
    case = r.json()
    cid = case["case_id"]
    assert case["status"] == "draft" and case["lead_architect"] == "architect@cloudseals" and len(case["architects"]) == 2

    # customers cannot see or create cases; staff only see cases they are assigned to; admins see all
    assert c.get("/v1/cases", headers=h("admin@t-bank")).status_code == 403
    assert create(c, h, who="admin@t-bank").status_code == 403
    assert c.get("/v1/cases", headers=h("reviewer@cloudseals")).json()["total"] == 1
    main.STORE.users["other@cloudseals"] = {"tenant_id": None, "roles": ["cloudseals_reviewer"]}
    other = main.issue_token("other@cloudseals")
    hd = {"Authorization": f"Bearer {other}"}
    assert c.get("/v1/cases", headers=hd).json()["total"] == 0
    assert c.get(f"/v1/cases/{cid}", headers=hd).status_code == 404                      # unassigned looks like it does not exist

    # only the lead or an admin changes it; assigned reviewers can read
    assert c.patch(f"/v1/cases/{cid}", headers=h("reviewer@cloudseals"), json={"title": "x" * 5}).status_code == 403
    assert c.patch(f"/v1/cases/{cid}", headers=h("architect@cloudseals"), json={"tier": "tier_2", "notes": "n"}).json()["tier"] == "tier_2"
    assert c.patch(f"/v1/cases/{cid}", headers=h("architect@cloudseals"), json={"frameworks_in_scope": ["nope"]}).status_code == 422
    assert c.patch(f"/v1/cases/{cid}", headers=h("architect@cloudseals"), json={"architects": ["admin@t-bank"]}).status_code == 422   # not staff

    # assessments: must belong to the case's customer workspace and to only one case
    aid = new_assessment(c, h, "admin@t-bank")
    other_t = new_assessment(c, h, "admin@t-health")
    assert c.post(f"/v1/cases/{cid}/assessments", headers=h("architect@cloudseals"), json={"assessment_id": other_t}).status_code == 422
    linked = c.post(f"/v1/cases/{cid}/assessments", headers=h("architect@cloudseals"), json={"assessment_id": aid}).json()
    assert linked["assessments"][0]["assessment_id"] == aid
    second = create(c, h, tenant_id="t-bank").json()["case_id"]
    assert c.post(f"/v1/cases/{second}/assessments", headers=h("architect@cloudseals"), json={"assessment_id": aid}).status_code == 409

    # Delivery requires explicit customer publication, not just a ready preview.
    bad = c.post(f"/v1/cases/{cid}/status", headers=h("architect@cloudseals"), json={"status": "delivered", "reason": "done"})
    assert bad.status_code == 409 and bad.json()["code"] == "report_not_published"
    ok = c.post(f"/v1/cases/{cid}/status", headers=h("architect@cloudseals"), json={"status": "intake", "reason": "Documents received"}).json()
    assert ok["status"] == "intake" and [x["status"] for x in ok["status_history"]] == ["draft", "intake"]

    # audit feed includes case and linked-assessment events
    actions = {a["action"] for a in c.get(f"/v1/cases/{cid}/audit", headers=h("reviewer@cloudseals")).json()["items"]}
    assert {"case.created", "case.updated", "case.assessment_linked", "case.status.intake"} <= actions
    assert c.delete(f"/v1/cases/{cid}/assessments/{aid}", headers=h("architect@cloudseals")).json()["assessment_ids"] == []


def test_case_progress_reflects_validated_work_and_delivery_unlocks(env, monkeypatch):
    import json

    from tests.e2e.test_studio import DOC, Fake, gap, item, maturity_json, uc, upload
    c, h = env
    rev, cust = "reviewer@cloudseals", "admin@t-bank"
    cid = create(c, h, tenant_id="t-bank", architects=[rev]).json()["case_id"]
    aid = new_assessment(c, h, cust)
    c.post(f"/v1/cases/{cid}/assessments", headers=h("architect@cloudseals"), json={"assessment_id": aid})
    assert c.get(f"/v1/cases/{cid}", headers=h(rev)).json()["progress"]["report"] == "none"
    upload(c, h, aid, DOC.encode())
    ok = {"status": "validated", "reason": "Checked"}
    monkeypatch.setattr(main, "SWASKA_CLIENT", Fake({"use_cases": [uc()]}))
    uid = c.post(f"/v1/assessments/{aid}/inventory/run", headers=h(cust), json={}).json()["use_cases"][0]["use_case_id"]
    c.patch(f"/v1/assessments/{aid}/inventory/use-cases/{uid}", headers=h(rev), json=ok)
    assert c.get(f"/v1/cases/{cid}", headers=h(rev)).json()["progress"] | {} == {"validated_use_cases": 1, "validated_gaps": 0, "validated_roadmap_items": 0,
                                                                                  "maturity_score": None, "risk_level": "high_risk", "report": "draft"}
    monkeypatch.setattr(main, "SWASKA_CLIENT", Fake({"findings": [gap(evidence_use_case_ids=[uid])]}))
    gid = c.post(f"/v1/assessments/{aid}/gap-analysis/run", headers=h(rev), json={"framework_id": "eu_ai_act"}).json()["gaps"][0]["gap_id"]
    c.patch(f"/v1/assessments/{aid}/gaps/{gid}", headers=h(rev), json=ok)
    monkeypatch.setattr(main, "SWASKA_CLIENT", Fake(maturity_json(evidence_refs={p: [uid] for p in ("model_agnostic", "neuro_symbolic", "digital_twin", "evidence_fabric", "model_welfare")})))
    c.post(f"/v1/assessments/{aid}/maturity/run", headers=h(rev))
    c.patch(f"/v1/assessments/{aid}/maturity", headers=h(rev), json=ok)
    monkeypatch.setattr(main, "SWASKA_CLIENT", Fake({"roadmap_items": [item("a", gap_ids_addressed=[gid])], "executive_summary": "Act."}))
    rid = c.post(f"/v1/assessments/{aid}/roadmap/run", headers=h(rev)).json()["roadmap"][0]["item_id"]
    c.patch(f"/v1/assessments/{aid}/roadmap/{rid}", headers=h(rev), json=ok)
    prog = c.get(f"/v1/cases/{cid}", headers=h(rev)).json()["progress"]
    assert prog["report"] == "final" and prog["maturity_score"] == 1.5 and prog["validated_roadmap_items"] == 1
    premature = c.post(f"/v1/cases/{cid}/status", headers=h("architect@cloudseals"), json={"status": "delivered", "reason": "Preview ready"})
    assert premature.status_code == 409
    digest = c.get(f"/v1/assessments/{aid}/diagnostic-report?format=json", headers=h(rev)).json()["source_digest"]
    published = c.post(f"/v1/assessments/{aid}/diagnostic-report/publish", headers=h(rev, **{"Idempotency-Key": "publish"}),
                       json={"reason": "Final review complete", "source_digest": digest})
    assert published.status_code == 200, published.text
    done = c.post(f"/v1/cases/{cid}/status", headers=h("architect@cloudseals"), json={"status": "delivered", "reason": "Report sent"})
    assert done.status_code == 200 and done.json()["status"] == "delivered"
    listing = c.get("/v1/cases?status=delivered&q=demo", headers=h(rev)).json()
    assert listing["total"] == 1 and json.dumps(listing)


def test_staff_directory_lists_only_staff(env):
    c, h = env
    emails = {s["sub"] for s in c.get("/v1/staff", headers=h("reviewer@cloudseals")).json()["items"]}
    assert emails == {"architect@cloudseals", "reviewer@cloudseals"}
    assert c.get("/v1/staff", headers=h("admin@t-bank")).status_code == 403
    pytest.importorskip("fastapi")
