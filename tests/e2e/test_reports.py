import io
import zipfile

from tests.conftest import BANK, fill_required, new_assessment


def submitted(c, h):
    aid = new_assessment(c, h, "admin@t-bank")
    fill_required(c, h, "admin@t-bank", aid, BANK)
    assert c.post(f"/v1/assessments/{aid}/submit", headers=h("admin@t-bank", **{"Idempotency-Key": "s"})).status_code == 202
    rep = c.get(f"/v1/assessments/{aid}/reports", headers=h("reviewer@cloudseals")).json()["items"][0]
    return aid, rep["report_id"]


def test_draft_is_staff_only_and_preliminary_marked(env):
    c, h = env
    aid, rid = submitted(c, h)
    assert c.get(f"/v1/assessments/{aid}/reports/{rid}/download", headers=h("admin@t-bank")).status_code == 404
    r = c.get(f"/v1/assessments/{aid}/reports/{rid}/download", params={"format": "json"}, headers=h("reviewer@cloudseals"))
    m = r.json()
    assert m["status"] == "PRELIMINARY" and "NOT REVIEWED" in m["banner"] and len(m["sections"]) == 16


def test_docx_and_pdf_render_for_staff_and_customer_after_approval(env):
    c, h = env
    aid, rid = submitted(c, h)
    c.post(f"/v1/assessments/{aid}/reviews/{rid}/decision", headers=h("reviewer@cloudseals", **{"Idempotency-Key": "d"}),
           json={"decision": "approve", "reviewer_reason": "ok"})
    pdf = c.get(f"/v1/assessments/{aid}/reports/{rid}/download", params={"format": "pdf"}, headers=h("admin@t-bank"))
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and pdf.headers["X-Report-Status"] == "FINAL"
    docx = c.get(f"/v1/assessments/{aid}/reports/{rid}/download", params={"format": "docx"}, headers=h("admin@t-bank"))
    z = zipfile.ZipFile(io.BytesIO(docx.content))
    xml = z.read("word/document.xml").decode()
    assert "R-001" in xml and "Q-IAM-002" in xml and "PRELIMINARY" not in xml and "not a legal determination" in xml.lower()


def test_every_claim_links_to_question_and_rule(env):
    c, h = env
    aid, rid = submitted(c, h)
    m = c.get(f"/v1/assessments/{aid}/reports/{rid}/download", params={"format": "json"}, headers=h("reviewer@cloudseals")).json()
    claims = [i for s in m["sections"] for i in s["items"] if "question_id" in i and "assurance" in i]
    assert claims and all(i["question_id"] and i["assurance"] for i in claims)
    findings = [f for s in m["sections"] for f in s["findings"]]
    assert findings and all(f["citations"] and f["rule_version"] for f in findings)
    assert m["provenance"]["registry_sha256"] and m["provenance"]["answer_manifest_digest"]
    assert all(i["assurance"] == "Self-attested" for i in claims)  # a checked answer is never "verified"


def test_published_report_is_immutable_and_digest_stable(env):
    c, h = env
    aid, rid = submitted(c, h)
    c.post(f"/v1/assessments/{aid}/reviews/{rid}/decision", headers=h("reviewer@cloudseals", **{"Idempotency-Key": "d"}),
           json={"decision": "approve", "reviewer_reason": "ok"})
    d1 = c.get(f"/v1/assessments/{aid}/reports/{rid}/download", params={"format": "json"}, headers=h("admin@t-bank")).json()["content_digest"]
    # findings are frozen after publication
    assert c.post(f"/v1/assessments/{aid}/findings/R-001/review", headers=h("reviewer@cloudseals"),
                  json={"status": "No gap evidenced", "reason": "late"}).status_code == 409
    d2 = c.get(f"/v1/assessments/{aid}/reports/{rid}/download", params={"format": "json"}, headers=h("admin@t-bank")).json()["content_digest"]
    from app.main import STORE
    assert d1 == d2 == STORE.reports[rid]["published_digest"]


def test_reviewer_adjustment_changes_report_with_history(env):
    c, h = env
    aid, rid = submitted(c, h)
    r = c.post(f"/v1/assessments/{aid}/findings/R-001/review", headers=h("reviewer@cloudseals"),
               json={"status": "Confirmed gap", "reason": "Credentials doc reviewed"})
    assert r.status_code == 200 and r.json()["review_history"][0]["to"] == "Confirmed gap"
    assert c.post(f"/v1/assessments/{aid}/findings/R-001/review", headers=h("admin@t-bank"),
                  json={"status": "No gap evidenced", "reason": "x"}).status_code == 403
    m = c.get(f"/v1/assessments/{aid}/reports/{rid}/download", params={"format": "json"}, headers=h("reviewer@cloudseals")).json()
    assert any(f["status"] == "Confirmed gap" for s in m["sections"] for f in s["findings"])


def test_preliminary_customer_report_only_when_configured_and_marked(env):
    c, h = env
    aid, rid = submitted(c, h)
    assert c.get(f"/v1/assessments/{aid}/reports/{rid}/download", headers=h("admin@t-bank")).status_code == 404
    assert c.put("/v1/admin/tenants/t-bank/settings", headers=h("architect@cloudseals"), json={"allow_preliminary_report": True}).status_code == 200
    r = c.get(f"/v1/assessments/{aid}/reports/{rid}/download", params={"format": "json"}, headers=h("admin@t-bank"))
    assert r.status_code == 200 and r.json()["banner"]


def test_reject_and_clarification_never_publish(env):
    c, h = env
    aid, rid = submitted(c, h)
    r = c.post(f"/v1/assessments/{aid}/reviews/{rid}/decision", headers=h("reviewer@cloudseals", **{"Idempotency-Key": "d"}),
               json={"decision": "request_clarification", "reviewer_reason": "need evidence"})
    assert r.json()["status"] == "clarification_requested"
    assert c.get(f"/v1/assessments/{aid}/reports", headers=h("admin@t-bank")).json()["items"] == []
    q = c.get("/v1/admin/review-queue", headers=h("reviewer@cloudseals")).json()["items"]
    assert q and q[0]["status"] == "clarification_requested"


def test_hostile_answer_text_cannot_break_or_inject_into_reports(env):
    c, h = env
    aid = new_assessment(c, h, "admin@t-bank")
    hostile = "x\x00\x08<b>bold</b><script>alert(1)</script>&amp; {{7*7}} ${jndi:ldap://x}‮"
    # the API rejects it up front; also prove the renderer survives if it ever reaches it
    r = c.put(f"/v1/assessments/{aid}/answers/Q-BASE-001", headers=h("admin@t-bank", **{"If-Match": "0"}),
              json={"scope_id": "org", "value": hostile, "answer_status": "answered"})
    assert r.status_code == 422 and r.json()["code"] == "invalid_characters"
    fill_required(c, h, "admin@t-bank", aid, BANK)
    from app.main import STORE
    STORE.answers[(aid, "org", "Q-BASE-001")]["value"] = hostile
    c.post(f"/v1/assessments/{aid}/submit", headers=h("admin@t-bank", **{"Idempotency-Key": "s"}))
    rid = c.get(f"/v1/assessments/{aid}/reports", headers=h("reviewer@cloudseals")).json()["items"][0]["report_id"]
    for fmt in ("pdf", "docx", "json"):
        r = c.get(f"/v1/assessments/{aid}/reports/{rid}/download", params={"format": fmt}, headers=h("reviewer@cloudseals"))
        assert r.status_code == 200, (fmt, r.text[:200])
