"""18/11: applications send many items in one request (POST /v1/decisions/batch, one state save), and an item sent
again after a lost answer (reuse_pending) is never created twice."""
from app import persist

from test_action_items_1611 import FACTS, key_for


def body(ref, **extra):
    return {"actor": {"type": "human", "id": "staff@firm.example"}, "action": "submit_for_review", "client": "client-a",
            "amount_minor": 50_000, "currency": "USD", "title": f"Item {ref}", "facts": FACTS, "resource": ref, **extra}


def test_batch_records_each_item_and_reports_failures(env, monkeypatch):
    c, h = env
    key = key_for(c, h)
    saves = []
    real = persist.save
    monkeypatch.setattr(persist, "save", lambda *a, **k: (saves.append(1), real(*a, **k))[1])
    items = [body(f"client-a|RUN-1|EX-{i:03d}", assign_to="controller@t-bank") for i in range(25)]
    items.append(body("client-a|RUN-1|EX-bad", assign_to="nobody@else.test"))           # refused, others still go
    r = c.post("/v1/decisions/batch", headers={"X-TrustOps-Key": key}, json={"items": items})
    assert r.status_code == 200, r.text
    res = r.json()["results"]
    assert len(res) == 26 and all(x["ok"] for x in res[:25])
    assert res[25]["ok"] is False and res[25]["status"] == 422 and res[25]["error"] == "not_a_reviewer"
    assert all(x["assigned_to"] == "controller@t-bank" and x["decision"] == "ESCALATE" for x in res[:25])
    assert len(set(x["decision_id"] for x in res[:25])) == 25
    if persist.enabled():
        assert len(saves) <= 1                                                          # one save for the whole batch
    st = c.get(f"/v1/decisions/{res[0]['decision_id']}/status", headers={"X-TrustOps-Key": key}).json()
    assert st["final"] == "PENDING" and st["assigned_to"] == "controller@t-bank"


def test_batch_needs_a_key_and_sane_input(env):
    c, h = env
    key = key_for(c, h)
    assert c.post("/v1/decisions/batch", json={"items": [body("x")]}).status_code == 401
    assert c.post("/v1/decisions/batch", headers={"X-TrustOps-Key": key}, json={"items": []}).status_code == 422
    assert c.post("/v1/decisions/batch", headers={"X-TrustOps-Key": key}, json={"items": [body("x")] * 201}).status_code == 422
    assert c.post("/v1/decisions/batch", headers={"X-TrustOps-Key": key}, json={"items": ["x"]}).status_code == 422


def test_reuse_pending_never_creates_a_second_copy(env):
    c, h = env
    key = key_for(c, h)
    k = {"X-TrustOps-Key": key}
    ref = "client-a|RUN-2|EX-001"
    first = c.post("/v1/decisions", headers=k, json=body(ref, assign_to="controller@t-bank", reuse_pending=True)).json()
    again = c.post("/v1/decisions", headers=k, json=body(ref, assign_to="controller2@t-bank", reuse_pending=True)).json()
    assert again["decision_id"] == first["decision_id"] and again["reused"] is True
    assert again["assigned_to"] == "controller2@t-bank"                                 # re-pointed to the new choice
    # without the flag the old behaviour stays (a new record)
    other = c.post("/v1/decisions", headers=k, json=body(ref, assign_to="controller@t-bank")).json()
    assert other["decision_id"] != first["decision_id"]
    # once decided, sending again (a resubmission) creates a new item
    c.post(f"/v1/decisions/{first['decision_id']}/resolve", headers=h("controller2@t-bank"), json={"outcome": "reject", "reason": "need proof"})
    c.post(f"/v1/decisions/{other['decision_id']}/resolve", headers=h("controller@t-bank"), json={"outcome": "reject", "reason": "dup"})
    third = c.post("/v1/decisions", headers=k, json=body(ref, assign_to="controller@t-bank", reuse_pending=True)).json()
    assert third["decision_id"] not in (first["decision_id"], other["decision_id"]) and not third.get("reused")


def test_policy_tests_are_never_waiting_for_approval(env):
    c, h = env
    sim = c.post("/v1/decisions/simulate", headers=h("admin@t-bank"), json={
        "actor": {"type": "human", "id": "someone@t-bank"}, "action": "submit_for_review", "amount_minor": 50_000})
    assert sim.status_code == 200 and sim.json()["decision"] == "ESCALATE"
    pending = c.get("/v1/decisions?pending=true", headers=h("controller@t-bank")).json()["items"]
    assert sim.json()["decision_id"] not in {r["id"] for r in pending}
    before = c.get("/v1/decisions-stats", headers=h("admin@t-bank")).json()["pending_approvals"]
    key = key_for(c, h)
    c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json=body("client-a|RUN-0001|EX-001"))
    assert c.get("/v1/decisions-stats", headers=h("admin@t-bank")).json()["pending_approvals"] == before + 1
