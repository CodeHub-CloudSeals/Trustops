"""Action items 16/11 (lead's list + LedgerSight/TrustOps integration test): named approver, no self-assignment, bulk
approve/reject/assign, new default rules reach workspaces that saved their own rules, people are not agents, plain
"Recent changes", lighter lists, one date format, local http addresses, snapshot saves off the event loop."""
import asyncio
import re
import socket
import time

import httpx
import pytest
from app import app_integrations, decisions, persist
from app.main import STORE, app

FACTS = [{"label": "Bank line", "value": "500.00"}]


@pytest.fixture()
def public_dns(monkeypatch):
    monkeypatch.setattr(app_integrations.socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, 1, 6, "", ("93.184.216.34", 443))])


def key_for(c, h, sub="admin@t-bank", name="LedgerSight"):
    r = c.post("/v1/integrations", headers=h(sub), json={"name": name})
    assert r.status_code == 200, r.text
    return r.json()["trustops_key"]


def submit(c, key, who="staff@firm.example", facts=FACTS, **extra):
    r = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={
        "actor": {"type": "human", "id": who}, "action": "submit_for_review", "client": "client-a", "amount_minor": 50_000,
        "currency": "USD", "title": f"Item {time.time_ns()}", **({"facts": facts} if facts else {}), **extra})
    assert r.status_code == 200, r.text
    return r.json()["decision_id"]


def test_named_approver_is_binding(env):
    c, h = env
    key = key_for(c, h)
    did = submit(c, key, assign_to="controller@t-bank")
    r = c.post(f"/v1/decisions/{did}/resolve", headers=h("controller2@t-bank"), json={"outcome": "approve", "reason": "ok"})
    assert r.status_code == 403 and r.json()["code"] == "assigned_to_someone_else" and "controller@t-bank" in r.json()["message"]
    r = c.post(f"/v1/decisions/{did}/resolve", headers=h("admin@t-bank"), json={"outcome": "approve", "reason": "ok"})
    assert r.status_code == 403                                                     # administrators too
    # reassigning is allowed for approvers and recorded; then the new assignee decides
    assert c.post(f"/v1/decisions/{did}/assign", headers=h("controller2@t-bank"), json={"to": "controller2@t-bank"}).status_code == 200
    r = c.post(f"/v1/decisions/{did}/resolve", headers=h("controller2@t-bank"), json={"outcome": "approve", "reason": "ok"})
    assert r.status_code == 200 and r.json()["assignment"]["history"][0]["to"] == "controller@t-bank"
    st = c.get(f"/v1/decisions/{did}/status", headers={"X-TrustOps-Key": key}).json()
    assert st["final"] == "APPROVED" and st["resolved_by"] == "controller2@t-bank"
    # nobody named: any approver, as before
    open_item = submit(c, key)
    assert c.post(f"/v1/decisions/{open_item}/resolve", headers=h("controller@t-bank"), json={"outcome": "reject", "reason": "no"}).status_code == 200


def test_requester_can_never_be_named_approver(env):
    c, h = env
    key = key_for(c, h)
    r = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={
        "actor": {"type": "human", "id": "Controller@T-Bank"}, "action": "submit_for_review", "assign_to": "controller@t-bank"})
    assert r.status_code == 422 and r.json()["code"] == "requester_cannot_approve"
    did = submit(c, key, who="controller@t-bank")
    r = c.post(f"/v1/decisions/{did}/app-assign", headers={"X-TrustOps-Key": key}, json={"to": "controller@t-bank", "by": "controller@t-bank"})
    assert r.status_code == 422 and "cannot be its approver" in r.json()["message"]
    r = c.post(f"/v1/decisions/{did}/assign", headers=h("admin@t-bank"), json={"to": "controller@t-bank"})
    assert r.status_code == 422
    assert c.post(f"/v1/decisions/{did}/assign", headers=h("admin@t-bank"), json={"to": "controller2@t-bank"}).status_code == 200
    # an administrator who sent an item with nobody named may still resolve it: recorded as a self-approval (unchanged rule)
    own = submit(c, key, who="admin@t-bank")
    r = c.post(f"/v1/decisions/{own}/resolve", headers=h("admin@t-bank"), json={"outcome": "approve", "reason": "mine"})
    assert r.status_code == 200 and r.json()["resolution"]["self_resolved"] is True


def test_bulk_approve_reject_and_assign(env):
    c, h = env
    key = key_for(c, h)
    good = [submit(c, key) for _ in range(3)]
    elsewhere = submit(c, key, assign_to="controller2@t-bank")
    own = submit(c, key, who="controller@t-bank")
    bare = submit(c, key, facts=None)
    bulk = lambda who, body: c.post("/v1/decisions-bulk", headers=h(who), json=body)
    assert bulk("risk@t-bank", {"ids": good, "op": "approve", "reason": "x"}).status_code == 403
    assert bulk("controller@t-bank", {"ids": good, "op": "approve"}).status_code == 422            # one reason is required
    assert bulk("controller@t-bank", {"ids": [], "op": "approve", "reason": "x"}).status_code == 422
    assert bulk("controller@t-bank", {"ids": good, "op": "delete", "reason": "x"}).status_code == 422
    assert bulk("controller@t-bank", {"ids": ["x"] * 201, "op": "approve", "reason": "x"}).status_code == 422
    out = bulk("controller@t-bank", {"ids": [*good, elsewhere, own, bare, "dec_missing", good[0]], "op": "approve", "reason": "Checked in batch"}).json()
    res = {x["id"]: x for x in out["results"]}
    assert out["done"] == 3 and out["failed"] == 4 and len(out["results"]) == 7                     # duplicates once
    assert all(res[d]["ok"] for d in good)
    assert res[elsewhere]["code"] == "assigned_to_someone_else" and res[own]["code"] == "maker_checker_violation"
    assert res[bare]["code"] == "details_required" and res["dec_missing"]["status"] == 404
    recs = [r for r in STORE.decisions if r["action"] == "resolve_escalation:approve"]
    assert len(recs) == 3 and {r["resource"] for r in recs} == set(good)                           # each recorded on its own
    assert c.get("/v1/decisions-verify", headers=h("admin@t-bank")).json()["valid"]
    # assign many, then reject many
    more = [submit(c, key) for _ in range(2)]
    a = bulk("admin@t-bank", {"ids": [*more, own], "op": "assign", "to": "controller2@t-bank"}).json()
    assert a["done"] == 3
    a = bulk("admin@t-bank", {"ids": [own], "op": "assign", "to": "controller@t-bank"}).json()
    assert a["results"][0]["code"] == "requester_cannot_approve"
    rj = bulk("controller2@t-bank", {"ids": [*more, bare], "op": "reject", "reason": "Need the bank letter"}).json()
    assert rj["done"] == 3                     # rejecting needs no details; `bare` has nobody named, so any approver may
    assert all(c.get(f"/v1/decisions/{d}/status", headers={"X-TrustOps-Key": key}).json()["final"] == "REJECTED" for d in more)


def test_new_default_rules_reach_workspaces_that_saved_their_own(env):
    c, h = env
    old = [dict(r) for r in decisions.DEFAULT_RULES if r["id"] not in ("LS-01", "LS-02")]       # saved before LS-01/LS-02
    STORE.policy_rules["t-bank"] = old
    key = key_for(c, h)
    ask = lambda action, actor="agent": c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={
        "actor": {"type": actor, "id": "agent:recon"}, "action": action, "client": "client-a"}).json()
    d = ask("run.compute")
    assert d["decision"] == "ALLOW" and d["policy_id"] == "LS-02"                                  # was ESCALATE (DEFAULT) before 16/11
    assert ask("ledger.post")["policy_id"] == "LS-01"
    ids = [r["id"] for r in c.get("/v1/policies", headers=h("admin@t-bank")).json()["rules"]]
    assert ids[:3] == ["FIN-00", "LS-01", "LS-02"]                                                 # in their default place
    added = [e for e in STORE.audit if e["action"] == "policy.defaults_added"]
    assert len(added) == 1 and added[0]["ref"] == "LS-01,LS-02"
    hist = c.get("/v1/authority", headers=h("admin@t-bank")).json()["history"]
    assert any(e["text"] == "TrustOps added new default rules to this workspace: LS-01, LS-02" for e in hist)
    # an administrator deletes LS-02 on purpose: it is never added back
    rules = [r for r in c.get("/v1/policies", headers=h("admin@t-bank")).json()["rules"] if r["id"] != "LS-02"]
    assert c.put("/v1/policies", headers=h("admin@t-bank"), json={"rules": rules}).status_code == 200
    assert ask("run.compute")["policy_id"] == "DEFAULT"
    assert "LS-02" not in [r["id"] for r in c.get("/v1/policies", headers=h("admin@t-bank")).json()["rules"]]
    assert len([e for e in STORE.audit if e["action"] == "policy.defaults_added"]) == 1
    # saved before versions were recorded but already with LS-01 (LS-02 deleted then): left alone
    STORE.policy_rules.clear()
    STORE.policy_rules["t-health"] = [r for r in decisions.DEFAULT_RULES if r["id"] != "LS-02"]
    assert "LS-02" not in [r["id"] for r in c.get("/v1/policies", headers=h("admin@t-health")).json()["rules"]]
    # workspaces that never saved rules keep using the current defaults
    assert [r["id"] for r in c.get("/v1/policies", headers=h("admin@t-logistics")).json()["rules"]] == [r["id"] for r in decisions.DEFAULT_RULES]


def test_upgrade_rules_helper_keeps_order_and_custom_rules():
    custom = {"id": "MY-1", "name": "x", "actions": ["a"], "actor_types": [], "min_amount_minor": None, "decision": "DENY", "reason": "", "enabled": True}
    base = [r for r in decisions.DEFAULT_RULES if r["id"] not in ("LS-01", "LS-02")] + [custom]
    out, added = decisions.upgrade_rules(base, 1)
    assert added == ["LS-01", "LS-02"] and [r["id"] for r in out][:4] == ["FIN-00", "LS-01", "LS-02", "FIN-01"] and out[-1] == custom
    assert decisions.upgrade_rules(base, 2) == (base, [])


def test_people_are_not_registered_as_agents(env):
    c, h = env
    key = key_for(c, h)
    submit(c, key, who="staff-preparer")
    c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "agent", "id": "agent:recon"}, "action": "run.compute"})
    c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "service", "id": "nightly"}, "action": "read"})
    agents = c.get("/v1/authority", headers=h("admin@t-bank")).json()["agents"]
    assert sorted(a["actor_id"] for a in agents) == ["agent:recon", "nightly"]
    # registered as an "agent" before 16/11: hidden from the list
    STORE.agents["agt_legacy"] = {**agents[0], "id": "agt_legacy", "actor_type": "human", "actor_id": "cpa-reviewer"}
    assert "cpa-reviewer" not in [a["actor_id"] for a in c.get("/v1/authority", headers=h("admin@t-bank")).json()["agents"]]


def test_recent_changes_read_as_sentences(env):
    c, h = env
    key = key_for(c, h)
    c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "agent", "id": "agent:query"}, "action": "query.answer"})
    aid = c.get("/v1/authority", headers=h("admin@t-bank")).json()["agents"][0]["id"]
    c.patch(f"/v1/authority/agents/{aid}", headers=h("admin@t-bank"), json={"status": "suspended", "reason": "Unusual questions"})
    c.patch(f"/v1/authority/agents/{aid}", headers=h("admin@t-bank"), json={"status": "active", "allowed_clients": ["client-a"]})
    rules = c.get("/v1/policies", headers=h("admin@t-bank")).json()["rules"]
    rules[-1]["enabled"] = False
    c.put("/v1/policies", headers=h("admin@t-bank"), json={"rules": rules})
    did = submit(c, key, assign_to="controller@t-bank")
    c.post(f"/v1/decisions/{did}/resolve", headers=h("controller@t-bank"), json={"outcome": "reject", "reason": "no"})
    hist = c.get("/v1/authority", headers=h("admin@t-bank")).json()["history"]
    texts = [e["text"] for e in hist]
    assert texts[0].startswith("Rejected “Item ")                                               # newest first
    assert "Saved the policies: changed FIN-06" in texts
    assert "Resumed agent:query in LedgerSight; Limited agent:query in LedgerSight to client-a" in texts
    assert "Suspended agent:query in LedgerSight — reason: Unusual questions" in texts
    assert "Registered the application LedgerSight" == texts[-1]
    assert all(e["who"] == "admin@t-bank" for e in hist[1:]) and hist[0]["who"] == "controller@t-bank"
    assert decisions.describe_change({"action": "authority.agent.status=suspended", "ref": "m@Old"}) == "Suspended m in Old"   # old entries


def test_lists_are_light_and_full_on_request(env):
    c, h = env
    key = key_for(c, h)
    submit(c, key, facts=[{"label": f"F{i}", "value": "x" * 400} for i in range(20)], summary="Short", link="https://ls.example.com/#x")
    light = c.get("/v1/decisions?pending=true", headers=h("controller@t-bank")).json()["items"][0]
    assert set(light["details"]) == {"title", "summary", "link"} and "loaded_details" not in light and light["attachment_count"] == 0
    full = c.get("/v1/decisions?pending=true&full=true", headers=h("controller@t-bank")).json()["items"][0]
    assert len(full["details"]["facts"]) == 20
    assert len(c.get("/v1/decisions?pending=true", headers=h("controller@t-bank")).content) * 4 < len(c.get("/v1/decisions?pending=true&full=true", headers=h("controller@t-bank")).content)


def test_one_date_format_in_exports(env, public_dns):
    c, h = env
    key = key_for(c, h)
    submit(c, key)
    assert decisions.fmt_time(1794823399) == "16 Nov 2026, 10:03" and decisions.fmt_time(1793990000).startswith("6 Nov 2026, ")
    assert decisions.fmt_time(None) == "–"
    csv = c.get("/v1/decisions-export?fmt=csv", headers=h("risk@t-bank")).text.splitlines()
    assert csv[0].split(",")[2] == "time (UTC)" and re.search(r",\"?\d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2}:\d{2}\"?,", csv[1])


def test_http_application_address_only_in_a_local_test_setup():
    assert app_integrations._check_url("http://127.0.0.1:8791", allow_private=True) == "http://127.0.0.1:8791"
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        app_integrations._check_url("http://ls.example.com", allow_private=False)


def test_snapshot_save_does_not_block_other_requests(monkeypatch):
    """16/11 slow pages: a save (MBs to Cloud Storage) ran on the event loop, so every page waited behind it."""
    monkeypatch.setattr(persist, "enabled", lambda: True)
    monkeypatch.setattr(persist, "_save", lambda *a, **k: time.sleep(0.6))

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as ac:
            slow = asyncio.create_task(ac.post("/v1/registration-requests", json={}))
            await asyncio.sleep(0.05)
            t = time.perf_counter()
            r = await ac.get("/health")
            fast = time.perf_counter() - t
            await slow
            return r.status_code, fast
    status, fast = asyncio.run(go())
    assert status == 200 and fast < 0.3, fast
