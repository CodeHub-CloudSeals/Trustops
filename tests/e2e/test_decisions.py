"""TrustOps policy decision point, application integrations and governance exports."""
import json
import socket

import pytest
from app import app_integrations
from app.main import STORE


@pytest.fixture()
def public_dns(monkeypatch):
    monkeypatch.setattr(app_integrations.socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, 1, 6, "", ("93.184.216.34", 443))])


def register(c, h, sub="admin@t-bank", name="Recon app"):
    r = c.post("/v1/integrations", headers=h(sub), json={"name": name, "category": "Finance", "base_url": "https://app.example.com",
                                                         "auth_type": "api_key", "api_key": "secret-value-123"})
    assert r.status_code == 200, r.text
    return r.json()


def ask(c, key, actor_type="agent", actor_id="match-agent", action="approve_match", amount=None):
    return c.post("/v1/decisions", headers={"X-TrustOps-Key": key},
                  json={"actor": {"type": actor_type, "id": actor_id}, "action": action, "amount_minor": amount, "client": "client-a"})


def test_key_shown_once_and_secrets_never_returned(env, public_dns):
    c, h = env
    app = register(c, h)
    assert app["trustops_key"].startswith("tok_") and app["has_trustops_key"]
    listed = c.get("/v1/integrations", headers=h("admin@t-bank")).json()["items"][0]
    body = json.dumps(listed)
    assert "trustops_key" not in listed and "key_hash" not in body and "secret-value-123" not in body
    stored = json.dumps(STORE.integrations)
    assert "secret-value-123" not in stored and app["trustops_key"] not in stored


def test_only_admin_registers_and_private_addresses_blocked(env, monkeypatch):
    c, h = env
    r = c.post("/v1/integrations", headers=h("controller@t-bank"), json={"name": "x", "base_url": "https://a.example.com", "auth_type": "bearer", "token": "t"})
    assert r.status_code == 403
    monkeypatch.setattr(app_integrations.socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, 1, 6, "", ("10.0.0.5", 443))])
    r = c.post("/v1/integrations", headers=h("admin@t-bank"), json={"name": "Internal", "base_url": "https://internal.example.com", "auth_type": "bearer", "token": "t"})
    assert r.status_code == 422
    r = c.post("/v1/integrations", headers=h("admin@t-bank"), json={"name": "Plain", "base_url": "http://a.example.com", "auth_type": "bearer", "token": "t"})
    assert r.status_code == 422


def test_allow_escalate_deny_and_default(env, public_dns):
    c, h = env
    key = register(c, h)["trustops_key"]
    assert ask(c, key, amount=5000).json()["decision"] == "ALLOW"
    esc = ask(c, key, amount=1_240_000).json()
    assert esc["decision"] == "ESCALATE" and esc["policy_id"] == "FIN-04" and esc["status"] == "pending_approval"
    deny = ask(c, key, actor_id="chat-agent", action="email_client").json()
    assert deny["decision"] == "DENY" and deny["policy_id"] == "FIN-02"
    unknown = ask(c, key, action="wire_funds").json()
    assert unknown["decision"] == "ESCALATE" and unknown["policy_id"] == "DEFAULT"
    assert ask(c, "tok_wrong").status_code == 401
    assert ask(c, "").status_code == 401


def test_tenant_isolation(env, public_dns):
    c, h = env
    key = register(c, h)["trustops_key"]
    ask(c, key, amount=5000)
    assert c.get("/v1/decisions", headers=h("admin@t-health")).json()["total"] == 0
    assert c.get("/v1/decisions", headers=h("admin@t-bank")).json()["total"] == 1


def test_maker_checker_and_status(env, public_dns):
    c, h = env
    key = register(c, h)["trustops_key"]
    did = ask(c, key, actor_type="human", actor_id="controller@t-bank", amount=2_000_000).json()["decision_id"]
    assert c.post(f"/v1/decisions/{did}/resolve", headers=h("contrib@t-bank"), json={"outcome": "approve", "reason": "ok"}).status_code == 403
    assert c.post(f"/v1/decisions/{did}/resolve", headers=h("controller@t-bank"), json={"outcome": "approve", "reason": "ok"}).status_code == 403
    assert c.post(f"/v1/decisions/{did}/resolve", headers=h("controller2@t-bank"), json={"outcome": "approve"}).status_code == 422
    assert c.post(f"/v1/decisions/{did}/resolve", headers=h("controller2@t-bank"), json={"outcome": "approve", "reason": "checked"}).status_code == 409  # no details
    next(x for x in STORE.decisions if x["id"] == did)["details"] = {"facts": [{"label": "Bank line", "value": "x"}]}
    assert c.post(f"/v1/decisions/{did}/resolve", headers=h("controller2@t-bank"), json={"outcome": "approve", "reason": "checked"}).status_code == 200
    assert c.post(f"/v1/decisions/{did}/resolve", headers=h("controller2@t-bank"), json={"outcome": "reject", "reason": "again"}).status_code == 409
    st = c.get(f"/v1/decisions/{did}/status", headers={"X-TrustOps-Key": key}).json()
    assert st["final"] == "APPROVED" and st["resolved_by"] == "controller2@t-bank"
    other = register(c, h, "admin@t-health", "Other")["trustops_key"]
    assert c.get(f"/v1/decisions/{did}/status", headers={"X-TrustOps-Key": other}).status_code == 404


def test_policies_edit_and_simulate(env, public_dns):
    c, h = env
    rules = c.get("/v1/policies", headers=h("admin@t-bank")).json()["rules"]
    for r in rules:
        if r["id"] == "FIN-02":
            r["decision"] = "ESCALATE"
    assert c.put("/v1/policies", headers=h("controller@t-bank"), json={"rules": rules}).status_code == 403
    assert c.put("/v1/policies", headers=h("admin@t-bank"), json={"rules": rules}).status_code == 200
    sim = c.post("/v1/decisions/simulate", headers=h("admin@t-bank"), json={"actor": {"type": "agent", "id": "chat"}, "action": "email_client"}).json()
    assert sim["decision"] == "ESCALATE"
    assert c.get("/v1/decisions-stats", headers=h("admin@t-bank")).json()["total"] == 0  # simulated are excluded
    bad = [{"id": "X", "actions": ["a"], "decision": "MAYBE"}]
    assert c.put("/v1/policies", headers=h("admin@t-bank"), json={"rules": bad}).status_code == 422
    assert c.post("/v1/policies/reset", headers=h("admin@t-bank")).status_code == 200


def test_chain_verify_detects_tampering_and_exports(env, public_dns):
    c, h = env
    key = register(c, h)["trustops_key"]
    for amt in (100, 200, 2_000_000):
        ask(c, key, amount=amt)
    v = c.get("/v1/decisions-verify", headers=h("risk@t-bank")).json()
    assert v["valid"] and v["checked"] == 3 and v["signed"] is False
    pack = c.get("/v1/decisions-export?fmt=json", headers=h("risk@t-bank"))
    assert pack.status_code == 200 and json.loads(pack.text)["verification"]["valid"]
    csv = c.get("/v1/decisions-export?fmt=csv", headers=h("risk@t-bank")).text
    assert csv.count("\n") == 4 and "FIN-04" in csv
    pdf = c.get("/v1/decisions-export?fmt=pdf", headers=h("risk@t-bank"))
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and pdf.headers["content-type"] == "application/pdf"
    STORE.decisions[1]["amount_minor"] = 1
    assert c.get("/v1/decisions-verify", headers=h("risk@t-bank")).json()["valid"] is False


def test_rotate_key_invalidates_old(env, public_dns):
    c, h = env
    app = register(c, h)
    new = c.post(f"/v1/integrations/{app['id']}/rotate-key", headers=h("admin@t-bank")).json()["trustops_key"]
    assert ask(c, app["trustops_key"]).status_code == 401
    assert ask(c, new, amount=10).status_code == 200


def test_state_is_persisted_with_store():
    from app import persist
    assert {"integrations", "decisions", "policy_rules"} <= set(persist.FIELDS)


def test_authority_registry_suspend_and_client_scope(env, public_dns):
    c, h = env
    key = register(c, h)["trustops_key"]
    assert ask(c, key, actor_id="match-agent", amount=100).json()["decision"] == "ALLOW"
    auth = c.get("/v1/authority", headers=h("risk@t-bank")).json()
    agent = next(a for a in auth["agents"] if a["actor_id"] == "match-agent")
    assert agent["status"] == "active" and agent["counts"]["ALLOW"] == 1 and agent["application"]["name"] == "Recon app"
    assert auth["can_edit"] is False and auth["matrix"]["cells"]["agent|email_client"][0]["decision"] == "DENY"
    assert any(x["user"] == "controller@t-bank" for x in auth["people"])
    url = f"/v1/authority/agents/{agent['id']}"
    assert c.patch(url, headers=h("controller@t-bank"), json={"status": "suspended", "reason": "x"}).status_code == 403
    assert c.patch(url, headers=h("admin@t-bank"), json={"status": "suspended"}).status_code == 422          # reason required
    assert c.patch(url, headers=h("admin@t-bank"), json={"status": "suspended", "reason": "Unusual behaviour"}).status_code == 200
    d = ask(c, key, actor_id="match-agent", amount=100).json()
    assert d["decision"] == "DENY" and d["policy_id"] == "AUTH-SUSPENDED"
    assert ask(c, key, actor_id="other-agent", amount=100).json()["decision"] == "ALLOW"                 # only that identity
    c.patch(url, headers=h("admin@t-bank"), json={"status": "active", "allowed_clients": ["client-b"]})
    d = ask(c, key, actor_id="match-agent", amount=100).json()                                             # asks for client-a
    assert d["decision"] == "DENY" and d["policy_id"] == "AUTH-SCOPE"
    c.patch(url, headers=h("admin@t-bank"), json={"allowed_clients": []})
    assert ask(c, key, actor_id="match-agent", amount=100).json()["decision"] == "ALLOW"
    hist = c.get("/v1/authority", headers=h("admin@t-bank")).json()["history"]
    assert any(e["action"].startswith("authority.agent.status=suspended") for e in hist)
    assert c.get("/v1/authority", headers=h("admin@t-health")).json()["agents"] == []                     # tenant isolation


def test_submit_for_review_is_approved_in_trustops(env, public_dns):
    c, h = env
    key = register(c, h)["trustops_key"]
    r = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={
        "actor": {"type": "human", "id": "staff@firm.example"}, "action": "submit_for_review", "client": "client-a",
        "amount_minor": 1_240_000, "currency": "USD", "title": "Unknown deposit 12,400.00",
        "summary": "No matching invoice", "link": "https://app.example.com/review/123",
        "facts": [{"label": "Bank line", "value": "14 Oct · DEPOSIT · 12,400.00"}],
        "lines": {"title": "Bank vs ledger", "columns": ["Source", "Amount"], "rows": [["Bank", "12,400.00"], ["Ledger", "—"]]}})
    d = r.json()
    assert d["decision"] == "ESCALATE" and d["policy_id"] == "FIN-00" and d["status"] == "pending_approval"
    pending = c.get("/v1/decisions?pending=true", headers=h("controller@t-bank")).json()["items"]
    det = pending[0]["details"]
    assert det["title"] == "Unknown deposit 12,400.00" and det["facts"][0]["label"] == "Bank line" and det["lines"]["rows"][0] == ["Bank", "12,400.00"]
    one = c.get(f"/v1/decisions/{d['decision_id']}", headers=h("risk@t-bank")).json()
    assert one["details"]["lines"]["columns"] == ["Source", "Amount"]
    assert c.get(f"/v1/decisions/{d['decision_id']}", headers=h("admin@t-health")).status_code == 404
    bad_lines = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "human", "id": "x"}, "action": "submit_for_review",
                                                                              "lines": {"columns": ["a", "b"], "rows": [["only one"]]}})
    assert bad_lines.status_code == 422
    assert c.post(f"/v1/decisions/{d['decision_id']}/resolve", headers=h("controller@t-bank"), json={"outcome": "reject", "reason": "Ask client for invoice"}).status_code == 200
    st = c.get(f"/v1/decisions/{d['decision_id']}/status", headers={"X-TrustOps-Key": key}).json()
    assert st["final"] == "REJECTED" and st["resolution_reason"] == "Ask client for invoice"
    bad = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "human", "id": "x"}, "action": "submit_for_review", "link": "javascript:alert(1)"})
    assert bad.status_code == 422


def test_risk_flags_agents_and_late_approvals(env, public_dns):
    c, h = env
    key = register(c, h)["trustops_key"]
    assert c.get("/v1/risk", headers=h("risk@t-bank")).json()["level"] == "normal"
    for _ in range(3):
        ask(c, key, actor_id="chat-agent", action="email_client")
    r = c.get("/v1/risk", headers=h("risk@t-bank")).json()
    assert r["level"] == "act" and r["agents_to_watch"][0]["actor_id"] == "chat-agent" and r["agents_to_watch"][0]["top_action"] == "email_client"
    aid = r["agents_to_watch"][0]["agent_id"]
    c.patch(f"/v1/authority/agents/{aid}", headers=h("admin@t-bank"), json={"status": "suspended", "reason": "emails"})
    r = c.get("/v1/risk", headers=h("risk@t-bank")).json()
    assert r["level"] == "normal" and r["agents_to_watch"][0]["status"] == "suspended"      # handled: still listed, no longer urgent
    did = ask(c, key, amount=5_000_000).json()["decision_id"]
    next(x for x in STORE.decisions if x["id"] == did)["at"] -= 30 * 3600
    r = c.get("/v1/risk", headers=h("risk@t-bank")).json()
    assert r["level"] == "act" and r["waiting_too_long"][0]["decision_id"] == did and len(r["trend"]) == 7
    assert any(x["policy_id"] == "FIN-02" and x["count"] == 3 for x in r["top_rules"])


def test_approval_needs_details_or_an_in_app_check(env, public_dns):
    c, h = env
    key = register(c, h)["trustops_key"]
    bare = ask(c, key, amount=5_000_000).json()["decision_id"]
    assert c.post(f"/v1/decisions/{bare}/resolve", headers=h("controller@t-bank"), json={"outcome": "approve", "reason": "ok", "checked_in_app": True}).status_code == 409  # no link to check
    linked = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "agent", "id": "m"}, "action": "approve_match",
                                                                          "amount_minor": 5_000_000, "link": "https://app.example.com/i/1"}).json()["decision_id"]
    ok = c.post(f"/v1/decisions/{linked}/resolve", headers=h("controller@t-bank"), json={"outcome": "approve", "reason": "seen in app", "checked_in_app": True})
    assert ok.status_code == 200 and ok.json()["resolution"]["basis"] == "checked_in_application"
    assert c.post(f"/v1/decisions/{bare}/resolve", headers=h("controller@t-bank"), json={"outcome": "reject", "reason": "send details"}).status_code == 200
    full = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "agent", "id": "m"}, "action": "approve_match", "amount_minor": 5_000_000,
        "compare": {"left_title": "Bank", "right_title": "Invoice", "rows": [["Amount", "50,000.00", "50,000.00"]]},
        "recommendation": "Approve", "consequence": "Invoice marked paid", "documents": [{"name": "Invoice", "url": "https://app.example.com/d/1"}]}).json()
    one = c.get(f"/v1/decisions/{full['decision_id']}", headers=h("controller@t-bank")).json()["details"]
    assert one["compare"]["rows"][0] == ["Amount", "50,000.00", "50,000.00"] and one["documents"][0]["name"] == "Invoice"
    ok = c.post(f"/v1/decisions/{full['decision_id']}/resolve", headers=h("controller@t-bank"), json={"outcome": "approve", "reason": "matches"})
    assert ok.json()["resolution"]["basis"] == "details_in_trustops"
    bad = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "agent", "id": "m"}, "action": "approve_match", "documents": [{"name": "x", "url": "http://a"}]})
    assert bad.status_code == 422


def test_load_details_from_the_application(env, public_dns, monkeypatch):
    import httpx
    c, h = env
    seen = {}

    def app(request):
        seen["url"], seen["key"] = str(request.url), request.headers.get("X-API-Key")
        if request.url.path.endswith("/missing"):
            return httpx.Response(404)
        return httpx.Response(200, json={"title": "Deposit 50,000.00", "compare": {"left_title": "Bank", "right_title": "Invoice",
                                                                                  "rows": [["Amount", "50,000.00", "50,000.00"]]},
                                         "recommendation": "Approve"})
    monkeypatch.setattr(app_integrations, "TRANSPORT", httpx.MockTransport(app))
    key = register(c, h)["trustops_key"]
    did = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "agent", "id": "m"}, "action": "approve_match",
                                                                       "amount_minor": 5_000_000, "resource": "item-42"}).json()["decision_id"]
    assert c.post(f"/v1/decisions/{did}/load-details", headers=h("risk@t-bank")).status_code == 403
    r = c.post(f"/v1/decisions/{did}/load-details", headers=h("controller@t-bank"))
    assert r.status_code == 200 and r.json()["loaded_details"]["compare"]["rows"][0][0] == "Amount"
    assert seen == {"url": "https://app.example.com/trustops/items/item-42", "key": "secret-value-123"}
    assert c.get("/v1/decisions-verify", headers=h("risk@t-bank")).json()["valid"]
    ok = c.post(f"/v1/decisions/{did}/resolve", headers=h("controller@t-bank"), json={"outcome": "approve", "reason": "matches"})
    assert ok.status_code == 200 and ok.json()["resolution"]["basis"] == "details_in_trustops"
    other = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "agent", "id": "m"}, "action": "approve_match",
                                                                         "amount_minor": 5_000_000, "resource": "missing"}).json()["decision_id"]
    bad = c.post(f"/v1/decisions/{other}/load-details", headers=h("controller@t-bank"))
    assert bad.status_code == 502 and "404" in bad.json()["detail"]["message"] if "detail" in bad.json() else bad.status_code == 502


def test_trustops_key_is_used_both_ways(env, public_dns, monkeypatch):
    import httpx
    c, h = env
    seen = {}
    monkeypatch.setattr(app_integrations, "TRANSPORT", httpx.MockTransport(lambda req: (seen.update(key=req.headers.get("X-TrustOps-Key")),
                                                                                      httpx.Response(200, json={"facts": [{"label": "Bank line", "value": "x"}]}))[1]))
    app = c.post("/v1/integrations", headers=h("admin@t-bank"), json={"name": "LedgerSight", "category": "Finance", "base_url": "https://ls.example.com"}).json()
    assert app["auth_type"] == "trustops_key" and app["secrets_set"] == []
    key = app["trustops_key"]
    did = ask(c, key, amount=5_000_000).json()["decision_id"]
    assert c.post(f"/v1/decisions/{did}/load-details", headers=h("controller@t-bank")).status_code == 200
    assert seen["key"] == key
    assert key not in json.dumps(STORE.integrations)          # stored encrypted only


def test_name_only_application_and_address_later(env, monkeypatch):
    c, h = env
    app = c.post("/v1/integrations", headers=h("admin@t-bank"), json={"name": "LedgerSight"}).json()
    assert app["trustops_key"].startswith("tok_") and app["status"] == "key_only" and app["base_url"] is None
    did = ask(c, app["trustops_key"], amount=5_000_000).json()["decision_id"]
    r = c.post(f"/v1/decisions/{did}/load-details", headers=h("controller@t-bank"))
    assert r.status_code == 409
    assert c.post(f"/v1/integrations/{app['id']}/test", headers=h("admin@t-bank")).json()["ok"] is False
    monkeypatch.setattr(app_integrations.socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, 1, 6, "", ("93.184.216.34", 443))])
    upd = c.patch(f"/v1/integrations/{app['id']}", headers=h("admin@t-bank"), json={"base_url": "https://ls.example.com"}).json()
    assert upd["base_url"] == "https://ls.example.com" and upd["status"] == "untested"
    assert c.patch(f"/v1/integrations/{app['id']}", headers=h("controller@t-bank"), json={"base_url": ""}).status_code == 403


def test_state_from_another_version_loads_and_keeps_unknown_fields():
    import json as _j
    from app import persist
    from app.store import Store
    s = Store()
    persist._apply(s, _j.dumps({"users": {"u": {"tenant_id": "t"}}, "pocs": {"p1": {"x": 1}}}))
    assert s.users == {"u": {"tenant_id": "t"}}
    out = _j.loads(persist._dump(s))
    assert out["pocs"] == {"p1": {"x": 1}} and "decisions" in out


def test_cloudseals_admins_work_in_the_cloudseals_workspace(env, public_dns):
    c, h = env
    app = c.post("/v1/integrations", headers=h("architect@cloudseals"), json={"name": "LedgerSight"})
    assert app.status_code == 200
    assert STORE.integrations[app.json()["id"]]["tenant"] == "t-cloudseals"
    assert c.get("/v1/integrations", headers=h("admin@t-bank")).json()["items"] == []        # customers do not see it
    assert c.get("/v1/integrations", headers=h("reviewer@cloudseals")).status_code == 403    # not a CloudSeals admin
    assert STORE.tenants["t-cloudseals"]["name"] == "CloudSeals"


def test_application_access_is_managed_in_trustops(env, public_dns):
    c, h = env
    app = register(c, h)
    key = app["trustops_key"]
    base = "/v1/governance/team"
    r = c.post(base + "/invites", headers=h("admin@t-bank"), json={"email": "Prep@Firm.test", "role": "none", "app_access": {app["id"]: "preparer"}})
    assert r.status_code == 201, r.text
    got = c.get("/v1/app-access", params={"email": "prep@firm.test"}, headers={"X-TrustOps-Key": key}).json()
    assert got["role"] == "preparer" and got["application"] == "Recon app"
    assert c.get("/v1/app-access", params={"email": "nobody@firm.test"}, headers={"X-TrustOps-Key": key}).json()["role"] is None
    assert c.get("/v1/app-access", params={"email": "prep@firm.test"}, headers={"X-TrustOps-Key": "tok_bad"}).status_code == 401
    other = register(c, h, "admin@t-health", "Other")["trustops_key"]
    assert c.get("/v1/app-access", params={"email": "prep@firm.test"}, headers={"X-TrustOps-Key": other}).json()["role"] is None
    # change to reviewer, then remove
    assert c.put(base + "/pending/prep@firm.test/access", headers=h("admin@t-bank"), json={"app_access": {app["id"]: "reviewer"}}).status_code == 200
    assert c.get("/v1/app-access", params={"email": "prep@firm.test"}, headers={"X-TrustOps-Key": key}).json()["role"] == "reviewer"
    c.put(base + "/pending/prep@firm.test/access", headers=h("admin@t-bank"), json={"role": "viewer", "app_access": {}})
    assert c.get("/v1/app-access", params={"email": "prep@firm.test"}, headers={"X-TrustOps-Key": key}).json()["role"] is None
    assert c.post(base + "/invites", headers=h("admin@t-bank"), json={"email": "x@firm.test", "app_access": {"int_nope": "preparer"}}).status_code == 422
    listing = c.get(base, headers=h("admin@t-bank")).json()
    assert listing["applications"][0]["name"] == "Recon app" and "none" in [o["id"] for o in listing["role_options"]]



def test_application_access_follows_the_trustops_role(env, public_dns):
    c, h = env
    key = register(c, h)["trustops_key"]
    base = "/v1/governance/team"
    for email, role in (("p@firm.test", "none"), ("a@firm.test", "approver"), ("v@firm.test", "viewer")):
        assert c.post(base + "/invites", headers=h("admin@t-bank"), json={"email": email, "role": role}).status_code == 201
    look = lambda e: c.get("/v1/app-access", params={"email": e}, headers={"X-TrustOps-Key": key}).json()["role"]
    assert look("p@firm.test") == "preparer" and look("a@firm.test") == "reviewer" and look("v@firm.test") is None


def test_assign_review_to_a_named_approver(env, public_dns):
    c, h = env
    key = register(c, h)["trustops_key"]
    revs = c.get("/v1/reviewers", headers={"X-TrustOps-Key": key}).json()["items"]
    emails = {r["email"] for r in revs}
    assert revs and all(r["role"] in ("Admin", "Approver") for r in revs)
    approver = next(r["email"] for r in revs if r["role"] == "Approver")
    assert c.get("/v1/reviewers", headers={"X-TrustOps-Key": "tok_wrong"}).status_code == 401
    # Assigned when submitted; a person who is not an approver is refused
    bad = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "human", "id": "prep@x"}, "action": "submit_for_review", "assign_to": "nobody@x.com"})
    assert bad.status_code == 422
    did = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={"actor": {"type": "human", "id": "prep@x"}, "action": "submit_for_review", "assign_to": approver}).json()["decision_id"]
    assert c.get(f"/v1/decisions/{did}/status", headers={"X-TrustOps-Key": key}).json()["assigned_to"] == approver
    # Reassign from the application and from the console; the evidence chain stays intact
    other = next(e for e in emails if e != approver)
    assert c.post(f"/v1/decisions/{did}/app-assign", headers={"X-TrustOps-Key": key}, json={"to": other, "by": "prep@x"}).json()["assigned_to"] == other
    assert c.post(f"/v1/decisions/{did}/assign", headers=h("risk@t-bank"), json={"to": approver}).status_code == 403
    assert c.post(f"/v1/decisions/{did}/assign", headers=h("admin@t-bank"), json={"to": None}).json()["assigned_to"] is None
    rec = c.get(f"/v1/decisions/{did}", headers=h("admin@t-bank")).json()
    assert len(rec["assignment"]["history"]) == 2
    assert c.get("/v1/decisions-verify", headers=h("admin@t-bank")).json()["valid"]
    assert {r["email"] for r in c.get("/v1/decisions-reviewers", headers=h("risk@t-bank")).json()["items"]} == emails


def test_rename_application_keeps_its_key(env, public_dns):
    c, h = env
    app = c.post("/v1/integrations", headers=h("admin@t-bank"), json={"name": "Ledgerisight"}).json()
    assert c.patch(f"/v1/integrations/{app['id']}", headers=h("controller@t-bank"), json={"name": "LedgerSight"}).status_code == 403
    assert c.patch(f"/v1/integrations/{app['id']}", headers=h("admin@t-bank"), json={"name": ""}).status_code == 422
    assert c.patch(f"/v1/integrations/{app['id']}", headers=h("admin@t-bank"), json={"name": "LedgerSight"}).json()["name"] == "LedgerSight"
    r = ask(c, app["trustops_key"], action="submit_for_review", actor_type="human", actor_id="p@x").json()
    assert c.get(f"/v1/decisions/{r['decision_id']}", headers=h("admin@t-bank")).json()["application"]["name"] == "LedgerSight"


def test_notifications_bell_follows_the_decision_log(env, public_dns):
    """The TrustOps bell: approvers hear about items sent for approval; others hear about approvals and blocks; your own
    actions never notify you; "seen" is per person; other workspaces see nothing."""
    c, h = env
    key = register(c, h)["trustops_key"]
    sent = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={
        "actor": {"type": "human", "id": "staff@firm.example"}, "action": "submit_for_review", "client": "client-a",
        "amount_minor": 50_000, "currency": "USD", "title": "Missing receipt EX-005", "facts": [{"label": "Bank line", "value": "500.00"}]}).json()
    ask(c, key, actor_id="chat-agent", action="email_client")                       # blocked by FIN-02
    bell = c.get("/v1/notifications", headers=h("controller@t-bank")).json()
    kinds = {i["kind"]: i for i in bell["items"]}
    assert bell["for"] == "approver" and bell["unread"] == 2
    assert kinds["SUBMITTED"]["title"] == "Missing receipt EX-005" and kinds["SUBMITTED"]["pending"] and kinds["SUBMITTED"]["decision_id"] == sent["decision_id"]
    assert kinds["DENIED"]["policy_id"] == "FIN-02" and kinds["DENIED"]["by"] == "chat-agent"
    viewer = c.get("/v1/notifications", headers=h("risk@t-bank")).json()
    assert viewer["for"] == "viewer" and [i["kind"] for i in viewer["items"]] == ["DENIED"]   # nothing to approve for a viewer
    assert c.post(f"/v1/decisions/{sent['decision_id']}/resolve", headers=h("controller@t-bank"),
                  json={"outcome": "approve", "reason": "Receipt checked"}).status_code == 200
    mine = c.get("/v1/notifications", headers=h("controller@t-bank")).json()
    assert "APPROVED" not in {i["kind"] for i in mine["items"]}                     # your own decision does not notify you
    other = c.get("/v1/notifications", headers=h("controller2@t-bank")).json()
    approved = next(i for i in other["items"] if i["kind"] == "APPROVED")
    assert approved["by"] == "controller@t-bank" and approved["note"] == "Receipt checked" and not approved["pending"]
    top = mine["items"][0]["seq"]
    assert c.post("/v1/notifications/seen", headers=h("controller@t-bank"), json={"upto": top}).json()["seen"] == top
    assert c.get("/v1/notifications", headers=h("controller@t-bank")).json()["unread"] == 0
    assert c.get("/v1/notifications", headers=h("controller2@t-bank")).json()["unread"] > 0   # seen is per person
    assert c.post("/v1/notifications/seen", headers=h("controller@t-bank"), json={"upto": "x"}).status_code == 422
    assert c.get("/v1/notifications", headers=h("admin@t-health")).json()["items"] == []     # tenant isolation
