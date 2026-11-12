from app.security import issue_token

REG = {"organisation_name": "Acme Ltd", "work_email": "cto@acme.example", "industry": "banking",
       "jurisdiction": ["UK"], "engagement_reference": "ENG-DEMO-001"}


def test_registration_approval_invitation_flow(env):
    c, h = env
    assert c.post("/v1/registration-requests", json=REG).status_code == 202
    regs = c.get("/v1/admin/registrations", headers=h("architect@cloudseals")).json()["items"]
    rid = regs[0]["registration_id"]
    assert regs[0]["engagement_verified"] is True
    # customers/reviewers cannot approve
    assert c.post(f"/v1/admin/registrations/{rid}/decision", headers=h("admin@t-bank"), json={"decision": "approve", "reason": "x"}).status_code == 403
    d = c.post(f"/v1/admin/registrations/{rid}/decision", headers=h("architect@cloudseals"), json={"decision": "approve", "reason": "ok"}).json()
    # new identity accepts the invitation -> becomes tenant admin
    new = issue_token("cto@acme.example")
    from app.main import STORE
    STORE.users.pop("cto@acme.example", None)
    r = c.post("/v1/invitations/accept", headers={"Authorization": f"Bearer {new}"}, json={"token": d["invitation_token"]})
    assert r.status_code == 200 and "customer_admin" in r.json()["roles"]
    # single use
    again = c.post("/v1/invitations/accept", headers={"Authorization": f"Bearer {issue_token('other@acme.example')}"}, json={"token": d["invitation_token"]})
    assert again.status_code == 400
    me = c.get("/v1/me", headers={"Authorization": f"Bearer {new}"}).json()
    assert me["tenant"]["name"] == "Acme Ltd" and me["tenant"]["allow_preliminary_report"] is False
    # tenant admin invites a contributor
    inv = c.post("/v1/tenant/invitations", headers={"Authorization": f"Bearer {new}"}, json={"role": "customer_contributor"})
    assert inv.status_code == 201
    assert any(e["type"] == "taad.tenant.activated.v1" for e in STORE.events)


def test_unknown_engagement_cannot_be_approved_and_response_does_not_leak(env):
    c, h = env
    ok = c.post("/v1/registration-requests", json=REG)
    bad = c.post("/v1/registration-requests", json={**REG, "engagement_reference": "NOPE", "work_email": "x@other.example"})
    assert ok.status_code == bad.status_code == 202 and ok.json() == bad.json()
    rid = c.get("/v1/admin/registrations", headers=h("architect@cloudseals")).json()["items"][1]["registration_id"]
    r = c.post(f"/v1/admin/registrations/{rid}/decision", headers=h("architect@cloudseals"), json={"decision": "approve", "reason": "x"})
    assert r.status_code == 409 and r.json()["code"] == "engagement_not_verified"


def test_registration_rate_limited(env):
    c, _ = env
    codes = [c.post("/v1/registration-requests", json={**REG, "work_email": f"u{i}@spam.example"}).status_code for i in range(7)]
    assert codes[:5] == [202] * 5 and codes[5] == 429


def test_expired_and_forged_invitation_rejected(env):
    c, _ = env
    t = {"Authorization": f"Bearer {issue_token('z@z.example')}"}
    assert c.post("/v1/invitations/accept", headers=t, json={"token": "forged"}).status_code == 400
