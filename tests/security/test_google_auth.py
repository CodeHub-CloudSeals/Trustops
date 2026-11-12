import io
import json

import pytest
from app import main, security


@pytest.fixture
def google(monkeypatch, env):
    claims = {"sub": "123", "email": "naveen.m@cloudseals.co.uk", "email_verified": True}
    import google.oauth2.id_token as idt
    monkeypatch.setattr(idt, "verify_oauth2_token", lambda token, req, audience=None: (
        claims if token == "good" and audience == "client-1" else (_ for _ in ()).throw(ValueError("bad token"))))
    monkeypatch.setattr(security, "AUTH_MODE", "oidc")
    monkeypatch.setattr(security, "AUTH_PROVIDER", "google")
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")
    monkeypatch.setattr(main, "AUTH_PROVIDER", "google")
    monkeypatch.setattr(main, "ENV", "dev")
    monkeypatch.setenv("TAAD_GOOGLE_CLIENT_ID", "client-1")
    monkeypatch.setenv("TAAD_FIRST_ADMIN_EMAIL", "naveen.m@cloudseals.co.uk")
    main.STORE.users.clear()   # the seeded dev users include admins; start from an empty directory
    return env[0], claims


def me(c, token="good"):
    return c.get("/v1/me", headers={"Authorization": f"Bearer {token}"})


def test_invalid_google_token_is_rejected(google):
    c, _ = google
    assert me(c, "forged").status_code == 401


def test_first_admin_bootstrap_by_verified_email_is_one_time(google):
    c, claims = google
    r = me(c)
    assert r.status_code == 200 and "cloudseals_admin" in r.json()["roles"]
    assert main.STORE.admin_bootstrap["email"] == "naveen.m@cloudseals.co.uk"
    assert any(a["action"] == "admin.bootstrap" for a in main.STORE.audit)
    # a different verified Google user does not become admin, even with the right token shape
    claims.update(sub="999", email="someone@else.com")
    assert me(c).status_code == 401


def test_unverified_email_or_wrong_env_never_bootstraps(google, monkeypatch):
    c, claims = google
    claims["email_verified"] = False
    assert me(c).status_code == 401
    claims["email_verified"] = True
    monkeypatch.setattr(main, "ENV", "prod")
    assert me(c).status_code == 401
    assert not main.STORE.users


def test_portal_config_uses_google_and_same_origin_token_exchange(google, monkeypatch):
    c, _ = google
    monkeypatch.setenv("TAAD_PORTAL_REDIRECT_URI", "https://app.example.com/portal/")
    cfg = c.get("/portal/config.json").json()["oidc"]
    assert cfg["provider"] == "google" and cfg["token_url"] == "/v1/auth/token" and cfg["client_id"] == "client-1"
    assert cfg["authorize_url"].startswith("https://accounts.google.com/")


def test_token_exchange_only_serves_our_client_and_returns_id_token(google, monkeypatch):
    c, _ = google
    monkeypatch.setenv("TAAD_PORTAL_REDIRECT_URI", "https://app.example.com/portal/")
    monkeypatch.setenv("TAAD_GOOGLE_CLIENT_SECRET", "s3cret")
    base = {"grant_type": "authorization_code", "code": "c", "code_verifier": "v", "client_id": "client-1",
            "redirect_uri": "https://app.example.com/portal/"}
    assert c.post("/v1/auth/token", data={**base, "client_id": "attacker"}).status_code == 400
    assert c.post("/v1/auth/token", data={**base, "redirect_uri": "https://evil.example/"}).status_code == 400
    sent = {}

    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=0):
        sent["body"] = req.data.decode()
        return Resp(json.dumps({"id_token": "good", "access_token": "opaque", "expires_in": 3599}).encode())
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    r = c.post("/v1/auth/token", data=base)
    assert r.status_code == 200 and r.json()["access_token"] == "good"      # the ID token, never Google's opaque access token
    assert "client_secret=s3cret" in sent["body"]


def test_token_exchange_is_off_without_google_provider(env):
    assert env[0].post("/v1/auth/token", data={}).status_code == 404


def test_google_callback_path_forwards_only_oauth_params_to_the_portal(google):
    c, _ = google
    r = c.get("/api/auth/callback/google?code=abc&state=xyz&evil=1&scope=openid", follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith("/portal/?") and "code=abc" in loc and "state=xyz" in loc and "evil" not in loc
    assert not loc.startswith("//") and "://" not in loc                         # never an open redirect
    from app import main
    main.AUTH_PROVIDER = ""
    try:
        assert c.get("/api/auth/callback/google?code=a", follow_redirects=False).status_code == 404
    finally:
        main.AUTH_PROVIDER = "google"


def test_root_redirects_to_the_portal(env):
    r = env[0].get("/", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/portal/"


def _as(claims, **kw):
    claims.update(kw)


def admin_headers():
    return {"Authorization": "Bearer good"}


def test_admin_user_management_lifecycle(google, monkeypatch):
    c, claims = google
    h = admin_headers()
    assert c.get("/v1/me", headers=h).status_code == 200                 # first admin bootstraps
    monkeypatch.setattr(main, "STAFF_EMAIL_DOMAINS", ["cloudseals.co.uk"])
    main.STORE.tenants["t-bank"] = {"tenant_id": "t-bank", "name": "T-Bank"}

    # guard rails on who can be invited with what
    bad = [{"email": "x@evil.com", "roles": ["cloudseals_reviewer"]},                      # staff role outside the allowed domains
           {"email": "a@cloudseals.co.uk", "roles": ["cloudseals_reviewer", "customer_admin"]},   # mixed staff/customer
           {"email": "a@cloudseals.co.uk", "roles": ["customer_admin"]},                  # customer role without a workspace
           {"email": "a@cloudseals.co.uk", "roles": ["customer_admin"], "tenant_id": "nope"},
           {"email": "a@cloudseals.co.uk", "roles": ["superuser"]},
           {"email": "not-an-email", "roles": ["cloudseals_reviewer"]}]
    for body in bad:
        assert c.post("/v1/admin/users", headers=h, json=body).status_code == 422, body

    ok = c.post("/v1/admin/users", headers=h, json={"email": "Reviewer@CloudSeals.co.uk", "roles": ["cloudseals_reviewer"]})
    assert ok.status_code == 201 and ok.json()["email"] == "reviewer@cloudseals.co.uk"
    assert c.post("/v1/admin/users", headers=h, json={"email": "cust@t-bank.com", "roles": ["customer_admin"], "tenant_id": "t-bank"}).status_code == 201
    listing = c.get("/v1/admin/users", headers=h).json()
    assert {p["email"] for p in listing["pending"]} == {"reviewer@cloudseals.co.uk", "cust@t-bank.com"} and listing["items"][0]["is_self"]

    # the invited person signs in once: membership appears, the invitation is consumed, unverified email never activates
    _as(claims, sub="g2", email="reviewer@cloudseals.co.uk", email_verified=False)
    assert c.get("/v1/me", headers=h).status_code == 401
    _as(claims, email_verified=True)
    me = c.get("/v1/me", headers=h).json()
    assert me["roles"] == ["cloudseals_reviewer"] and "reviewer@cloudseals.co.uk" not in main.STORE.pending_users
    assert c.get("/v1/admin/users", headers=h).status_code == 403          # not an admin
    assert main.STORE.users["google:g2"]["email"] == "reviewer@cloudseals.co.uk"

    # admin edits and removes
    _as(claims, sub="123", email="naveen.m@cloudseals.co.uk")
    assert c.patch("/v1/admin/users/google:g2", headers=h, json={"roles": ["cloudseals_assessor"]}).json()["roles"] == ["cloudseals_assessor"]
    assert c.patch("/v1/admin/users/google:g2", headers=h, json={"roles": ["customer_admin"]}).status_code == 422
    assert c.patch("/v1/admin/users/google:123", headers=h, json={"roles": ["cloudseals_reviewer"]}).status_code in (404, 409)
    assert c.delete("/v1/admin/users/pending/cust@t-bank.com", headers=h).status_code == 200
    assert c.delete("/v1/admin/users/pending/cust@t-bank.com", headers=h).status_code == 404
    assert c.delete("/v1/admin/users/google:g2", headers=h).status_code == 200 and "google:g2" not in main.STORE.users
    actions = {a["action"] for a in main.STORE.audit}
    assert {"user.invited", "user.activated", "user.roles_changed", "user.removed", "user.invite_cancelled"} <= actions


def test_last_admin_and_self_cannot_be_removed(google):
    c, claims = google
    h = admin_headers()
    assert c.get("/v1/me", headers=h).status_code == 200
    me = next(s for s, u in main.STORE.users.items() if "cloudseals_admin" in u["roles"])
    assert c.delete(f"/v1/admin/users/{me}", headers=h).status_code == 409
    assert c.patch(f"/v1/admin/users/{me}", headers=h, json={"roles": ["cloudseals_reviewer"]}).status_code == 409


def test_invites_need_google_sign_in(env):
    c, h = env
    assert c.post("/v1/admin/users", headers=h("architect@cloudseals"), json={"email": "a@b.com", "roles": ["cloudseals_reviewer"]}).status_code == 409


def test_audit_log_filters_pagination_export_and_health(env):
    c, h = env
    arch, rev = "architect@cloudseals", "reviewer@cloudseals"
    for i in range(7):
        main.audit(main.Principal(sub=arch, tenant_id=None, roles=["cloudseals_admin"]), "case.created" if i % 2 else "user.invited", f"=cmd|calc {i}")
    main.audit(main.Principal(sub=rev, tenant_id=None, roles=["cloudseals_reviewer"]), "agent.inventory", "assess-1")
    page = c.get("/v1/admin/activity?limit=3&offset=0", headers=h(arch)).json()
    assert len(page["items"]) == 3 and page["total"] == 8 and page["categories"]["case"] == 3
    assert page["items"][0]["action"] == "agent.inventory"                       # newest first
    assert c.get("/v1/admin/activity?limit=3&offset=6", headers=h(arch)).json()["items"][0]["at"] <= page["items"][0]["at"]
    assert c.get("/v1/admin/activity?action=agent.", headers=h(arch)).json()["total"] == 1
    assert c.get(f"/v1/admin/activity?actor={rev}", headers=h(arch)).json()["total"] == 1
    assert c.get("/v1/admin/activity?q=CMD", headers=h(arch)).json()["total"] == 7
    assert c.get("/v1/admin/activity?until=1", headers=h(arch)).json()["total"] == 0
    assert c.get("/v1/admin/activity", headers=h(rev)).status_code == 403
    csv = c.get("/v1/admin/activity/export?q=cmd", headers=h(arch))
    assert csv.headers["content-type"].startswith("text/csv") and "attachment" in csv.headers["content-disposition"]
    assert "'=cmd|calc" in csv.text and '"=cmd' not in csv.text                   # spreadsheet formula injection is neutralised
    assert any(a["action"] == "audit.exported" for a in main.STORE.audit)

    hl = c.get("/v1/admin/health", headers=h(arch)).json()
    assert hl["state"]["backend"] in ("memory", "sql", "gcs") and hl["model"]["configured"] is False and hl["evidence_signing"]["configured"] is False
    assert hl["agents"]["calls_last_24h"].get("agent.inventory") == 1 and hl["counts"]["audit_events"] >= 9
    assert c.get("/v1/admin/health", headers=h(rev)).status_code == 403


def test_health_probe_measures_model_and_signer(env, monkeypatch):
    c, h = env

    class Model:
        def complete(self, system, user, max_tokens=20):
            return '{"ok": true}'
    monkeypatch.setattr(main, "SWASKA_CLIENT", Model())
    monkeypatch.setenv("TAAD_LLM_PROVIDER", "vertex")
    got = c.get("/v1/admin/health?probe=true", headers=h("architect@cloudseals")).json()
    assert got["model"]["probe"]["ok"] is True and "ms" in got["model"]["probe"]


def test_first_admin_becomes_owner_with_every_cloudseals_role(google):
    c, _ = google
    roles = c.get("/v1/me", headers=admin_headers()).json()["roles"]
    assert set(roles) == {"cloudseals_admin", "cloudseals_assessor", "cloudseals_reviewer", "cloudseals_platform_ops"}


def test_workspace_views_are_read_only_staff_material(env):
    c, h = env
    from tests.e2e.test_trustops_runtime import request_body
    run = c.post("/v1/workflows/ledgersight.ar_cash/runs", headers=h("admin@t-bank", **{"Idempotency-Key": "w1"}), json=request_body(amount=999999999)).json()
    new_assessment_id = c.post("/v1/assessments", headers=h("admin@t-bank", **{"Idempotency-Key": "w2"}),
                               json={"ai_system_name": "X", "industry": "banking", "questionnaire_version": "1.0.0"}).json()["assessment_id"]
    ws = c.get("/v1/admin/workspaces", headers=h("reviewer@cloudseals")).json()["items"]
    bank = next(w for w in ws if w["tenant_id"] == "t-bank")
    assert bank["pending_approvals"] == 1 and bank["runs"] == 1 and bank["assessments"] == 1 and bank["users"] >= 3
    detail = c.get("/v1/admin/workspaces/t-bank", headers=h("reviewer@cloudseals")).json()
    assert detail["runs"][0]["run_id"] == run["run_id"] and detail["assessments"][0]["assessment_id"] == new_assessment_id
    assert {m["sub"] for m in detail["members"]} >= {"admin@t-bank"}
    assert c.get("/v1/admin/workspaces", headers=h("admin@t-bank")).status_code == 403          # customers never see other workspaces
    assert c.get("/v1/admin/workspaces/nope", headers=h("reviewer@cloudseals")).status_code == 404
    # staff can look but not act as the customer: the maker-checker approval stays a customer controller's job
    deny = c.post(f"/v1/approvals/{run['run_id']}/decision", headers=h("architect@cloudseals", **{"Idempotency-Key": "a1"}), json={"decision": "approve", "reason": "owner"})
    assert deny.status_code == 403
