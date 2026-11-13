import os
from pathlib import Path
import sys
import threading
import tempfile
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"apps/assessment-api/app"))
from governance_team import make_team_router


class TeamTests(unittest.TestCase):
    def setUp(self):
        self.store=SimpleNamespace(lock=threading.RLock(),users={
            "admin@example.test":{"tenant_id":"ours","roles":["customer_admin"]},
            "reviewer@example.test":{"tenant_id":"ours","roles":["customer_risk"]},
            "other@example.test":{"tenant_id":"other","roles":["customer_admin"]}},pending_users={},audit=[])
        self.p=SimpleNamespace(sub="admin@example.test",tenant_id="ours",roles=["customer_admin"])
        app=FastAPI();app.include_router(make_team_router(lambda:self.p,self.store))
        self.c=TestClient(app);self.base="/v1/governance/team"
        self.env=patch.dict(os.environ,{"TAAD_ENV":"local","TAAD_AUTH_MODE":"dev"});self.env.start()

    def tearDown(self):
        self.c.close();self.env.stop()

    def test_only_admin_can_manage_users_and_cross_tenant_members_are_hidden(self):
        listing=self.c.get(self.base).json()
        self.assertEqual(len(listing["members"]),2)
        self.assertNotIn("other@example.test",str(listing))
        r=self.c.put(self.base+"/members/other@example.test/role",json={"role":"viewer","revision":0})
        self.assertEqual(r.status_code,404)
        self.p.roles=["customer_risk"]
        self.assertEqual(self.c.get(self.base).status_code,403)
        self.assertEqual(self.c.post(self.base+"/invites",json={"email":"new@example.test","role":"admin"}).status_code,403)

    def test_offered_roles_are_admin_approver_viewer(self):
        opts=[o["id"] for o in self.c.get(self.base).json()["role_options"]]
        self.assertEqual(opts,["admin","approver","viewer","none"])
        r=self.c.post(self.base+"/invites",json={"email":"approver@example.test","role":"approver"})
        self.assertEqual(r.status_code,201)
        self.assertEqual(self.store.pending_users["approver@example.test"]["roles"],["customer_controller"])

    def test_registration_and_preview_activation_preserve_registered_role(self):
        r=self.c.post(self.base+"/invites",json={"email":"new@example.test","role":"reviewer"})
        self.assertEqual(r.status_code,201)
        self.assertFalse(r.json()["email_sent"])
        r=self.c.post(self.base+"/preview-activate",json={"email":"new@example.test","role":"admin"})
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()["member"]["roles"],["customer_risk"])
        self.assertEqual(self.store.pending_users,{})

    def test_last_admin_and_self_revocation_are_blocked(self):
        r=self.c.put(self.base+"/members/admin@example.test/role",json={"role":"viewer","revision":0})
        self.assertEqual(r.status_code,409)
        self.assertEqual(self.c.post(self.base+"/members/admin@example.test/revoke",json={"revision":0}).status_code,409)

    def test_role_change_is_scoped_and_stale_edits_are_rejected(self):
        url=self.base+"/members/reviewer@example.test/role"
        r=self.c.put(url,json={"role":"viewer","revision":0})
        self.assertEqual(r.status_code,200)
        self.assertEqual(self.store.users["reviewer@example.test"]["roles"],["customer_viewer"])
        self.assertEqual(self.c.put(url,json={"role":"admin","revision":0}).status_code,409)

    def test_pending_registration_can_be_cancelled_without_affecting_members(self):
        self.c.post(self.base+"/invites",json={"email":"new@example.test","role":"submitter"})
        r=self.c.post(self.base+"/pending/cancel",json={"email":"new@example.test"})
        self.assertEqual(r.status_code,200)
        self.assertEqual(self.store.pending_users,{})
        self.assertEqual(len(self.store.users),3)

    def test_preview_activation_is_disabled_on_hosted_environments(self):
        self.c.post(self.base+"/invites",json={"email":"new@example.test","role":"viewer"})
        with patch.dict(os.environ,{"TAAD_ENV":"dev","TAAD_AUTH_MODE":"oidc"}):
            self.assertEqual(self.c.post(self.base+"/preview-activate",json={"email":"new@example.test"}).status_code,404)

    def test_duplicate_email_cannot_be_assigned_into_another_tenant(self):
        self.assertEqual(self.c.post(self.base+"/invites",json={"email":"other@example.test","role":"admin"}).status_code,409)
        self.assertEqual(self.store.users["other@example.test"]["tenant_id"],"other")

    def test_memberships_survive_reload_with_existing_state_persistence(self):
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"apps/assessment-api"))
        from app.store import Store
        from app import persist
        with tempfile.TemporaryDirectory() as directory:
            real=Store();real.users=copy.deepcopy(self.store.users)
            target=f"sqlite:///{directory}/members.sqlite3"
            app=FastAPI();app.include_router(make_team_router(lambda:self.p,real,lambda:persist.save(real,target)))
            client=TestClient(app)
            r=client.post(self.base+"/invites",json={"email":"new@example.test","role":"submitter"})
            self.assertEqual(r.status_code,201,r.text)
            restored=Store();self.assertTrue(persist.load(restored,target))
            self.assertEqual(restored.pending_users["new@example.test"]["roles"],["customer_operator"])
            r=client.post(self.base+"/preview-activate",json={"email":"new@example.test","role":"admin"})
            self.assertEqual(r.status_code,200,r.text)
            restored=Store();persist.load(restored,target)
            self.assertEqual(restored.users["new@example.test"]["roles"],["customer_operator"])
            self.assertNotIn("new@example.test",restored.pending_users)
            client.close()
            persist._engines.pop(target).dispose()
            persist._versions.pop(target,None)


if __name__=="__main__":unittest.main()


def test_cloudseals_admins_can_be_changed_and_removed_in_cloudseals_workspace(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.governance_team import make_team_router
    from app.main import STORE, Principal
    STORE.users.clear()
    STORE.users.update({"a": {"tenant_id": None, "roles": ["cloudseals_admin"], "email": "a@cs.com"},
                        "b": {"tenant_id": None, "roles": ["cloudseals_admin"], "email": "b@cs.com"}})
    me = Principal(sub="a", tenant_id="t-cloudseals", roles=["cloudseals_admin", "customer_admin"])
    app = FastAPI(); app.include_router(make_team_router(lambda: me, STORE))
    c = TestClient(app)
    listed = {m["sub"]: m for m in c.get("/v1/governance/team").json()["members"]}
    assert listed["b"]["role_labels"] == ["Admin"]
    assert c.put("/v1/governance/team/members/b/role", json={"revision": 0, "role": "approver"}).status_code == 200
    assert STORE.users["b"]["tenant_id"] == "t-cloudseals" and STORE.users["b"]["roles"] == ["customer_controller"]
    assert c.post("/v1/governance/team/members/a/revoke", json={"revision": 0}).status_code == 409   # not yourself
    assert c.post("/v1/governance/team/members/b/revoke", json={"revision": 1}).status_code == 200
    assert "b" not in STORE.users
    # the last administrator cannot be demoted
    assert c.put("/v1/governance/team/members/a/role", json={"revision": 0, "role": "viewer"}).status_code == 409


def test_application_access_is_chosen_per_person(env):
    import socket
    from app import app_integrations
    c, h = env
    app = c.post("/v1/integrations", headers=h("admin@t-bank"), json={"name": "LedgerSight"}).json()
    other = c.post("/v1/integrations", headers=h("admin@t-bank"), json={"name": "Other app"}).json()
    key, key2 = app["trustops_key"], other["trustops_key"]
    access = lambda k, e: c.get(f"/v1/app-access?email={e}", headers={"X-TrustOps-Key": k}).json()["role"]
    assert c.post("/v1/governance/team/invites", headers=h("admin@t-bank"), json={"email": "p@bank.com", "role": "none", "apps": [app["id"]]}).status_code == 201
    assert access(key, "p@bank.com") == "preparer" and access(key2, "p@bank.com") is None
    assert c.post("/v1/governance/team/invites", headers=h("admin@t-bank"), json={"email": "x@bank.com", "role": "approver", "apps": ["nope"]}).status_code == 422
    assert c.put("/v1/governance/team/pending/p@bank.com/access", headers=h("admin@t-bank"), json={"role": "approver", "apps": [other["id"]]}).status_code == 200
    assert access(key, "p@bank.com") is None and access(key2, "p@bank.com") == "reviewer"
    # existing members without a choice keep access to every application
    assert access(key, "controller@t-bank") == "reviewer"
    m = next(x for x in c.get("/v1/governance/team", headers=h("admin@t-bank")).json()["members"] if x["sub"] == "controller@t-bank")
    assert c.put("/v1/governance/team/members/controller@t-bank/role", headers=h("admin@t-bank"), json={"revision": m["revision"], "role": "approver", "apps": []}).status_code == 200
    assert access(key, "controller@t-bank") is None
