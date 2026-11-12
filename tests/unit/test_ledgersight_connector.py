"""Read-only connector isolation, authentication and independent evidence checks."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps/assessment-api"))
from app.ledgersight_connector import SIGNED_FIELDS, GovernanceConnector, LedgerSightClient, make_router, verify_chain


class ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pem = self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.event = {k: None for k in SIGNED_FIELDS}
        self.event.update(event_id="ev1", tenant_id="firm-01", workspace_id="client-a", prior_hash="0" * 64,
                          timestamp_utc="2026-11-12T00:00:00Z", action="run.compute", policy_decision="ALLOW:OK")
        body = json.dumps(self.event, sort_keys=True, separators=(",", ":")).encode()
        self.event.update(event_hash=hashlib.sha256(body).hexdigest(), signature=self.key.sign(body).hex())

    def test_independent_signature_verification_rejects_tampering(self):
        self.assertEqual(verify_chain([self.event], self.pem)["state"], "PASS")
        tampered = dict(self.event, policy_decision="ALLOW:TAMPERED")
        self.assertEqual(verify_chain([tampered], self.pem)["state"], "FAIL")
        self.assertEqual(verify_chain([], self.pem)["state"], "UNKNOWN")

    def test_wrong_signer_and_broken_chain_fail(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.assertEqual(verify_chain([self.event], other)["state"], "FAIL")
        self.assertEqual(verify_chain([dict(self.event, prior_hash="bad")], self.pem)["state"], "FAIL")

    def test_upstream_auth_cookie_stays_in_client_and_reads_do_not_mutate(self):
        calls = []
        def remote(request):
            calls.append((request.method, request.url.path))
            if request.url.path == "/v1/login":
                return httpx.Response(200, json={"ok": True}, headers={"set-cookie": "ls_session=private-session; Secure; HttpOnly"})
            self.assertIn("ls_session=private-session", request.headers.get("cookie", ""))
            return httpx.Response(200, json={"tenant": "firm-01"})
        client = LedgerSightClient("https://source.example", credentials=lambda: ("user", "password", "JBSWY3DPEHPK3PXP"), transport=httpx.MockTransport(remote))
        self.assertEqual(client.get("/v1/trust")["tenant"], "firm-01")
        client.get("/v1/rulebooks")
        self.assertEqual(calls, [("POST", "/v1/login"), ("GET", "/v1/trust"), ("GET", "/v1/rulebooks")])
        with self.assertRaises(ValueError):
            client.get("/v1/users")

    def test_scope_enforced_before_any_source_request(self):
        class Fake:
            calls = 0
            def snapshot(self, ids, refresh=False):
                self.calls += 1
                return {"source_tenant": "firm-01", "runs": []}
        fake = Fake()
        person = SimpleNamespace(tenant_id="other", roles=["customer_admin"])
        app = FastAPI(); app.include_router(make_router(lambda: person, connector=fake))
        mapping = {"mapped": {"source_tenant": "firm-01", "workspaces": ["client-a"]}}
        with patch.dict(os.environ, {"TRUSTOPS_LEDGERSIGHT_TENANT_MAP": json.dumps(mapping)}):
            c = TestClient(app)
            self.assertEqual(c.get("/v1/applications/ledgersight/snapshot").status_code, 404)
            self.assertEqual(fake.calls, 0)
            person.tenant_id = "mapped"; person.roles = ["customer_contributor"]
            self.assertEqual(c.get("/v1/applications/ledgersight/snapshot").status_code, 404)
            person.roles = ["customer_admin"]
            self.assertEqual(c.get("/v1/applications/ledgersight/snapshot").status_code, 200)
            self.assertEqual(fake.calls, 1)

    def test_snapshot_uses_actual_reviews_and_refreshes_without_source_rows(self):
        event = self.event
        pem = self.pem
        class Source:
            base_url = "https://source.example"
            status = "OPEN"
            def get(self, path):
                if path == "/v1/trust":
                    return {"tenant":"firm-01", "evidence":{"public_key_pem":pem}}
                if path == "/v1/rulebooks":
                    return {"version":"v1", "policies":[], "agents":[]}
                if path.endswith("/evidence"):
                    return {"events":[event]}
                if path.endswith("/runs/run-1"):
                    return {"id":"run-1", "result":{"workspace_id":"client-a", "bank_net_cents":999999,
                            "exceptions":[{"id":"ex1", "status":self.status}]}, "lines":{"private":"raw data"}}
                return {"id":"client-a", "runs":[{"id":"run-1"}]}
        source = Source(); connector = GovernanceConnector(source)
        first = connector.snapshot(["client-a"])
        self.assertEqual(first["runs"][0]["pending_reviews"], 1)
        self.assertEqual(first["verification"]["state"], "PASS")
        self.assertNotIn("bank_net_cents", json.dumps(first))
        self.assertNotIn("raw data", json.dumps(first))
        source.status = "ACCEPTED"
        second = connector.snapshot(["client-a"], refresh=True)
        self.assertEqual(second["runs"][0]["pending_reviews"], 0)
        self.assertEqual(second["reviews"][0]["status"], "ACCEPTED")
        event["workspace_id"] = "other-client"
        with self.assertRaises(Exception):
            connector.snapshot(["client-a"], refresh=True)

    def test_wrong_source_tenant_and_upstream_exceptions_are_not_exposed(self):
        class Fake:
            def snapshot(self, ids, refresh=False):
                if refresh:
                    raise ValueError("private-password-and-cookie")
                return {"source_tenant": "wrong-tenant"}
        p = SimpleNamespace(tenant_id="mapped", roles=["customer_admin"])
        app = FastAPI(); app.include_router(make_router(lambda: p, connector=Fake()))
        with patch.dict(os.environ, {"TRUSTOPS_LEDGERSIGHT_TENANT_MAP": '{"mapped":{"source_tenant":"firm-01","workspaces":["client-a"]}}'}):
            for path in ("/v1/applications/ledgersight/snapshot", "/v1/applications/ledgersight/snapshot?refresh=true"):
                response = TestClient(app).get(path)
                self.assertEqual(response.status_code, 503)
                self.assertNotIn("private-password", response.text)
                self.assertNotIn("wrong-tenant", response.text)

    def test_run_evidence_survives_more_recent_read_events(self):
        events = []
        prior = "0" * 64
        for i in range(130):
            ev = {k: None for k in SIGNED_FIELDS}
            ev.update(event_id=f"e{i}", tenant_id="firm-01", workspace_id="client-a", prior_hash=prior,
                      timestamp_utc=f"2026-11-12T00:{i//60:02}:{i%60:02}Z",
                      action="run.compute" if i == 0 else "workspace.read", run_id="run-1" if i == 0 else None)
            body = json.dumps(ev, sort_keys=True, separators=(",", ":")).encode()
            prior = hashlib.sha256(body).hexdigest()
            ev.update(event_hash=prior, signature=self.key.sign(body).hex()); events.append(ev)
        pem = self.pem
        class Source:
            base_url = "https://source.example"
            def get(self, path):
                if path == "/v1/trust": return {"tenant":"firm-01", "evidence":{"public_key_pem":pem}}
                if path == "/v1/rulebooks": return {}
                if path.endswith("/evidence"): return {"events":events}
                if path.endswith("/runs/run-1"): return {"id":"run-1", "result":{"workspace_id":"client-a"}}
                return {"id":"client-a", "runs":[{"id":"run-1"}]}
        result = GovernanceConnector(Source()).snapshot(["client-a"])
        self.assertEqual(result["verification"]["checked"], 130)
        self.assertEqual(result["verification"]["state"], "PASS")
        self.assertIn("e0", [e["event_id"] for e in result["events"]])
        self.assertEqual(len(result["events"]), 101)


if __name__ == "__main__":
    unittest.main()
