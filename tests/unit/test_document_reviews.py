import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"apps/assessment-api"))
from app.document_reviews import DocumentReviewStore, make_document_router


class DocumentReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=DocumentReviewStore(self.tmp.name)
        self.p=SimpleNamespace(sub="reviewer@example.test",tenant_id="ours",roles=["customer_risk"])
        self.doc={"upload_id":"UP-1","sha256":"a"*64,"workspace_id":"client-a","workspace_name":"Client A",
                  "filename":"bank.csv","uploaded_by":"uploader@example.test","uploaded_at":"2026-11-12T00:00:00Z",
                  "kind":"bank","header":["amount"],"preview":[["100.00"]]}
        self.source={"source_tenant":"firm-01","synced_at":"2026-11-12T00:00:00Z","documents":[self.doc],"document_gate_enforced":False}
        self.calls=[]
        def snapshot(p,fresh):self.calls.append(fresh);return copy.deepcopy(self.source)
        app=FastAPI();app.include_router(make_document_router(lambda:self.p,snapshot,store=self.store))
        self.c=TestClient(app)
        self.env=patch.dict(os.environ,{"TRUSTOPS_LEDGERSIGHT_TENANT_MAP":'{"ours":{"source_tenant":"firm-01","workspaces":["client-a"]}}',
                                      "TRUSTOPS_DOCUMENT_GATE_TOKEN":"test-only-token","TRUSTOPS_DOCUMENT_GATE_TENANT":"ours"})
        self.env.start()

    def tearDown(self):self.c.close();self.env.stop();self.tmp.cleanup()

    def decision(self,decision="APPROVED",reason="Checked the source document"):
        doc=self.c.get('/documents').json()["items"][0]
        return self.c.post(f'/documents/{doc["document_key"]}/decision',json={"decision":decision,"reason":reason,"sha256":doc["sha256"],"revision":0})

    def gate(self,sha=None,token="test-only-token"):
        return self.c.post('/documents/runtime/authorize',headers={"Authorization":"Bearer "+token},json={"workspace_id":"client-a","action":"run.compute","nonce":"unique-nonce-for-test","files":[{"upload_id":"UP-1","sha256":sha or self.doc["sha256"]}]})

    def test_source_uploads_appear_pending_without_reupload(self):
        r=self.c.get('/documents').json()
        self.assertEqual(r["items"][0]["filename"],"bank.csv")
        self.assertEqual(r["items"][0]["review_status"],"PENDING")
        self.assertTrue(r["items"][0]["can_review"])
        self.assertFalse(r["runtime_gate_enforced"])

    def test_rejection_reason_reviewer_and_signed_history_survive_restart(self):
        r=self.decision("REJECTED","Amounts do not match the source statement")
        self.assertEqual(r.status_code,200,r.text)
        item=self.c.get('/documents').json()["items"][0]
        self.assertEqual(item["review_status"],"REJECTED")
        self.assertEqual(item["review"]["reason"],"Amounts do not match the source statement")
        self.assertEqual(item["review"]["reviewer"],self.p.sub)
        restored=DocumentReviewStore(self.tmp.name).listing('ours')
        self.assertEqual(restored[0],item["decision_evidence"])
        self.assertTrue(self.calls[-2])

    def test_blank_reason_self_review_and_wrong_roles_are_blocked(self):
        self.assertEqual(self.decision(reason="   ").status_code,422)
        self.p.sub=self.doc["uploaded_by"]
        self.assertEqual(self.decision().status_code,403)
        self.p.sub="viewer@example.test";self.p.roles=["customer_viewer"]
        self.assertEqual(self.decision().status_code,403)
        self.p.roles=["customer_admin"]
        self.assertEqual(self.decision().status_code,403)

    def test_stale_fingerprint_is_not_approved_and_decisions_cannot_be_overwritten(self):
        row=self.c.get('/documents').json()["items"][0]
        self.doc["sha256"]="b"*64
        r=self.c.post(f'/documents/{row["document_key"]}/decision',json={"decision":"APPROVED","reason":"Reviewed","sha256":"a"*64})
        self.assertEqual(r.status_code,404)
        self.assertEqual(self.decision().status_code,200)
        self.assertEqual(self.decision("REJECTED").status_code,409)

    def test_gate_denies_pending_rejected_changed_and_unauthenticated_inputs(self):
        self.assertFalse(self.gate().json()["payload"]["allowed"])
        self.assertEqual(self.gate(token="wrong").status_code,401)
        self.assertEqual(self.decision("REJECTED","Wrong reporting period").status_code,200)
        payload=self.gate().json()["payload"]
        self.assertFalse(payload["allowed"])
        self.assertEqual(payload["files"][0]["reason"],"Wrong reporting period")

    def test_only_exact_approved_fingerprints_are_authorized(self):
        self.assertEqual(self.decision().status_code,200)
        self.assertTrue(self.gate().json()["payload"]["allowed"])
        self.assertFalse(self.gate(sha="b"*64).json()["payload"]["allowed"])

    def test_tampered_decision_fails_closed(self):
        self.decision()
        with self.store.connect() as db:
            key,body=db.execute('SELECT key,body FROM decisions').fetchone();row=json.loads(body)
            row["payload"]["reason"]="tampered"
            db.execute('UPDATE decisions SET body=? WHERE key=?',(json.dumps(row),key))
        self.assertEqual(self.gate().status_code,503)

    def test_cross_tenant_and_out_of_scope_source_are_hidden(self):
        self.p.tenant_id="other"
        self.assertEqual(self.c.get('/documents').status_code,404)
        self.assertEqual(self.calls,[])
        self.p.tenant_id="ours";self.doc["workspace_id"]="other-client"
        self.assertEqual(self.c.get('/documents').status_code,503)


if __name__=="__main__":unittest.main()
