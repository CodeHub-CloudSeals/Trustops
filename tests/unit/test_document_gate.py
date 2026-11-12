import json
from pathlib import Path
import sys
import time
import unittest

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"integrations/ledgersight"))
from document_gate import DocumentGateClient, GateDenied, canonical


class GateTests(unittest.TestCase):
    def client(self,status="APPROVED",tamper=False,stale=False,offline=False):
        key=Ed25519PrivateKey.generate()
        pem=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        def respond(request):
            if offline: raise httpx.ConnectError("offline")
            body=json.loads(request.content)
            payload={"schema":"trustops.document-gate.v1","workspace_id":body["workspace_id"],"action":body["action"],
                     "nonce":body["nonce"],"files":[{**f,"status":status,"reason":"Wrong reporting period"} for f in body["files"]],
                     "allowed":status=="APPROVED","expires_at":int(time.time())+(-10 if stale else 30)}
            signature=key.sign(canonical(payload)).hex()
            if tamper:payload["nonce"]="forged"
            return httpx.Response(200,json={"payload":payload,"signature":signature})
        return DocumentGateClient("https://trustops.example/runtime/authorize","test-token",pem,httpx.MockTransport(respond))

    def test_only_approved_fingerprints_pass(self):
        files=[{"upload_id":"UP-1","sha256":"a"*64}]
        self.client().authorize("client-a","run.compute",files)
        for status in ["PENDING","REJECTED"]:
            with self.assertRaises(GateDenied):self.client(status).authorize("client-a","run.compute",files)

    def test_offline_expired_and_forged_responses_fail_closed(self):
        for options in [{"offline":True},{"stale":True},{"tamper":True}]:
            with self.assertRaises(GateDenied):
                self.client(**options).authorize("client-a","run.compute",[{"upload_id":"UP-1","sha256":"a"*64}])

    def test_rejection_reason_is_returned_to_the_source(self):
        with self.assertRaisesRegex(GateDenied,"Wrong reporting period"):
            self.client("REJECTED").authorize("client-a","mapping.commit",[{"upload_id":"UP-1","sha256":"a"*64}])


if __name__=="__main__":unittest.main()
