import json

import boto3
import pytest
from app.evidence import S3ObjectStore
from moto import mock_aws


@pytest.fixture()
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x", "AWS_DEFAULT_REGION": "eu-west-2"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        yield


def test_s3_store_quarantine_then_promote(aws):
    s3 = boto3.client("s3")
    for b in ("quar-bkt", "evid-bkt"):
        s3.create_bucket(Bucket=b, CreateBucketConfiguration={"LocationConstraint": "eu-west-2"})
    key = boto3.client("kms").create_key()["KeyMetadata"]["Arn"]
    st = S3ObjectStore("quar-bkt", "evid-bkt", key)
    st.put("t1", "quarantine", "obj", b"data")
    assert s3.get_object(Bucket="quar-bkt", Key="t1/obj")["Body"].read() == b"data"
    st.promote("t1", "obj")
    assert s3.get_object(Bucket="evid-bkt", Key="t1/obj")["Body"].read() == b"data"
    assert "Contents" not in s3.list_objects_v2(Bucket="quar-bkt")


def test_s3_store_reads_guardduty_scan_tag(aws):
    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="quar-bkt", CreateBucketConfiguration={"LocationConstraint": "eu-west-2"})
    key = boto3.client("kms").create_key()["KeyMetadata"]["Arn"]
    st = S3ObjectStore("quar-bkt", "evid-bkt", key)
    st.put("t1", "quarantine", "obj", b"data")
    assert st.scan_status("t1", "obj") is None
    s3.put_object_tagging(Bucket="quar-bkt", Key="t1/obj", Tagging={"TagSet": [
        {"Key": "GuardDutyMalwareScanStatus", "Value": "NO_THREATS_FOUND"}
    ]})
    assert st.scan_status("t1", "obj") == "NO_THREATS_FOUND"


def test_evidence_is_promoted_only_for_clean_guardduty_result(monkeypatch):
    from app import main

    class FakeStore:
        def __init__(self, status):
            self.status = status
            self.promoted = []

        def scan_status(self, _tenant, _key):
            return self.status

        def promote(self, tenant, key):
            self.promoted.append((tenant, key))

    clean = FakeStore("NO_THREATS_FOUND")
    monkeypatch.setattr(main, "OBJECTS", clean)
    ev = {"state": "scanning", "tenant_id": "t1", "evidence_id": "e1"}
    main.refresh_guardduty_scan(ev)
    assert ev["state"] == "clean" and ev["scanned_by"] == "guardduty"
    assert clean.promoted == [("t1", "e1")]

    for status, state in ((None, "scanning"), ("THREATS_FOUND", "infected"),
                          ("UNSUPPORTED", "rejected"), ("ACCESS_DENIED", "rejected"),
                          ("FAILED", "rejected")):
        store = FakeStore(status)
        monkeypatch.setattr(main, "OBJECTS", store)
        item = {"state": "scanning", "tenant_id": "t1", "evidence_id": "e2"}
        main.refresh_guardduty_scan(item)
        assert item["state"] == state
        assert not store.promoted


def test_events_published_to_eventbridge(aws, monkeypatch):
    monkeypatch.setenv("TAAD_EVENT_BUS", "taad-bus")
    boto3.client("events").create_event_bus(Name="taad-bus")
    from app.main import emit
    ev = emit("taad.assessment.submitted.v1", "t1", {"assessment_id": "a"})
    assert "publish_failed" not in ev


def test_event_publish_failure_never_blocks(aws, monkeypatch):
    monkeypatch.setenv("TAAD_EVENT_BUS", "missing-bus")
    from app.main import emit
    assert emit("taad.assessment.submitted.v1", "t1", {})["publish_failed"] is True
    json.dumps({})


def test_gcs_store_roundtrip_with_fake_client(monkeypatch):
    from app.evidence import GCSObjectStore, make_store

    blobs = {}

    class Blob:
        def __init__(self, name): self.name = name
        def upload_from_string(self, data, content_type=None): blobs[self.name] = data
        def download_as_bytes(self): return blobs[self.name]
        def exists(self): return self.name in blobs
        def delete(self): del blobs[self.name]

    class Bucket:
        def blob(self, name): return Blob(name)

    class Client:
        def bucket(self, name):
            assert name == "evid"
            return Bucket()

    store = GCSObjectStore("evid", client=Client())
    store.put("t1", "evidence", "k1", b"hello")
    assert store.get("t1", "evidence", "k1") == b"hello" and "t1/evidence/k1" in blobs
    store.delete("t1", "evidence", "k1")
    assert not blobs
    assert not hasattr(store, "promote") and not hasattr(store, "scan_status")  # direct-evidence path, no GuardDuty tags
    monkeypatch.setenv("TAAD_OBJECT_BACKEND", "gcs")
    monkeypatch.setenv("TAAD_BUCKET_EVID", "evid")
    import google.cloud.storage as gcs
    monkeypatch.setattr(gcs, "Client", lambda: Client())
    assert isinstance(make_store(), GCSObjectStore)
