"""Evidence quarantine: size/hash/magic-byte checks, signature scan, injection flagging.

Local filesystem object store for dev; the same interface maps to S3 + GuardDuty Malware Protection in AWS.
Documents are untrusted inputs: only metadata ever reaches Swaska.
"""
from __future__ import annotations

import hashlib
import os
import re
import zipfile
from io import BytesIO
from pathlib import Path

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SIGNATURES = [EICAR, b"MZ\x90\x00\x03", b"\x7fELF", b"<script", b"#!/bin/sh"]
INJ = re.compile(rb"ignore (all|previous|prior) instructions|you are now|system prompt|disregard the above", re.I)
TEXT_TYPES = {"text/plain", "text/csv", "application/json"}
ZIP_TYPES = {"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
             "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


class LocalObjectStore:
    def __init__(self, root: str | None = None) -> None:
        self.root = Path(root or os.environ.get("TAAD_OBJECT_ROOT", "/tmp/taad-objects"))

    def path(self, tenant: str, bucket: str, key: str) -> Path:
        # key is always a server-generated UUID; client filenames never touch the filesystem.
        p = (self.root / tenant / bucket / key).resolve()
        if self.root.resolve() not in p.parents:
            raise ValueError("path escape")
        return p

    def put(self, tenant: str, bucket: str, key: str, data: bytes) -> None:
        p = self.path(tenant, bucket, key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def get(self, tenant: str, bucket: str, key: str) -> bytes:
        return self.path(tenant, bucket, key).read_bytes()

    def delete(self, tenant: str, bucket: str, key: str) -> None:
        self.path(tenant, bucket, key).unlink(missing_ok=True)


def inspect(content_type: str, data: bytes, claimed_sha256: str, declared_size: int) -> dict:
    """Return {'state': clean|rejected|infected, 'reason', 'injection_flagged'}."""
    if len(data) != declared_size:
        return {"state": "rejected", "reason": "size_mismatch", "injection_flagged": False}
    if hashlib.sha256(data).hexdigest() != claimed_sha256.lower():
        return {"state": "rejected", "reason": "sha256_mismatch", "injection_flagged": False}
    head = data[:2048]
    if content_type == "application/pdf" and not head.startswith(b"%PDF-"):
        return {"state": "rejected", "reason": "magic_mismatch", "injection_flagged": False}
    if content_type in ZIP_TYPES:
        try:
            with zipfile.ZipFile(BytesIO(data)) as z:
                if z.testzip() is not None or sum(i.file_size for i in z.infolist()) > 200 * 1024 * 1024 \
                        or any(i.filename.startswith(("/", "..")) for i in z.infolist()):
                    return {"state": "rejected", "reason": "unsafe_archive", "injection_flagged": False}
                if any(i.filename.lower().endswith((".bin", ".exe")) or "vbaProject" in i.filename for i in z.infolist()):
                    return {"state": "rejected", "reason": "macro_or_binary_content", "injection_flagged": False}
        except zipfile.BadZipFile:
            return {"state": "rejected", "reason": "magic_mismatch", "injection_flagged": False}
    if content_type in TEXT_TYPES:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return {"state": "rejected", "reason": "not_utf8_text", "injection_flagged": False}
    if any(sig in data for sig in SIGNATURES):
        return {"state": "infected", "reason": "signature_match", "injection_flagged": False}
    return {"state": "clean", "reason": "", "injection_flagged": bool(INJ.search(data))}


class S3ObjectStore:
    """S3 backend: quarantine bucket (GuardDuty Malware Protection) -> evidence bucket. SSE-KMS on every write."""

    def __init__(self, quarantine: str, evidence: str, kms_key_arn: str, client=None) -> None:
        import boto3  # lazy
        self.s3 = client or boto3.client("s3")
        self.buckets = {"quarantine": quarantine, "evidence": evidence}
        self.kms = kms_key_arn

    def put(self, tenant: str, bucket: str, key: str, data: bytes) -> None:
        self.s3.put_object(Bucket=self.buckets[bucket], Key=f"{tenant}/{key}", Body=data,
                           ServerSideEncryption="aws:kms", SSEKMSKeyId=self.kms)

    def promote(self, tenant: str, key: str) -> None:
        """Copy a scanned-clean object from quarantine to evidence, then remove the quarantined copy."""
        src = {"Bucket": self.buckets["quarantine"], "Key": f"{tenant}/{key}"}
        self.s3.copy_object(Bucket=self.buckets["evidence"], Key=f"{tenant}/{key}", CopySource=src,
                            ServerSideEncryption="aws:kms", SSEKMSKeyId=self.kms)
        self.s3.delete_object(**src)

    def get(self, tenant: str, bucket: str, key: str) -> bytes:
        return self.s3.get_object(Bucket=self.buckets[bucket], Key=f"{tenant}/{key}")["Body"].read()

    def scan_status(self, tenant: str, key: str) -> str | None:
        """Read GuardDuty's post-scan tag. Missing tags mean the asynchronous scan is pending."""
        result = self.s3.get_object_tagging(
            Bucket=self.buckets["quarantine"], Key=f"{tenant}/{key}"
        )
        return next((tag["Value"] for tag in result.get("TagSet", [])
                     if tag.get("Key") == "GuardDutyMalwareScanStatus"), None)

    def delete(self, tenant: str, bucket: str, key: str) -> None:
        self.s3.delete_object(Bucket=self.buckets[bucket], Key=f"{tenant}/{key}")


class GCSObjectStore:
    """Google Cloud Storage backend (single evidence bucket, CMEK optional, no public access).

    Unlike the S3 path there is no asynchronous malware-scan tag: uploads rely on the byte-level checks in `inspect`
    before they are stored. Add a scanner (e.g. a Cloud Run job reading this bucket) before accepting untrusted files in prod.
    """

    def __init__(self, evidence_bucket: str, client=None) -> None:
        if client is None:
            from google.cloud import storage  # lazy: optional dependency
            client = storage.Client()
        self.bucket = client.bucket(evidence_bucket)

    def put(self, tenant: str, bucket: str, key: str, data: bytes) -> None:
        self.bucket.blob(f"{tenant}/{bucket}/{key}").upload_from_string(data, content_type="application/octet-stream")

    def get(self, tenant: str, bucket: str, key: str) -> bytes:
        return self.bucket.blob(f"{tenant}/{bucket}/{key}").download_as_bytes()

    def delete(self, tenant: str, bucket: str, key: str) -> None:
        blob = self.bucket.blob(f"{tenant}/{bucket}/{key}")
        if blob.exists():
            blob.delete()


def make_store():
    if os.environ.get("TAAD_OBJECT_BACKEND") == "gcs":
        return GCSObjectStore(os.environ["TAAD_BUCKET_EVID"])
    if os.environ.get("TAAD_OBJECT_BACKEND") == "s3":
        return S3ObjectStore(os.environ["TAAD_BUCKET_QUAR"], os.environ["TAAD_BUCKET_EVID"], os.environ["TAAD_KMS_KEY_ARN"])
    return LocalObjectStore()
