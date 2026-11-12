"""Cloud KMS signing for runtime evidence records (asymmetric EC P-256 key; the private key never leaves KMS).

Fail closed: when a key is configured and signing fails, the caller must abort. An unsigned record is never stored.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Any, Callable, Optional


class SigningError(RuntimeError):
    pass


class KmsSigner:
    def __init__(self, key_version: str, client: Any = None) -> None:
        self.key_version = key_version
        if client is None:
            from google.cloud import kms  # lazy: optional dependency
            client = kms.KeyManagementServiceClient()
        self.client = client

    def sign(self, digest_hex: str) -> dict[str, str]:
        try:
            r = self.client.asymmetric_sign(request={"name": self.key_version, "digest": {"sha256": bytes.fromhex(digest_hex)}})
        except Exception as exc:
            raise SigningError("KMS signing failed") from exc
        return {"alg": "ECDSA_P256_SHA256", "key_version": self.key_version, "signature": base64.b64encode(r.signature).decode()}

    def verify(self, digest_hex: str, signature: dict[str, str]) -> bool:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
            pem = self.client.get_public_key(request={"name": signature["key_version"]}).pem.encode()
            serialization.load_pem_public_key(pem).verify(base64.b64decode(signature["signature"]), bytes.fromhex(digest_hex),
                                                          ec.ECDSA(Prehashed(hashes.SHA256())))
            return True
        except Exception:
            return False


_signer: Optional[KmsSigner] = None


def from_env() -> Optional[KmsSigner]:
    global _signer
    key = os.environ.get("TAAD_KMS_SIGNING_KEY_VERSION", "").strip()
    if not key:
        return None
    if _signer is None or _signer.key_version != key:
        _signer = KmsSigner(key)
    return _signer


def set_signer(signer: Optional[KmsSigner]) -> None:  # tests
    global _signer
    _signer = signer


def digest_of(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


SignFn = Callable[[str], dict[str, str]]
