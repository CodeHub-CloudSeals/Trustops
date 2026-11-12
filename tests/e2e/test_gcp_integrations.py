import base64
import types

import pytest
from app import kms, llm, trustops_runtime


class FakeKms:
    """Stands in for Cloud KMS with a real P-256 key so signatures are genuinely verified."""

    def __init__(self, fail=False):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key, self.fail = ec.generate_private_key(ec.SECP256R1()), fail

    def asymmetric_sign(self, request):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        if self.fail:
            raise RuntimeError("kms down")
        sig = self.key.sign(request["digest"]["sha256"], ec.ECDSA(Prehashed(hashes.SHA256())))
        return types.SimpleNamespace(signature=sig)

    def get_public_key(self, request):
        from cryptography.hazmat.primitives import serialization
        pem = self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        return types.SimpleNamespace(pem=pem.decode())


@pytest.fixture
def signer():
    s = kms.KmsSigner("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", client=FakeKms())
    kms.set_signer(s)
    yield s
    kms.set_signer(None)


def test_evidence_records_are_kms_signed_and_tamper_evident(signer, monkeypatch):
    monkeypatch.setenv("TAAD_KMS_SIGNING_KEY_VERSION", signer.key_version)
    chain: list = []
    r1 = trustops_runtime.append_evidence(chain, "t1", "run1", "precommit", {"a": 1})
    trustops_runtime.append_evidence(chain, "t1", "run1", "commit", {"b": 2})
    assert r1["signature"]["alg"] == "ECDSA_P256_SHA256" and base64.b64decode(r1["signature"]["signature"])
    assert trustops_runtime.verify_evidence(chain, "t1")                       # hash chain still verifies with signatures attached
    assert trustops_runtime.verify_signatures(chain, "t1") == {"signed": True, "count": 2, "all_valid": True}
    chain[0]["record_hash"] = "0" * 64                                         # a forged hash no longer matches its signature
    assert trustops_runtime.verify_signatures(chain, "t1")["all_valid"] is False


def test_signing_failure_blocks_the_record(monkeypatch):
    s = kms.KmsSigner("k/1", client=FakeKms(fail=True))
    kms.set_signer(s)
    monkeypatch.setenv("TAAD_KMS_SIGNING_KEY_VERSION", "k/1")
    chain: list = []
    try:
        with pytest.raises(trustops_runtime.RuntimeErrorCode) as e:
            trustops_runtime.append_evidence(chain, "t1", "run1", "commit", {"a": 1})
        assert e.value.code == "evidence_signing_failed" and chain == []       # fail closed: nothing unsigned is stored
    finally:
        kms.set_signer(None)


def test_unsigned_mode_is_unchanged(monkeypatch):
    monkeypatch.delenv("TAAD_KMS_SIGNING_KEY_VERSION", raising=False)
    chain: list = []
    trustops_runtime.append_evidence(chain, "t1", "run1", "commit", {"a": 1})
    assert "signature" not in chain[0] and trustops_runtime.verify_signatures(chain, "t1")["signed"] is False


def test_vertex_client_sends_json_mode_system_prompt_and_budget():
    seen = {}

    class Models:
        def generate_content(self, model, contents, config):
            seen.update(model=model, contents=contents, config=config)
            return types.SimpleNamespace(text='{"ok": true}')

    c = llm.VertexModelClient("gemini-2.5-flash", client=types.SimpleNamespace(models=Models()))
    assert c.complete("be brief", "hello", max_tokens=321) == '{"ok": true}'
    assert seen["model"] == "gemini-2.5-flash" and seen["contents"] == "hello"
    assert seen["config"].max_output_tokens == 321 and seen["config"].response_mime_type == "application/json"
    assert seen["config"].system_instruction == "be brief" and seen["config"].thinking_config.thinking_budget == 0


def test_vertex_empty_response_is_an_error():
    class Models:
        def generate_content(self, **kw):
            return types.SimpleNamespace(text="")
    with pytest.raises(ValueError):
        llm.VertexModelClient("gemini-2.5-pro", client=types.SimpleNamespace(models=Models())).complete("s", "u")


def test_provider_selection(monkeypatch):
    monkeypatch.delenv("TAAD_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("TAAD_SWASKA_MODEL", raising=False)
    monkeypatch.delenv("TRUSTOPS_AGENT_MODEL_ID", raising=False)
    assert llm.provider() == "" and llm.vertex_client() is None
    monkeypatch.setenv("TRUSTOPS_AGENT_MODEL_ID", "x")
    assert llm.provider() == "bedrock"
    monkeypatch.setenv("TAAD_LLM_PROVIDER", "vertex")
    assert llm.provider() == "vertex"


def test_explicit_bedrock_provider_initialises_document_client(monkeypatch):
    from app import swaska
    seen = {}
    def make_client(model_id, region):
        seen.update(model_id=model_id, region=region)
        return object()
    monkeypatch.setenv('TAAD_LLM_PROVIDER', 'bedrock')
    monkeypatch.delenv('TAAD_SWASKA_MODEL', raising=False)
    monkeypatch.setenv('TAAD_BEDROCK_MODEL_ID', 'approved-model')
    monkeypatch.setenv('AWS_REGION', 'eu-west-2')
    monkeypatch.setattr(swaska, 'BedrockModelClient', make_client)
    assert swaska.default_client() is not None
    assert seen == {'model_id': 'approved-model', 'region': 'eu-west-2'}
