import time

import jwt
import pytest
from app import security
from cryptography.hazmat.primitives.asymmetric import rsa

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def mint(key=KEY, **over):
    claims = {"sub": "admin@t-bank", "iss": "https://issuer.example", "aud": "taad-api", "exp": int(time.time()) + 300, "token_use": "access"}
    claims.update(over)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, key, algorithm="RS256")


@pytest.fixture()
def oidc(env, monkeypatch):
    monkeypatch.setattr(security, "AUTH_MODE", "oidc")
    monkeypatch.setenv("TAAD_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("TAAD_OIDC_AUDIENCE", "taad-api")
    security.set_key_resolver(lambda token: KEY.public_key())
    yield env
    security.set_key_resolver(None)


def call(c, token):
    return c.get("/v1/assessments", headers={"Authorization": f"Bearer {token}"}).status_code


def test_valid_token_accepted_dev_token_rejected(oidc):
    c, h = oidc
    assert call(c, mint()) == 200
    assert c.get("/v1/assessments", headers=h("admin@t-bank")).status_code == 401  # HMAC dev tokens disabled in oidc mode


@pytest.mark.parametrize("over", [{"exp": int(time.time()) - 10}, {"aud": "other"}, {"iss": "https://evil.example"},
                                  {"token_use": "id"}, {"sub": None}])
def test_bad_claims_rejected(oidc, over):
    c, _ = oidc
    assert call(c, mint(**over)) == 401


def test_wrong_signature_and_alg_none_rejected(oidc):
    c, _ = oidc
    assert call(c, mint(key=OTHER)) == 401  # resolver returns KEY.public_key, token signed by OTHER
    none_tok = jwt.encode({"sub": "admin@t-bank", "iss": "https://issuer.example", "aud": "taad-api", "exp": int(time.time()) + 300}, None, algorithm="none")
    assert call(c, none_tok) == 401


def test_valid_token_without_membership_gets_no_access(oidc):
    c, _ = oidc
    assert call(c, mint(sub="stranger")) == 401


def test_dev_auth_refused_in_prod(monkeypatch):
    import importlib
    monkeypatch.setenv("TAAD_ENV", "prod")
    monkeypatch.setenv("TAAD_AUTH_MODE", "dev")
    with pytest.raises(RuntimeError):
        importlib.reload(security)
    monkeypatch.delenv("TAAD_ENV")
    importlib.reload(security)


def test_cognito_style_access_token_with_client_id(oidc):
    c, _ = oidc
    assert call(c, mint(aud=None, client_id="taad-api")) == 200
    assert call(c, mint(aud=None, client_id="someone-elses-client")) == 401
    assert call(c, mint(aud=["x", "taad-api"])) == 200
