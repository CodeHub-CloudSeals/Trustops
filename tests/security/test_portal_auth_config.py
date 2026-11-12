import json
from pathlib import Path

import pytest
from app import main
from fastapi import HTTPException
from fastapi.testclient import TestClient


def test_local_portal_explicitly_uses_seeded_development_login(monkeypatch):
    monkeypatch.setattr(main, "ENV", "local")
    monkeypatch.setattr(main, "AUTH_MODE", "dev")
    monkeypatch.setattr(main, "SWASKA_CLIENT", None)
    assert main.portal_config() == {"mode": "dev", "oidc": {}, "assessment_model": "unavailable"}
    response = TestClient(main.app).get("/portal/config.json")
    assert response.status_code == 200 and response.json()["mode"] == "dev"


def test_portal_distinguishes_scripted_demo_from_real_model(monkeypatch):
    monkeypatch.setattr(main, "ENV", "local")
    monkeypatch.setattr(main, "AUTH_MODE", "dev")
    class DemoModel:
        is_demo = True
    monkeypatch.setattr(main, "SWASKA_CLIENT", DemoModel())
    assert main.portal_config()["assessment_model"] == "demo"
    monkeypatch.setattr(main, "SWASKA_CLIENT", object())
    assert main.portal_config()["assessment_model"] == "configured"


def test_deployed_portal_fails_closed_without_cognito_settings(monkeypatch):
    monkeypatch.setattr(main, "ENV", "dev")
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")
    for name in ("TAAD_PORTAL_AUTHORIZE_URL", "TAAD_PORTAL_TOKEN_URL", "TAAD_PORTAL_CLIENT_ID",
                 "TAAD_PORTAL_REDIRECT_URI", "TAAD_PORTAL_LOGOUT_URL"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(HTTPException) as exc:
        main.portal_config()
    assert exc.value.status_code == 503
    assert exc.value.detail["code"] == "portal_auth_misconfigured"


def test_deployed_portal_returns_only_configured_cognito_auth(monkeypatch):
    monkeypatch.setattr(main, "ENV", "dev")
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")
    values = {
        "TAAD_PORTAL_AUTHORIZE_URL": "https://auth.example.test/oauth2/authorize",
        "TAAD_PORTAL_TOKEN_URL": "https://auth.example.test/oauth2/token",
        "TAAD_PORTAL_CLIENT_ID": "public-client-id",
        "TAAD_PORTAL_REDIRECT_URI": "https://taad.example.test/portal/",
        "TAAD_PORTAL_LOGOUT_URL": "https://auth.example.test/logout",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    cfg = main.portal_config()
    assert cfg["mode"] == "oidc"
    assert cfg["oidc"]["client_id"] == "public-client-id"
    assert cfg["oidc"]["redirect_uri"] == values["TAAD_PORTAL_REDIRECT_URI"]
    assert cfg["oidc"]["scope"] == "openid email"
    template = json.loads((Path(main.ROOT) / "apps/portal-web/config.json").read_text())
    assert template["mode"] == "oidc"
    response = TestClient(main.app).get("/portal/config.json")
    assert response.status_code == 200 and response.json() == cfg


def test_portal_csp_allows_only_the_configured_cognito_token_origin(monkeypatch):
    monkeypatch.setattr(main, "AUTH_MODE", "oidc")
    monkeypatch.setenv("TAAD_PORTAL_TOKEN_URL", "https://auth.example.test/oauth2/token")
    response = TestClient(main.app).get("/portal/")
    csp = response.headers["content-security-policy"]
    assert "connect-src 'self' https://auth.example.test" in csp
    assert "https://other.example.test" not in csp
