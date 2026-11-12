import pytest
from app import admin_bootstrap
from app.store import Store


class Cognito:
    def __init__(self, *, status="CONFIRMED", verified="true", sub="first-admin-sub"):
        self.status, self.verified, self.sub = status, verified, sub

    def admin_get_user(self, **kwargs):
        assert kwargs == {"UserPoolId": "pool-dev", "Username": "operator"}
        return {"UserStatus": self.status, "UserAttributes": [
            {"Name": "sub", "Value": self.sub}, {"Name": "email_verified", "Value": self.verified}
        ]}


@pytest.fixture
def configured_bootstrap(monkeypatch):
    monkeypatch.setattr(admin_bootstrap, "ENV", "dev")
    monkeypatch.setattr(admin_bootstrap, "AUTH_MODE", "oidc")
    monkeypatch.setattr(admin_bootstrap.persist, "enabled", lambda: True)
    monkeypatch.setattr(admin_bootstrap.persist, "load", lambda _store: False)
    saves = []
    monkeypatch.setattr(admin_bootstrap.persist, "save", lambda store: saves.append(store.admin_bootstrap.copy()))
    monkeypatch.setenv("TAAD_COGNITO_USER_POOL_ID", "pool-dev")
    return saves


def test_first_admin_bootstrap_is_verified_and_one_time(configured_bootstrap):
    saves = configured_bootstrap
    store = Store()
    sub = admin_bootstrap.bootstrap_first_admin("operator", store=store, cognito_client=Cognito())
    assert sub == "first-admin-sub"
    assert store.users[sub] == {"tenant_id": None, "roles": ["cloudseals_admin"]}
    assert store.admin_bootstrap["sub"] == sub
    assert len(saves) == 1
    with pytest.raises(RuntimeError, match="already completed"):
        admin_bootstrap.bootstrap_first_admin("operator", store=store, cognito_client=Cognito())


@pytest.mark.parametrize("status,verified", [("UNCONFIRMED", "true"), ("CONFIRMED", "false")])
def test_bootstrap_refuses_unconfirmed_or_unverified_identity(configured_bootstrap, status, verified):
    store = Store()
    with pytest.raises(RuntimeError, match="confirmed and have a verified email"):
        admin_bootstrap.bootstrap_first_admin("operator", store=store,
                                              cognito_client=Cognito(status=status, verified=verified))
    assert store.users == {} and store.admin_bootstrap == {}


def test_bootstrap_refuses_ephemeral_database(monkeypatch):
    monkeypatch.setattr(admin_bootstrap, "ENV", "dev")
    monkeypatch.setattr(admin_bootstrap, "AUTH_MODE", "oidc")
    monkeypatch.setattr(admin_bootstrap.persist, "enabled", lambda: False)
    with pytest.raises(RuntimeError, match="durable database"):
        admin_bootstrap.bootstrap_first_admin("operator", store=Store(), cognito_client=Cognito())


def test_bootstrap_by_sub_for_non_cognito_idp(configured_bootstrap):
    store = Store()
    assert admin_bootstrap.bootstrap_first_admin_by_sub("gcp-sub-1", store=store) == "gcp-sub-1"
    assert store.users["gcp-sub-1"]["roles"] == ["cloudseals_admin"]
    with pytest.raises(RuntimeError, match="already completed"):
        admin_bootstrap.bootstrap_first_admin_by_sub("gcp-sub-2", store=store)
    with pytest.raises(RuntimeError, match="valid OIDC subject"):
        admin_bootstrap.bootstrap_first_admin_by_sub("", store=Store())
