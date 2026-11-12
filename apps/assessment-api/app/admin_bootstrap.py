"""One-time first CloudSeals admin bootstrap for an approved AWS DEV environment.

Run inside the API task with its least-privilege task role after the Cognito user has
been created and verified. No password or access token is accepted or persisted.
"""
from __future__ import annotations

import argparse
import os
import time
from typing import Any

from . import persist
from .security import AUTH_MODE, ENV
from .store import Store


def bootstrap_first_admin(cognito_username: str, *, store: Store, cognito_client: Any) -> str:
    """Grant the first CloudSeals admin role to a confirmed, email-verified Cognito user."""
    if ENV != "dev" or AUTH_MODE != "oidc":
        raise RuntimeError("Bootstrap is allowed only in the OIDC-authenticated dev environment")
    if not persist.enabled():
        raise RuntimeError("A durable database is required; refusing to bootstrap ephemeral state")
    pool_id = os.environ.get("TAAD_COGNITO_USER_POOL_ID")
    if not pool_id:
        raise RuntimeError("TAAD_COGNITO_USER_POOL_ID is required")

    identity = cognito_client.admin_get_user(UserPoolId=pool_id, Username=cognito_username)
    attrs = {item["Name"]: item["Value"] for item in identity.get("UserAttributes", [])}
    sub = attrs.get("sub")
    if identity.get("UserStatus") != "CONFIRMED" or attrs.get("email_verified", "").lower() != "true" or not sub:
        raise RuntimeError("Cognito identity must be confirmed and have a verified email")

    # Reload immediately before the one-time check. The SQL snapshot uses optimistic
    # versioning, so concurrent bootstrap attempts cannot both commit successfully.
    persist.load(store)
    with store.lock:
        if store.admin_bootstrap or any("cloudseals_admin" in u.get("roles", []) for u in store.users.values()):
            raise RuntimeError("A CloudSeals admin bootstrap has already completed")
        if sub in store.users:
            raise RuntimeError("Cognito identity already has a membership")
        store.users[sub] = {"tenant_id": None, "roles": ["cloudseals_admin"]}
        store.admin_bootstrap.update({"completed_at": time.time(), "sub": sub})
        store.audit.append({"at": time.time(), "sub": sub, "tenant_id": None,
                            "action": "admin.bootstrap", "ref": "first_cloudseals_admin"})
        persist.save(store)
    return sub


def bootstrap_first_admin_by_sub(sub: str, *, store: Store) -> str:
    """IdP-neutral bootstrap (GCP / any OIDC provider): the operator supplies the verified OIDC `sub` of the first admin."""
    if ENV != "dev" or AUTH_MODE != "oidc":
        raise RuntimeError("Bootstrap is allowed only in the OIDC-authenticated dev environment")
    if not persist.enabled():
        raise RuntimeError("A durable database is required; refusing to bootstrap ephemeral state")
    if not sub or len(sub) > 256:
        raise RuntimeError("A valid OIDC subject is required")
    persist.load(store)
    with store.lock:
        if store.admin_bootstrap or any("cloudseals_admin" in u.get("roles", []) for u in store.users.values()):
            raise RuntimeError("A CloudSeals admin bootstrap has already completed")
        if sub in store.users:
            raise RuntimeError("This identity already has a membership")
        store.users[sub] = {"tenant_id": None, "roles": ["cloudseals_admin"]}
        store.admin_bootstrap.update({"completed_at": time.time(), "sub": sub})
        store.audit.append({"at": time.time(), "sub": sub, "tenant_id": None,
                            "action": "admin.bootstrap", "ref": "first_cloudseals_admin"})
        persist.save(store)
    return sub


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap the first CloudSeals admin in AWS DEV.")
    who = parser.add_mutually_exclusive_group(required=True)
    who.add_argument("--cognito-username", help="Exact Cognito username for the pre-created, confirmed, email-verified operator")
    who.add_argument("--sub", help="OIDC subject (`sub` claim) of the first admin, for non-Cognito identity providers (GCP)")
    args = parser.parse_args()
    if not persist.enabled():
        raise SystemExit("Bootstrap refused: database persistence is not configured")

    from .main import STORE

    try:
        if args.sub:
            sub = bootstrap_first_admin_by_sub(args.sub, store=STORE)
        else:
            import boto3
            sub = bootstrap_first_admin(args.cognito_username, store=STORE,
                                        cognito_client=boto3.client("cognito-idp"))
    except Exception as exc:
        raise SystemExit(f"Bootstrap refused: {exc}") from None
    print(f"First CloudSeals admin bootstrapped for Cognito sub {sub}.")


if __name__ == "__main__":
    main()
