"""Authentication. dev mode: HMAC tokens. oidc mode: RS256 JWTs verified against a JWKS (Cognito / federated OIDC).

Either way the token only proves *who* the caller is; tenant and roles come from server-side membership.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any, Callable, Optional

CLOUDSEALS_ROLES = {"cloudseals_admin", "cloudseals_assessor", "cloudseals_reviewer", "cloudseals_platform_ops"}
CUSTOMER_ROLES = {"customer_admin", "customer_architect", "customer_risk", "customer_controller", "customer_contributor"}
ALL_ROLES = CLOUDSEALS_ROLES | CUSTOMER_ROLES | {"auditor_readonly"}

AUTH_MODE = os.environ.get("TAAD_AUTH_MODE", "dev")
ENV = os.environ.get("TAAD_ENV", "local")
SECRET = os.environ.get("TAAD_DEV_SECRET", "dev-only-secret-change-me").encode()

if ENV in ("staging", "prod") and AUTH_MODE != "oidc":
    raise RuntimeError("dev auth is forbidden outside local/dev environments")

# Overridable in tests: callable(token) -> signing key object
_key_resolver: Optional[Callable[[str], Any]] = None


def set_key_resolver(fn: Optional[Callable[[str], Any]]) -> None:
    global _key_resolver
    _key_resolver = fn


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def issue_token(sub: str) -> str:
    body = _b64(json.dumps({"sub": sub}).encode())
    return f"{body}.{hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()}"


def _verify_dev(token: str) -> Optional[str]:
    try:
        body, sig = token.split(".")
        good = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))["sub"]
    except Exception:
        return None


AUTH_PROVIDER = os.environ.get("TAAD_AUTH_PROVIDER", "").strip().lower()   # "google" = Google ID tokens (Workspace / Gmail)


def _verify_google(token: str) -> Optional[dict]:
    """Google ID token: signature, expiry, issuer and audience (our OAuth client ID) are checked by google-auth."""
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token
        claims = id_token.verify_oauth2_token(token, google_requests.Request(), audience=os.environ["TAAD_GOOGLE_CLIENT_ID"])
        if not claims.get("sub"):
            return None
        return {"sub": f"google:{claims['sub']}", "email": str(claims.get("email", "")).lower(),
                "email_verified": claims.get("email_verified") is True}
    except Exception:
        return None


def _verify_oidc(token: str) -> Optional[str]:
    import jwt
    try:
        if _key_resolver is not None:
            key = _key_resolver(token)
        else:
            key = jwt.PyJWKClient(os.environ["TAAD_OIDC_JWKS_URL"]).get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], issuer=os.environ["TAAD_OIDC_ISSUER"],
                            options={"require": ["exp", "iss", "sub"], "verify_aud": False})
        # Cognito access tokens carry client_id (no aud); other IdPs carry aud. One of them must match.
        aud = claims.get("aud") if claims.get("aud") is not None else claims.get("client_id")
        auds = aud if isinstance(aud, list) else [aud]
        if os.environ["TAAD_OIDC_AUDIENCE"] not in auds:
            return None
        # ID tokens are not accepted for API calls.
        if claims.get("token_use", "access") != "access":
            return None
        return str(claims["sub"])
    except Exception:
        return None


def verify_identity(token: str) -> Optional[dict]:
    """Verified identity: {sub, email, email_verified}. Roles and tenant always come from server-side membership."""
    if AUTH_MODE == "oidc" and AUTH_PROVIDER == "google":
        return _verify_google(token)
    sub = _verify_oidc(token) if AUTH_MODE == "oidc" else _verify_dev(token)
    return {"sub": sub, "email": "", "email_verified": False} if sub else None


def verify_token(token: str) -> Optional[str]:
    ident = verify_identity(token)
    return ident["sub"] if ident else None
