"""Customer-owned TrustOps membership administration; no email is sent here."""
from __future__ import annotations

import copy
import os
import re
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

ROLE_MAP = {"admin": ["customer_admin"], "submitter": ["customer_operator"],
            "reviewer": ["customer_risk"], "viewer": ["customer_viewer"]}
ROLE_LABELS = {"customer_admin": "Customer Admin", "customer_architect": "Technical user (legacy)", "customer_operator": "User / Submitter",
               "customer_risk": "Reviewer", "customer_controller": "Reviewer (controller)",
               "customer_viewer": "Viewer / Auditor", "customer_contributor": "Legacy Contributor"}


class Invite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=200)
    role: Literal["admin", "submitter", "reviewer", "viewer"] = "viewer"


class RoleChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["admin", "submitter", "reviewer", "viewer"]
    revision: int = Field(ge=0)


class Revision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=0)


def make_team_router(principal, store, persist=None):
    router = APIRouter(prefix="/v1/governance/team", tags=["Customer team and access"])

    def admin(p):
        if not p.tenant_id or "customer_admin" not in p.roles:
            raise HTTPException(403, "A customer administrator must manage team access")

    def tenant_user(p, sub):
        user = store.users.get(sub)
        if not user or user.get("tenant_id") != p.tenant_id:
            raise HTTPException(404, "Team member not found")
        return user

    def event(p, action, ref):
        store.audit.append({"at": time.time(), "sub": p.sub, "tenant_id": p.tenant_id, "action": action, "ref": ref})

    def save():
        if persist:
            persist()

    def checked_revision(user, revision):
        if user.get("membership_revision", 0) != revision:
            raise HTTPException(409, "Team access changed. Reload before continuing")

    def preserve_admin(p, sub, new_roles):
        user = tenant_user(p, sub)
        admins = sum(u.get("tenant_id") == p.tenant_id and "customer_admin" in u.get("roles", []) for u in store.users.values())
        if "customer_admin" in user["roles"] and "customer_admin" not in new_roles and admins <= 1:
            raise HTTPException(409, "Keep at least one active customer administrator")

    def public(sub, u):
        return {"sub": sub, "email": u.get("email") or sub, "roles": u["roles"],
                "role_labels": [ROLE_LABELS.get(r, r) for r in u["roles"]], "revision": u.get("membership_revision", 0)}

    @router.get("")
    def listing(p=Depends(principal)):
        admin(p)
        with store.lock:
            return {"members": [public(sub, u) for sub, u in store.users.items() if u.get("tenant_id") == p.tenant_id],
                    "pending": [{"email": email, "roles": u["roles"], "role_labels": [ROLE_LABELS.get(r, r) for r in u["roles"]],
                                 "registered_by": u.get("invited_by")} for email, u in store.pending_users.items() if u.get("tenant_id") == p.tenant_id],
                    "actor": p.sub, "local_preview": os.environ.get("TAAD_ENV", "local") == "local",
                    "role_options": [{"id": r, "label": ROLE_LABELS[v[0]]} for r, v in ROLE_MAP.items()],
                    "delivery": "Access registration only. No invitation email is sent. Hosted users sign in with their verified work email."}

    @router.post("/invites", status_code=201)
    def invite(body: Invite, p=Depends(principal)):
        admin(p)
        email = body.email.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise HTTPException(422, "Enter a valid work email")
        with store.lock:
            if any(email == sub.lower() or email == str(u.get("email", "")).lower() for sub, u in store.users.items()) or email in store.pending_users:
                raise HTTPException(409, "This email already has access or a pending access request")
            store.pending_users[email] = {"roles": ROLE_MAP[body.role], "tenant_id": p.tenant_id, "invited_by": p.sub, "at": time.time()}
            event(p, "governance.team.access_registered", email)
            try:
                save()
            except Exception:
                store.pending_users.pop(email, None)
                raise HTTPException(503, "Could not save access registration. Retry after reloading") from None
        return {"email": email, "status": "PENDING_SIGN_IN", "email_sent": False}

    @router.post("/preview-activate")
    def preview_activate(body: Invite, p=Depends(principal)):
        admin(p)
        if os.environ.get("TAAD_ENV", "local") != "local" or os.environ.get("TAAD_AUTH_MODE", "dev") != "dev":
            raise HTTPException(404, "Local preview action not available")
        email = body.email.strip().lower()
        with store.lock:
            pending = store.pending_users.get(email)
            if not pending or pending.get("tenant_id") != p.tenant_id or email in store.users:
                raise HTTPException(404, "Pending access registration not found")
            # The pending record is authoritative: request body cannot substitute a role.
            store.users[email] = {"email": email, "tenant_id": p.tenant_id, "roles": list(pending["roles"]), "membership_revision": 1}
            del store.pending_users[email]
            event(p, "governance.team.preview_activated", email)
            try:
                save()
            except Exception:
                store.users.pop(email, None); store.pending_users[email] = pending
                raise HTTPException(503, "Could not save preview membership") from None
        return {"status": "ACTIVE_LOCAL_PREVIEW", "member": public(email, store.users[email])}

    @router.post("/pending/cancel")
    def cancel_pending(body: Invite, p=Depends(principal)):
        admin(p)
        email = body.email.strip().lower()
        with store.lock:
            pending = store.pending_users.get(email)
            if not pending or pending.get("tenant_id") != p.tenant_id:
                raise HTTPException(404, "Pending registration not found")
            del store.pending_users[email]
            event(p, "governance.team.registration_cancelled", email)
            try:
                save()
            except Exception:
                store.pending_users[email] = pending
                raise HTTPException(503, "Could not cancel access registration") from None
        return {"cancelled": True}

    @router.put("/members/{sub:path}/role")
    def change_role(sub: str, body: RoleChange, p=Depends(principal)):
        admin(p)
        with store.lock:
            user = tenant_user(p, sub)
            checked_revision(user, body.revision)
            preserve_admin(p, sub, ROLE_MAP[body.role])
            old = copy.deepcopy(user)
            user.update(roles=list(ROLE_MAP[body.role]), membership_revision=body.revision + 1)
            event(p, "governance.team.role_changed", sub)
            try:
                save()
            except Exception:
                store.users[sub] = old
                raise HTTPException(503, "Could not save the role change") from None
        return public(sub, user)

    @router.post("/members/{sub:path}/revoke")
    def revoke(sub: str, body: Revision, p=Depends(principal)):
        admin(p)
        if sub == p.sub:
            raise HTTPException(409, "Another customer administrator must revoke your access")
        with store.lock:
            user = tenant_user(p, sub)
            checked_revision(user, body.revision)
            preserve_admin(p, sub, [])
            old = store.users.pop(sub)
            event(p, "governance.team.access_revoked", sub)
            try:
                save()
            except Exception:
                store.users[sub] = old
                raise HTTPException(503, "Could not revoke access") from None
        return {"revoked": True}

    return router
