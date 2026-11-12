"""Seed sample bank / health / logistics tenants and staff users; returns dev tokens."""
from __future__ import annotations

from .main import STORE
from .security import issue_token

TENANTS = {"t-bank": "Demo Bank plc", "t-health": "Demo Health Trust", "t-logistics": "Demo Logistics Ltd"}


def seed() -> dict[str, str]:
    for tid, name in TENANTS.items():
        STORE.tenants[tid] = {"tenant_id": tid, "name": name}
        STORE.users[f"admin@{tid}"] = {"tenant_id": tid, "roles": ["customer_admin", "customer_architect"]}
        STORE.users[f"risk@{tid}"] = {"tenant_id": tid, "roles": ["customer_risk"]}
        STORE.users[f"controller@{tid}"] = {"tenant_id": tid, "roles": ["customer_controller"]}
        STORE.users[f"controller2@{tid}"] = {"tenant_id": tid, "roles": ["customer_controller"]}
        STORE.users[f"contrib@{tid}"] = {"tenant_id": tid, "roles": ["customer_contributor"]}
    STORE.engagements["ENG-DEMO-001"] = {"status": "approved", "organisation": "Demo Co"}
    STORE.users["reviewer@cloudseals"] = {"tenant_id": None, "roles": ["cloudseals_reviewer"]}
    STORE.users["architect@cloudseals"] = {"tenant_id": None, "roles": ["cloudseals_admin", "cloudseals_assessor"]}
    return {sub: issue_token(sub) for sub in STORE.users}
