"""In-memory repository (POC). Swap for Aurora Postgres behind the same interface in Gate 6."""
from __future__ import annotations

import threading
from typing import Any


class Store:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users: dict[str, dict[str, Any]] = {}          # sub -> {tenant_id, roles, email?}
        self.pending_users: dict[str, dict[str, Any]] = {}  # verified email -> {tenant_id, roles, invited_by, at}; activated at first sign-in
        self.tenants: dict[str, dict[str, Any]] = {}
        self.assessments: dict[str, dict[str, Any]] = {}
        self.answers: dict[tuple[str, str, str], dict[str, Any]] = {}   # (assessment, scope, qid)
        self.revisions: list[dict[str, Any]] = []
        self.evidence: dict[str, dict[str, Any]] = {}
        self.findings: dict[str, list[dict]] = {}
        self.reports: dict[str, dict[str, Any]] = {}
        self.blueprints: dict[str, dict[str, Any]] = {}
        self.cases: dict[str, dict[str, Any]] = {}           # CloudSeals engagement cases (staff only), may link several assessments
        self.inventory: dict[str, dict[str, Any]] = {}       # assessment -> {"use_cases": [...], "gaps": [...]} (UNREVIEWED until validated)
        self.idempotency: dict[tuple[str, str, str], Any] = {}
        self.registrations: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.audit: list[dict[str, Any]] = []
        self.invitations: dict[str, dict[str, Any]] = {}     # sha256(token) -> invitation
        self.assignments: dict[str, dict[str, list[str]]] = {}  # assessment -> {sub: [sections]}
        self.engagements: dict[str, dict[str, Any]] = {}      # approved engagement refs
        self.rate: dict[str, list[float]] = {}
        self.outbox: list[dict[str, Any]] = []                # SES stand-in
        self.not_assessed: dict[str, list[dict]] = {}
        self.admin_bootstrap: dict[str, Any] = {}             # immutable first-admin bootstrap marker
        self.workflow_runs: dict[str, dict[str, Any]] = {}   # TrustOps Core bounded workflow runtime
        self.action_tokens: dict[str, dict[str, Any]] = {}   # token digest -> one-time execution grant
        self.runtime_evidence: list[dict[str, Any]] = []     # append-only local hash chain (KMS adapter required in AWS)
        self.mock_sap: dict[str, dict[str, Any]] = {}         # sandbox connector only; never production ERP writes
        self.integrations: dict[str, dict[str, Any]] = {}    # integration id -> {tenant, body, secret (Fernet ciphertext)}
        self.decisions: list[dict[str, Any]] = []            # append-only per-tenant hash-chained policy decisions
        self.policy_rules: dict[str, list[dict[str, Any]]] = {}  # tenant -> ordered policy rules
        self.agents: dict[str, dict[str, Any]] = {}          # authority registry: agent id -> identity, owner, status, client scope
