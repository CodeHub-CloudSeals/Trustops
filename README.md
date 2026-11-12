# CloudSeals TrustOps

TrustOps is a governance layer between AI agents and the business systems they act on.
Applications ask TrustOps before a consequential action; TrustOps answers **ALLOW**, **ESCALATE**
(a person decides) or **DENY**, records the decision as evidence, and gives risk and compliance
teams one place to see and control what their AI is doing.

## What is in the console

| Area | Purpose |
|---|---|
| **Overview** | What needs attention: approvals waiting, denials, decisions, applications |
| **Approvals** | Items escalated by policy or submitted for review. Reviewers see the details side by side and approve or reject (maker-checker: the requester can never approve) |
| **Decisions** | Live feed of every Allow / Escalate / Deny with the policy and reason |
| **Risk** | Agents to watch, approvals waiting too long, 7-day trend, rules firing most |
| **Policies** | Ordered rules per workflow pack (Finance pack today); test a decision without an application |
| **Authority** | What every agent may do, applications and their agents (suspend / resume), who can approve or change rules |
| **Evidence** | Search decisions, verify the SHA-256 hash chain, PDF report |
| **Reports** | Governance report as PDF |
| **Applications** | Add an application by name; TrustOps issues the key it uses |

CloudSeals AI readiness assessments (questionnaire, evidence, reviewed reports) remain available
from Reports → AI readiness assessment.

## Connecting an application

1. Applications → **Add application** → enter a name → **Create key**.
2. Put the two values shown in the application's settings:
   ```
   TRUSTOPS_URL=https://<your TrustOps host>
   TRUSTOPS_KEY=tok_…
   ```
3. Before each consequential action the application calls:
   ```
   POST /v1/decisions            header X-TrustOps-Key: <key>
   {"actor": {"type": "agent", "id": "match-agent"}, "action": "approve_match",
    "amount_minor": 1240000, "currency": "USD", "client": "client-a", "resource": "item-123",
    "title": "...", "compare": {...}, "recommendation": "...", "documents": [...]}
   → {"decision": "ALLOW" | "ESCALATE" | "DENY", "policy_id": "...", "reason": "...", "decision_id": "dec_…"}
   ```
   and, for ESCALATE, polls `GET /v1/decisions/{decision_id}/status` → `APPROVED | REJECTED | PENDING`.
4. Optional: set the application's address in Applications so reviewers can **Load details**;
   TrustOps then calls `GET <address>/trustops/items/{ref}` with the same `X-TrustOps-Key`.

To submit an item for human review, send `"action": "submit_for_review"` (rule FIN-00 always escalates).

## Run locally

```sh
python3.12 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
TAAD_ENV=local TAAD_AUTH_MODE=dev TAAD_SEED=1 make dev      # http://localhost:8000/portal/
```

## Tests

```sh
make test       # API, security, contracts
make browser    # Playwright UI tests (needs: .venv/bin/playwright install chromium)
```

## Deploy

Cloud Run on GCP — see [docs/GCP_DEPLOYMENT.md](docs/GCP_DEPLOYMENT.md) and `infra/gcp/`.
In hosted environments set `TRUSTOPS_INTEGRATION_KEY` (a Fernet key from Secret Manager) so
application credentials can be stored encrypted; without it TrustOps refuses to store them.

## Known limits

- Evidence is a SHA-256 hash chain; KMS signing is used only when a key is configured.
- Cost per run is not tracked yet.
- Only the Finance workflow pack exists; other packs are planned.
- State is a single-writer snapshot (GCS or Postgres); run one API instance.
- Agent risk flags use simple thresholds, not anomaly detection.

## Layout

```
apps/assessment-api/   FastAPI service (decisions.py, app_integrations.py, main.py …)
apps/portal-web/       Console (vanilla JS, strict CSP)
packages/              question-engine, reporting
packs/                 workflow packs
db/migrations/         database schema
infra/gcp/             Cloud Run setup
tests/                 unit, e2e, security, contracts, browser
docs/                  deployment, security, runtime, model connections
```
