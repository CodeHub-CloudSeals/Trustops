# TrustOps Core execution runtime

## Implemented in this workspace

The LedgerSight AR/Cash workflow defines six bounded roles: Intake, Match, Reconciliation, Cash Allocation, Exception, and Audit. When `TRUSTOPS_AGENT_MODEL_ID` is set, each role makes one structured Amazon Bedrock Converse call, with temperature zero and bounded output tokens. The model receives normalized receipt, invoice, remittance, and policy fields only; it has no tools, credentials, or connector access. Invalid model responses fail the request closed. Without a configured model, the same route falls back to deterministic-only analysis and exposes that mode in `/v1/agentops` and the portal.

Deterministic policy remains authoritative. The model cannot turn an unmatched or ambiguous record into an executable proposal, approve a proposal, or call a connector. Disagreement on a deterministic exact match escalates and removes the proposal. The model can recommend a tighter review route. Each returned role recommendation and model ID is attached to the run trace. The current implementation is synchronous and has not yet been exercised against a real Bedrock account/model.

The local portal exposes these definitions and the workflow trace at **TrustOps** (`#/trustops`). Authorized tenant users can inspect all six role cards, submit a workflow payload, review tenant-scoped recent runs, view the per-agent trace and policy result, perform the sandbox approval/prepare/mock-execute path where their role permits it, and verify evidence. The page labels the runtime as **SANDBOX ONLY** and identifies `mock_sap`; it does not represent a live production service. `GET /v1/runs` returns a bounded tenant-scoped history (default 25, maximum 100) for that page. Terraform now maps `bedrock_model_id` into `TRUSTOPS_AGENT_MODEL_ID`; its task role already scopes Bedrock Converse/InvokeModel to the configured model ARN.

The workflow currently supports a strict exact-match path. A unique reference + amount + currency match can be prepared. Multiple candidates or no exact candidate escalate. A match at or above the example pack threshold (100,000 minor units) requires a different tenant member with the dedicated `customer_controller` role to approve it. Risk users and the workflow initiator cannot approve it. The threshold is illustrative and must be replaced by customer-approved pack configuration before UAT.

The execution sequence is enforced by the API:

1. `POST /v1/workflows/ledgersight.ar_cash/runs` runs all six agents and deterministic policy.
2. `POST /v1/approvals/{run_id}/decision` records approve/reject for high-value proposals; the initiator cannot approve their own proposal.
3. `POST /v1/execution/prepare` creates a prepared proposal, appends local PRE-COMMIT evidence, then issues a one-time 60-second token bound to tenant, actor, run, and proposal digest.
4. `POST /v1/execution/execute` validates that token and calls only the deterministic `mock_sap` adapter. It is idempotent by run and request key.
5. `POST /v1/evidence/{run_id}/verify` verifies the tenant's local evidence hash chain.

All routes are tenant-scoped and role-gated. The runtime is available only with `TAAD_ENV=local` or `dev` and `TRUSTOPS_RUNTIME_MODE=sandbox`; it returns unavailable in staging/prod. The short-lived token is never persisted in the application idempotency record. For non-local token signing, `TRUSTOPS_ACTION_TOKEN_SECRET` must be set; production should use a dedicated KMS asymmetric signer instead.

## Not production-ready yet

This implementation provides a model-backed sandbox path when configured, not a production TrustOps Core deployment. It is not connected to SAP and the hosted Bedrock calls have not been tested. The original Core design says Core is an existing system; its source repository and deployed service are not included in this TAAD handoff. The current code is therefore a reference runtime integrated into the TAAD API for local/dev testing.

Before production use, engineering must:

- Move the runtime into the independently deployed TrustOps Core/orchestrator and separate agent worker tasks. Use durable Step Functions/SQS execution, retry, timeout, cancellation, and DLQ recovery instead of inline API execution.
- Replace in-memory/snapshot state with normalized transactional storage, unique action/idempotency constraints, row-level tenant isolation, and concurrency-safe approval/token consumption.
- Replace the illustrative threshold and exact-match rules with an approved versioned Workflow Pack, Controller role, authority matrix, currency-aware limits, risk rules, and customer sign-off.
- Add a model gateway for the reasoning agents (Match and Reconciliation) with strict structured output, prompt/template versioning, source grounding, budget/time limits, adversarial evaluation, and deterministic fallback. Model output must never grant authority.
- Implement real source-system adapters in a separate Execution Gateway task role. Store no connector credentials in agents. Add sandbox/UAT before production and verify connector idempotency semantics against the source system.
- Replace the local SHA-256 evidence chain with canonical versioned records, KMS/HSM asymmetric signatures, durable immutable storage/Object Lock where configured, and an independently deployed verification API. Current verification explicitly reports `production_signature: false`.
- Run hosted integration, golden-path and adversarial tests (exact, ambiguous, high-value, duplicate, prompt injection, token replay/expiry, tenant crossover, PRE-COMMIT failure, connector timeout/retry, COMMIT failure), restore/recovery drills, penetration testing, and operational acceptance.

The original requirement remains: probabilistic agents may recommend or prepare only; deterministic policy and explicit human authority govern consequential actions; failed evidence PRE-COMMIT blocks execution.

## Advisory agents (TAAD / TrustOps)

Four read-only advisory agents sit beside the six runtime workers: Evidence Extractor, Findings Summarizer, POC Drafter and Approval Summarizer (`taad_agent_manifests_v1.json`, `app/taad_agents.py`, `GET /v1/agents`). They suggest; they never write answers, findings, approvals or blueprints, and every output is labelled `advisory_only` / `persisted: false`.

Production controls: allowlisted tools per manifest; deterministic output by default; when `TAAD_SWASKA_MODEL=bedrock`, model JSON is schema-checked, grounded (extraction excerpts must exist verbatim in the evidence, finding rule IDs must match, the approval summary must keep the policy reason code) and rejected to the deterministic fallback otherwise; compliance/verification claims are rejected; tenant isolation and role gates on every route; audit entry per call; per-user limit of `TAAD_AGENT_CALLS_PER_MINUTE` (default 20, in-memory per instance — use a shared limiter or WAF rate rule when running more than one task); model output is capped at 1500 tokens.

Portal: Evidence panel ("Suggest answers from this file"), reviewer panel ("Summarise findings"), POC blueprint form ("Draft scope notes"), Approvals and TrustOps run ("Summarise for approver"), and Administration → Agents.
