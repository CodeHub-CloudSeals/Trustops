# Real model connections

A configured provider is not evidence of a working connection. Run the synthetic probe and a representative document/reviewer/report check before accepting a model route. There is no automatic switch to a different provider or scripted output.

## OpenAI

`TAAD_LLM_PROVIDER=openai` selects the server-side Responses API adapter for both document analysis and optional payment recommendations. `TAAD_OPENAI_MODEL` defaults to `gpt-6-luna`; `TAAD_OPENAI_REASONING` defaults to `none`. Choose an account-accessible model and supported reasoning effort explicitly if changing them. JSON mode is followed by the existing application schema, verbatim-source and authority checks. It does not itself guarantee correct findings.

Provide `OPENAI_API_KEY` through the server environment or `OPENAI_API_KEY_FILE` through a private mounted secret. Never put a key in portal JavaScript, Git, command-line arguments or chat. Customer users do not supply a key. For the local workspace, a private empty file has been prepared outside the repository at `../work/secrets/openai-api-key`; populate it locally before configuring the provider.

From the repository directory:

```bash
TAAD_LLM_PROVIDER=openai OPENAI_API_KEY_FILE=../work/secrets/openai-api-key ../work/verify-env/bin/python scripts/probe_model.py
```

Use the same provider/secret environment when starting the API. The probe prints status metadata only. API access and account quota must be available. The adapter uses a fixed HTTPS endpoint, a 60-second timeout, bounded response size, no tools and `store: false`; incomplete, refused or invalid output is rejected. The storage flag is not a promise of zero provider retention.

The original Vertex and Bedrock routes remain available. Explicit `TAAD_LLM_PROVIDER=bedrock` now initialises document agents as well as the payment route, using the configured model ID.

## Verification on 18 October 2026

- Existing Google CLI login refreshed after user sign-in. Application Default Credentials remained unavailable.
- A synthetic real Vertex call in `trustops-uat` returned HTTP 403 with a billing hold. Login alone did not restore model access.
- OpenAI transport, failure handling, secret loading and provider routing were verified with controlled test responses. No live OpenAI call has passed because no API key was configured during this check.
- The runtime's ERP connector remains `mock_sap`. Adding a model does not establish a live ERP integration, multi-instance storage safety or production readiness.

## Analysis failure and delivery behavior

Unavailable models return HTTP 503; unusable model analysis returns HTTP 502. Existing working analysis is preserved. A partly successful inventory updates only fully successful source documents and retains prior candidates for incomplete documents. Partial gap/roadmap batches also preserve prior working items. Reviewed items remain protected.

`GET /v1/report-library` returns customer-safe metadata and download routes for both published questionnaire reports and published document diagnostics. Drafts and other tenants' records stay hidden. Questionnaire exports support PDF/Word; document diagnostic exports currently support immutable HTML. Publication still requires a reviewer and source-digest checks.

Reference: [OpenAI structured output](https://developers.openai.com/api/docs/guides/structured-outputs), [current model guidance](https://developers.openai.com/api/docs/guides/latest-model).

## Self-hosted Google Cloud route

`TAAD_LLM_PROVIDER=ollama` selects an Ollama sidecar with `TAAD_OLLAMA_MODEL=qwen3:4b`. The adapter connects to `TAAD_OLLAMA_URL=http://127.0.0.1:11434`, accepts local/private sidecar hosts only, disables outbound proxies and redirects, and rejects cloud model names. No external model API key is needed. Google Cloud compute, storage and build charges still apply.

`infra/gcp/selfhost/cloudbuild.yaml` builds both the application and an Ollama image containing the model weights. The model image disables Ollama cloud features. Only the application port is exposed through Cloud Run; the model port is a private container port. `scripts/deploy_selfhost_check.py --build-id BUILD_UUID --output PLAN_PATH` deploys the completed image digests to a tagged revision with zero normal customer traffic, preserving the existing OIDC, storage and malware-scanner configuration. The model receives 4 CPUs/12 GiB; the revision has concurrency one, maximum one instance and minimum zero. This preserves the existing single-writer storage constraint.

The new revision runs a real JSON probe and a synthetic document-inventory extraction during startup. Invalid, incomplete or ungrounded output prevents startup. These checks do not save assessment data or publish reports. They establish model connectivity and a small extraction check; representative documents, reviewer approval, report publication and payment-agent execution require separate acceptance checks. Promote traffic only after the revision becomes ready and those required checks pass. Keep the previous ready revision for rollback.

The adapter requires completed JSON-object output and rejects tool calls. Normal application source-quote checks, authority rules and reviewer gates remain in force. There is no scripted success fallback when inference fails.


## Structured self-hosted output and evidence integrity

The self-hosted adapter passes server-owned JSON schemas to Ollama for the core inventory, gap, maturity, roadmap and payment-worker calls. Required JSON shape is a decoding constraint, not evidence of factual accuracy: verbatim quotes, known references, deterministic authority and reviewer checks still apply. Other provider adapters retain their existing JSON mode and validators.

Inventory verifies stored bytes against the upload hash before sending text to a model. New candidates retain that source hash. Diagnostic publication checks that the original clean source remains available with the same hash; changing evidence metadata also changes the review preview digest. Unavailable or changed sources cannot be published as newly reviewed diagnostics.


## Active UAT route — 19 October 2026

The public UAT service now uses the self-hosted Qwen3 route on revision `trustops-ui-00050-mot`. Real synthetic document/gap/maturity/roadmap/report checks completed, and the corrected six-worker positive-match acceptance passed without unnecessary escalation. Eighteen public-domain authentication/security/portal smoke checks passed after cutover. These tests do not represent a real customer's sign-off, comprehensive model accuracy, production ERP execution or production readiness.

One service instance is kept warm for demonstration availability (paid idle resources); maximum one instance and concurrency one preserve the current single-writer constraint. CPU analysis takes tens of seconds to several minutes per stage. The local portal on port 8018 still runs without a model provider; real self-hosted inference is available through the hosted UAT backend.


The 19 October customer-UI release preserves this model route. `GET /v1/agents` keeps its existing advisory `items` and additionally exposes a complete `catalog`, `total` and a separate application-evidence workflow description. The directory includes the interviewer and payment manifest entries; configured availability is not an execution claim.
