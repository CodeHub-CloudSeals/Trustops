# Application evidence: LangGraph workflow and optional REA collector

The assessment page supports **Website URL → Inspect website** and an advanced REA capture import. Both feed the reviewer-gated technical evidence/report workflow. Existing evidence upload, integrity and malware checks apply before ingestion.

## Public website inspection

`POST /v1/assessments/{aid}/website-inspection` accepts a domain name or URL and explicit `authorized: true` from an allowed, authenticated assessment member or staff user. Bare domain names default to HTTPS; an explicitly supplied HTTP(S) scheme is preserved. Unsupported schemes remain rejected. It performs an anonymous HTTP GET, follows at most four redirects, checks every destination against private/local/metadata addresses, pins the resolved public IP, verifies TLS certificates and uses only standard HTTP(S) ports. Proxy environment variables are not used. Requests are rate-limited by the existing per-user agent budget. The operation excludes queries/fragments, cookies, authentication, forms, scripts, prompts and subresource downloads. A bounded HTML response is parsed for its title, element count and script URL references; selected security response headers and the body SHA-256 are retained. Body text and nonselected headers are discarded. A missing header alone is not declared a security vulnerability.

The inspector emits `producer: trustops-http-inspector`, with page metadata, rather than claiming a rendered REA browser observation. The UI then uploads the generated capture through ordinary evidence safety checks and attaches it to the selected assessment. Failure does not create a report or a successful capture. The page clearly states that JavaScript, login and chatbot behaviour were not exercised. The API does not run a browser, REA CLI, shell or LLM for this operation. Final reports still require reviewer validation and publication.

## Advanced browser capture

A client-side collector runs **REA 6.5.0** against one explicitly selected browser origin and exports `trustops.rea.capture.v1` JSON. The API does not connect to the client browser or expose its debugging port. Use this route for separately authorized browser observations that exceed anonymous HTTP page inspection.

## Capture and trust boundary

The connector retains the page URL, observation timestamps, producer-reported DOM count, bounded script URL/hash metadata, bounded HTTP method/URL/status records, REA evidence ID, source-artifact digest and limitations. URL credentials are rejected; queries/fragments are removed from the normalized view. It excludes raw DOM text, script sources, cookies, credentials, storage values and request/response bodies. The private raw REA artifact can be retained on the collector host for verification.

An uploaded capture is client-supplied evidence, not a cryptographically authenticated collector attestation. File digests establish integrity of stored bytes; they do not establish origin authenticity or prove that an AI model ran. The UI and report preserve this distinction. No absent browser observation is interpreted as proof of a missing security control. HTTP failures, if actually retained, become operational findings with exact source indices; other information requests explicitly say **not verified**, not failed.

## Collect on the client/test host

Use a supported Node.js version and install the pinned optional CLI in an isolated directory:

```sh
npm install --prefix /path/to/rea-client --ignore-scripts rea-agents@6.5.0
```

Native-analysis providers are unnecessary for this passive browser connector. This does not run REA setup or modify agent registrations. Start a dedicated Chrome-family browser/profile with a **loopback-only** debugging port. The local owned test app and browser helper are `scripts/rea_test_app.py` and `scripts/start_rea_browser.sh`.

With the TrustOps Python requirements installed, export a capture:

```sh
python scripts/collect_rea.py \
  --node /absolute/path/to/node \
  --rea-cli /path/to/rea-client/node_modules/rea-agents/scripts/rea.mjs \
  --endpoint http://127.0.0.1:9227 \
  --origin http://127.0.0.1:8033 \
  --output /private/path/capture.json \
  --raw-output /private/path/raw-rea-evidence.json
```

The CLI requires exactly one matching page, enforces an explicit origin, runs passive `inspect-web-page`, and fails if REA is unavailable. An empty network observation is valid and is displayed as an unknown window, never invented traffic. Scripts are producer-reported metadata; their hashes are not independently verified script-source hashes. Do not expose browser debugging ports to other machines.

## Assessment and review

1. Open an assessment's **Application evidence** panel and attach the exported JSON. It goes through the existing quarantine/scan process. The API requires clean JSON, verifies its stored-byte SHA-256 and validates the narrow capture schema.
2. LangGraph executes capture validation and metadata analysis, then stops **before** its human-review node. Actual completed node updates, observations, findings, missing information and limits appear in the panel.
3. An authenticated `cloudseals_reviewer` supplies a reason and the current source digest to validate or reject the capture. The graph resumes; validated material generates a report draft. Customer/assessor/admin roles cannot substitute for the reviewer role.
4. The reviewer downloads an explicitly unpublished preview, then separately publishes with a reason/current digest. The API rechecks source availability, clean state and integrity. Customers download only the released, immutable HTML, including through **Reports & results**. Internal review notes/identities are not in the customer report.

Repeated attachment of identical bytes is idempotent within an assessment. A rejection cannot be silently overwritten by reattaching the same capture. A fresh capture is a new run/report. The current format is downloadable HTML with browser printing; PDF/Word conversion is not implemented for this report type.

## Persistence and scope

`application_evidence.SnapshotSaver` implements LangGraph's checkpoint interface with JSON-only server-generated checkpoints inside the existing `inventory` snapshot. It does not use pickle or deserialize client-supplied checkpoints. The graph's review boundary survives a Store SQLite/GCS snapshot save/load. This retains the application's **single-writer** restriction; it does not make the system horizontally scalable. The adapter supports this bounded, synchronous graph, not arbitrary nested graphs, time-travel APIs or delta channels. LangGraph is pinned to 1.2.16 and dependency upgrades require the restart/review tests.

All import/review/publication operations run under the existing Store lock and persistence middleware. The reviewer transition is built on a copy before commit. There is no model inference in this metadata workflow; existing document AI is separate and still needs a usable configured model. No CrewAI, ADK or DeepSeek Harness runtime was added to the API.

## Verification completed locally

- Real REA CDP observation of the owned support test application: 35 DOM nodes, 1 script and 3 HTTP requests during a five-second window. All three retained requests were HTTP 200; earlier/unexercised traffic remains unknown.
- The actual artifact completed upload, clean evidence checks, LangGraph pause/resume, local development reviewer validation, separate publication, customer download and report-library listing.
- Nine focused backend scenarios cover persistence restart, role/tenant boundaries, stale/changed evidence, rejection, deduplication, strict input, escaped report text, unavailable evidence storage and collector privacy. The complete backend suite passed 237 tests; lint and dependency checks passed.
- An opt-in Playwright test used the externally started dedicated browser and the actual capture file: customer upload, reviewer controls/preview/publication, customer download, library listing, mobile overflow and JavaScript errors. This is a **local engineering rehearsal using seeded roles**, not real customer sign-off or production UAT.

Run that UI check with `TRUSTOPS_REA_CDP`, `TRUSTOPS_REA_URL`, `TRUSTOPS_REA_CAPTURE` and optionally `TRUSTOPS_REA_UI_OUTPUT`, then `pytest tests/browser/test_application_evidence_live.py`. The test creates a local assessment and is skipped by default. `scripts/rehearse_rea_delivery.py` likewise only accepts the loopback local development service.

This feature has not been deployed to the public TrustOps domain. Live document-model connectivity, client-host installation, production acceptance and any real ERP connection require their own verification.

References: [REA](https://github.com/morluto/rea), [passive browser observation](https://github.com/morluto/rea/blob/main/docs/browser-observation.md), [LangGraph checkpoints](https://docs.langchain.com/oss/python/langgraph/persistence).
