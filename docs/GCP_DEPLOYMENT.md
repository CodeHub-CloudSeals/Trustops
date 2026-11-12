# GCP deployment (Cloud Run + Cloud Storage + Cloud KMS + Vertex AI)

`infra/gcp/setup.sh` provisions and deploys everything. It is idempotent: re-running reuses resources.

```bash
export PROJECT_ID=trustops-uat REGION=europe-west1
export GOOGLE_CLIENT_ID=<oauth client id> GOOGLE_SECRET=<Secret Manager name of the client secret>
export FIRST_ADMIN_EMAIL=you@cloudseals.co.uk
export SERVICE=trustops-ui PUBLIC_URL=https://trustops.cloudseals.com REDIRECT_PATH=/api/auth/callback/google   # custom domain, see below
export LLM_PROVIDER=vertex      # empty = deterministic agents only
export CLAMAV=true              # ClamAV sidecar scans every upload (~4 GiB / 2 vCPU per instance)
./infra/gcp/setup.sh
```

## What it creates
Artifact Registry repo, private versioned evidence bucket, private versioned **state bucket** (one JSON snapshot, optimistic locking, 30-day history), Cloud KMS EC P-256 signing key, two least-privilege service accounts, then `cloudbuild.yaml`: tests -> image -> push -> (mirror ClamAV) -> Cloud Run deploy -> /health smoke test.

State is in GCS, not Cloud SQL, because the organisation policy `sql.restrictPublicIp` blocks public-IP Cloud SQL and a private-IP VPC was out of scope. The PostgreSQL backend is still in the code (`TAAD_DATABASE_URL`).

## Custom domain
`trustops.cloudseals.com` is mapped to the Cloud Run service named `trustops-ui`, so the app is deployed *as* that service (`SERVICE=trustops-ui`). The OAuth client already lists `https://trustops.cloudseals.com/api/auth/callback/google`; the app forwards that path to the portal, so no console change is needed. For a different URL add `<url>/portal/` (default `REDIRECT_PATH`) as an authorised redirect URI.
Rollback of the previous Next.js UI: `~/trustops/trustops-uat-cloudrun-backup/trustops-ui.yaml` plus the image `trustops-ui:4a418b8` (source: GitHub `cs-trustops-studio/trustops-ui`).

## How the pieces connect
| Concern | Implementation |
|---|---|
| Sign-in | Google OAuth code flow; `POST /v1/auth/token` adds the client secret server-side; the API verifies the Google ID token. Roles/tenant come from server-side membership. |
| First admin | `TAAD_FIRST_ADMIN_EMAIL`: first verified sign-in becomes **owner** (all CloudSeals roles), once, `TAAD_ENV=dev` only. Others: Administration -> Users (staff roles limited to `TAAD_STAFF_EMAIL_DOMAINS`). |
| LLM | `TAAD_LLM_PROVIDER=vertex` -> Gemini; JSON-only, token-capped, grounded; failures fall back or fail closed. |
| Evidence integrity | `TAAD_KMS_SIGNING_KEY_VERSION` -> Cloud KMS signs every runtime evidence record; signing failure blocks the action. Verified against the real key. |
| Malware scanning | `TAAD_CLAMD_HOST` -> ClamAV INSTREAM; mandatory when configured (scanner down = upload rejected). |

## Tests
`pytest -q` (unit/API), `pytest tests/browser` (Playwright against a real server with a scripted model), and `DEPLOYED_URL=https://trustops.cloudseals.com pytest tests/browser/test_deployed_smoke.py` against the live site (cannot sign in with Google; covers shell, config, redirects, headers, anonymous refusal, Google redirect).

## Constraints
- **One instance** (`min=max=1`): single-writer snapshot, in-memory rate limiter.
- `APP_ENV=dev` enables the sandbox workflow runtime (mock ERP connector) and first-admin bootstrap; real connectors need the Core runtime integration in PROJECT_COMPLETION_STATUS.md.
- Vertex AI needs the billing account to be in good standing (a payment hold returns `Lightning dunning decision is deny`).
- Framework definitions are marked **PENDING_LEGAL_REVIEW**.
