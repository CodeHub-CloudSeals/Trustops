#!/usr/bin/env bash
# One-shot GCP provisioning + build + deploy for TrustOps (Cloud Run + GCS + Vertex AI + Cloud KMS).
# Safe to re-run: existing resources are reused.
#
# Google sign-in (default):
#   export PROJECT_ID=trustops-uat REGION=europe-west1
#   export GOOGLE_CLIENT_ID=...apps.googleusercontent.com GOOGLE_SECRET=trustops-google-client-secret   # Secret Manager secret name
#   export FIRST_ADMIN_EMAIL=you@cloudseals.co.uk
#   ./infra/gcp/setup.sh
# Another OIDC provider: AUTH_PROVIDER=oidc plus OIDC_ISSUER OIDC_JWKS_URL OIDC_AUDIENCE OIDC_CLIENT_ID OIDC_AUTHORIZE_URL OIDC_TOKEN_URL OIDC_LOGOUT_URL
set -euo pipefail

: "${PROJECT_ID:?}"
REGION="${REGION:-europe-west1}"
APP_ENV="${APP_ENV:-dev}"
AUTH_PROVIDER="${AUTH_PROVIDER:-google}"
SERVICE="${SERVICE:-taad-api}"
REPO="${REPO:-taad}"
LLM_PROVIDER="${LLM_PROVIDER-vertex}"
CLAMAV="${CLAMAV:-false}"   # true = ClamAV sidecar scans every upload (adds ~4 GiB / 2 vCPU to the instance)
STAFF_EMAIL_DOMAINS="${STAFF_EMAIL_DOMAINS-cloudseals.co.uk;cloudseals.com}"   # email domains allowed to hold CloudSeals roles (";" separated)
VERTEX_MODEL="${VERTEX_MODEL:-gemini-2.5-flash}"
VERTEX_LOCATION="${VERTEX_LOCATION:-$REGION}"
KMS_KEYRING="${KMS_KEYRING:-taad}"
KMS_KEY="${KMS_KEY:-evidence-signing}"
RUN_SA="taad-run"
BUILD_SA="taad-build"
BUCKET="${BUCKET:-${PROJECT_ID}-taad-evidence}"
BUILD_BUCKET="${BUILD_BUCKET:-${PROJECT_ID}-taad-build}"
STATE_BUCKET="${STATE_BUCKET:-${PROJECT_ID}-taad-state}"
GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID:-}"; GOOGLE_SECRET="${GOOGLE_SECRET:-}"; FIRST_ADMIN_EMAIL="${FIRST_ADMIN_EMAIL:-}"
if [ "$AUTH_PROVIDER" = "google" ]; then
  : "${GOOGLE_CLIENT_ID:?set GOOGLE_CLIENT_ID}" "${GOOGLE_SECRET:?set GOOGLE_SECRET (Secret Manager secret name of the OAuth client secret)}"
else
  : "${OIDC_ISSUER:?}" "${OIDC_JWKS_URL:?}" "${OIDC_AUDIENCE:?}" "${OIDC_CLIENT_ID:?}" "${OIDC_AUTHORIZE_URL:?}" "${OIDC_TOKEN_URL:?}" "${OIDC_LOGOUT_URL:?}"
fi
cd "$(dirname "$0")/../.."

gcloud config set project "$PROJECT_ID" >/dev/null
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
SERVICE_URL="https://${SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"
# PUBLIC_URL=https://trustops.example.com serves the portal (and the OAuth redirect) from your own domain once it is mapped to the service.
PUBLIC_URL="${PUBLIC_URL:-$SERVICE_URL}"
# REDIRECT_PATH=/api/auth/callback/google reuses a callback path already registered on the OAuth client (the previous UI used it).
REDIRECT_PATH="${REDIRECT_PATH:-/portal/}"
REDIRECT_URI="${PUBLIC_URL%/}${REDIRECT_PATH}"
echo ">> Add this authorised redirect URI to your OAuth client / identity provider: ${REDIRECT_URI}"

echo ">> Enabling APIs"
gcloud services enable run.googleapis.com sqladmin.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com \
  secretmanager.googleapis.com storage.googleapis.com iam.googleapis.com logging.googleapis.com aiplatform.googleapis.com cloudkms.googleapis.com

echo ">> Service accounts"
for sa in "$RUN_SA" "$BUILD_SA"; do
  gcloud iam service-accounts describe "${sa}@${PROJECT_ID}.iam.gserviceaccount.com" >/dev/null 2>&1 \
    || gcloud iam service-accounts create "$sa" --display-name "TAAD ${sa}"
done
RUN_SA_EMAIL="${RUN_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
BUILD_SA_EMAIL="${BUILD_SA}@${PROJECT_ID}.iam.gserviceaccount.com"

echo ">> Artifact Registry"
gcloud artifacts repositories describe "$REPO" --location "$REGION" >/dev/null 2>&1 \
  || gcloud artifacts repositories create "$REPO" --repository-format=docker --location "$REGION" --description "TAAD images"

echo ">> Evidence bucket (private, versioned) and build staging bucket"
gcloud storage buckets describe "gs://${BUCKET}" >/dev/null 2>&1 \
  || gcloud storage buckets create "gs://${BUCKET}" --location "$REGION" --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets update "gs://${BUCKET}" --versioning >/dev/null
gcloud storage buckets describe "gs://${BUILD_BUCKET}" >/dev/null 2>&1 \
  || gcloud storage buckets create "gs://${BUILD_BUCKET}" --location "$REGION" --uniform-bucket-level-access --public-access-prevention

echo ">> Application state bucket (single JSON snapshot, optimistic locking, object versioning, 30-day history)"
gcloud storage buckets describe "gs://${STATE_BUCKET}" >/dev/null 2>&1 \
  || gcloud storage buckets create "gs://${STATE_BUCKET}" --location "$REGION" --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets update "gs://${STATE_BUCKET}" --versioning >/dev/null
printf '{"rule":[{"action":{"type":"Delete"},"condition":{"daysSinceNoncurrentTime":30,"isLive":false}}]}' > "${TMPDIR:-/tmp}/taad-lifecycle.json"
gcloud storage buckets update "gs://${STATE_BUCKET}" --lifecycle-file="${TMPDIR:-/tmp}/taad-lifecycle.json" >/dev/null

echo ">> Cloud KMS signing key (EC P-256; key material never leaves KMS)"
gcloud kms keyrings describe "$KMS_KEYRING" --location "$REGION" >/dev/null 2>&1 || gcloud kms keyrings create "$KMS_KEYRING" --location "$REGION"
gcloud kms keys describe "$KMS_KEY" --keyring "$KMS_KEYRING" --location "$REGION" >/dev/null 2>&1 \
  || gcloud kms keys create "$KMS_KEY" --keyring "$KMS_KEYRING" --location "$REGION" --purpose asymmetric-signing --default-algorithm ec-sign-p256-sha256
KMS_KEY_VERSION="projects/${PROJECT_ID}/locations/${REGION}/keyRings/${KMS_KEYRING}/cryptoKeys/${KMS_KEY}/cryptoKeyVersions/1"

echo ">> IAM (least privilege)"
bind() { gcloud projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:$1" --role "$2" --condition=None >/dev/null; }
bind "$RUN_SA_EMAIL" roles/aiplatform.user
bind "$BUILD_SA_EMAIL" roles/run.admin
bind "$BUILD_SA_EMAIL" roles/logging.logWriter
[ -n "$GOOGLE_SECRET" ] && gcloud secrets add-iam-policy-binding "$GOOGLE_SECRET" --member "serviceAccount:${RUN_SA_EMAIL}" --role roles/secretmanager.secretAccessor >/dev/null
for b in "$BUCKET" "$STATE_BUCKET"; do
  gcloud storage buckets add-iam-policy-binding "gs://${b}" --member "serviceAccount:${RUN_SA_EMAIL}" --role roles/storage.objectUser >/dev/null
done
gcloud kms keys add-iam-policy-binding "$KMS_KEY" --keyring "$KMS_KEYRING" --location "$REGION" \
  --member "serviceAccount:${RUN_SA_EMAIL}" --role roles/cloudkms.signerVerifier >/dev/null
gcloud artifacts repositories add-iam-policy-binding "$REPO" --location "$REGION" --member "serviceAccount:${BUILD_SA_EMAIL}" --role roles/artifactregistry.writer >/dev/null
gcloud storage buckets add-iam-policy-binding "gs://${BUILD_BUCKET}" --member "serviceAccount:${BUILD_SA_EMAIL}" --role roles/storage.objectViewer >/dev/null
gcloud iam service-accounts add-iam-policy-binding "$RUN_SA_EMAIL" --member "serviceAccount:${BUILD_SA_EMAIL}" --role roles/iam.serviceAccountUser >/dev/null

echo ">> Cloud Build: test, build, push, deploy, smoke test"
SUBS="_REGION=${REGION},_REPO=${REPO},_SERVICE=${SERVICE},_ENV=${APP_ENV},_RUNTIME_SA=${RUN_SA},_BUCKET=${BUCKET},_STATE_BUCKET=${STATE_BUCKET},_AUTH_PROVIDER=${AUTH_PROVIDER},_PORTAL_REDIRECT_URI=${REDIRECT_URI},_LLM_PROVIDER=${LLM_PROVIDER},_VERTEX_MODEL=${VERTEX_MODEL},_VERTEX_LOCATION=${VERTEX_LOCATION},_KMS_KEY_VERSION=${KMS_KEY_VERSION},_GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID},_GOOGLE_SECRET=${GOOGLE_SECRET},_FIRST_ADMIN_EMAIL=${FIRST_ADMIN_EMAIL},_STAFF_EMAIL_DOMAINS=${STAFF_EMAIL_DOMAINS},_CLAMAV=${CLAMAV}"
if [ "$AUTH_PROVIDER" != "google" ]; then
  SUBS="${SUBS},_OIDC_ISSUER=${OIDC_ISSUER},_OIDC_JWKS_URL=${OIDC_JWKS_URL},_OIDC_AUDIENCE=${OIDC_AUDIENCE},_PORTAL_AUTHORIZE_URL=${OIDC_AUTHORIZE_URL},_PORTAL_TOKEN_URL=${OIDC_TOKEN_URL},_PORTAL_LOGOUT_URL=${OIDC_LOGOUT_URL},_PORTAL_CLIENT_ID=${OIDC_CLIENT_ID}"
fi
gcloud builds submit . --config cloudbuild.yaml \
  --service-account "projects/${PROJECT_ID}/serviceAccounts/${BUILD_SA_EMAIL}" \
  --gcs-source-staging-dir "gs://${BUILD_BUCKET}/source" \
  --substitutions "$SUBS"

echo
echo "Deployed: ${PUBLIC_URL%/}/portal/   (Cloud Run URL: ${SERVICE_URL}/portal/)"
