#!/usr/bin/env bash
# One-time: grant the first CloudSeals admin role to a verified OIDC subject (works only in TAAD_ENV=dev, with the database configured).
#   PROJECT_ID=my-project ./infra/gcp/bootstrap-admin.sh <oidc-sub-of-first-admin>
set -euo pipefail
: "${PROJECT_ID:?}"
SUB="${1:?usage: bootstrap-admin.sh <oidc-sub>}"
REGION="${REGION:-europe-west2}"; SERVICE="${SERVICE:-taad-api}"; REPO="${REPO:-taad}"
SQL_INSTANCE="${SQL_INSTANCE:-taad-db}"; DB_SECRET="${DB_SECRET:-taad-database-url}"
JOB="taad-bootstrap-admin"
# Reuse the running service's image and environment so the job sees exactly the same configuration.
IMAGE="$(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(spec.template.spec.containers[0].image)')"
ENVS="$(gcloud run services describe "$SERVICE" --region "$REGION" --format=json | python3 -c "
import json,sys
env=json.load(sys.stdin)['spec']['template']['spec']['containers'][0].get('env',[])
print(','.join(f\"{e['name']}={e['value']}\" for e in env if 'value' in e))")"
gcloud run jobs deploy "$JOB" --region "$REGION" --image "$IMAGE" \
  --service-account "taad-run@${PROJECT_ID}.iam.gserviceaccount.com" \
  --set-cloudsql-instances "${PROJECT_ID}:${REGION}:${SQL_INSTANCE}" \
  --set-secrets "TAAD_DATABASE_URL=${DB_SECRET}:latest" \
  --set-env-vars "${ENVS}" \
  --command python --args=-m,app.admin_bootstrap,--sub,"${SUB}" --max-retries 0
gcloud run jobs execute "$JOB" --region "$REGION" --wait
echo "First CloudSeals admin created for subject ${SUB}."
