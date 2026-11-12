# Self-hosted model on the existing Cloud Run service

This route bundles Ollama and Qwen3 4B weights into a private sidecar. It needs no external model API key. It uses paid Google Cloud resources and retains the application's existing Google sign-in and single-instance state storage.

## Build

Use the existing build identity and its authorized source bucket; the project default compute identity cannot push to the application registry.

```sh
gcloud builds submit . --project=trustops-uat \
  --gcs-source-staging-dir=gs://trustops-uat-taad-build/source \
  --config=infra/gcp/selfhost/cloudbuild.yaml --async
```

Wait for build SUCCESS. Both image digests must exist before deployment. Do not grant broader IAM roles to work around an incorrect build identity/bucket.

## Deploy without customer traffic

```sh
python scripts/deploy_selfhost_check.py --build-id BUILD_UUID --output /tmp/selfhost-plan.json
```

The helper reads the existing service and preserves its auth, service account, secrets, scanner, object store and state settings. It adds the model dependency and deploys the digest-pinned images with a `selfhost-check` tag, zero normal traffic, min zero/max one instance, concurrency one and a 900-second request timeout. The model container has 4 CPUs/12 GiB, in addition to the existing API/scanner resources. The model port is never the Cloud Run ingress.

Startup performs a real JSON request and a grounded synthetic document extraction. Inspect the new revision readiness and `MODEL_STARTUP_VERIFIED` log before accepting it. Startup failures are generic and do not log model output or customer text. Cold starts can take time on CPU. The deployment probe is not representative document/report UAT and does not exercise all payment agents.

## Acceptance and traffic

Use Google sign-in on the existing domain for customer UAT. Keep normal traffic on the previous ready revision until acceptance passes. A tagged revision and the current live revision must not both write the shared GCS state: the snapshot store is single-writer. Synthetic startup checks do not write it.

After acceptance, route 100% to the explicit verified revision with `gcloud run services update-traffic`, retaining its predecessor in the saved plan for rollback. Never expose the model port or bypass reviewer/publication gates for a demo. A real model does not create an ERP integration: the current connector remains `mock_sap`.


## Isolated real inference acceptance

Run `gcloud builds submit --project=trustops-uat --config=infra/gcp/selfhost/acceptance.cloudbuild.yaml --gcs-source-staging-dir=gs://trustops-uat-taad-build/source --async`.
This global build runs the pinned model with four CPU cores and 12 GiB in a private Docker network. It uses synthetic data only, without API credentials, customer state or publication. JSON readiness, document extraction, framework gaps, maturity, roadmap, HTML rendering and six payment recommendations must pass. Synthetic prompts/provider replies are explicitly logged for diagnosis; the production adapter never logs customer content. No artifact-bucket write permission is needed. The model calls use server-owned JSON schemas as decoding constraints, followed by the existing semantic and grounding validators.

For an API-only change, build `application.cloudbuild.yaml` and deploy with `--model-build-id` pointing at the earlier successful model build. The API build runs the backend suite and lint before producing an image. Browser acceptance remains a separate check.


Current UAT release: `trustops-ui-00050-mot` receives 100% traffic. After acceptance/cutover, service-level minimum was set to one warm instance without creating a new revision; this incurs idle resource charges. The build/deploy helper still defaults new test revisions to zero normal traffic. Existing Google OAuth redirects are configured for the public domain, so an anonymous tagged smoke check is not authenticated customer UAT. Keep an explicit prior revision and a private state backup for release recovery.


For static portal changes after a tested API build, `portal.cloudbuild.yaml` accepts `_BASE_IMAGE` as the completed API image's immutable digest and copies only `apps/portal-web`. It preserves that image's application, dependencies, non-root user and runtime settings. Run browser checks against the final portal sources before release; the reused API base must have passed backend tests/lint. This avoids rebuilding unchanged runtime dependencies for an asset correction.
