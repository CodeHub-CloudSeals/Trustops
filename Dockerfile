FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/packages/question-engine:/app/packages/reporting:/app/apps/assessment-api \
    TAAD_ENV=prod TAAD_AUTH_MODE=oidc PORT=8000
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --no-create-home taad
COPY packages packages
COPY apps apps
COPY packs packs
# Every file the API reads at import time (see ROOT / "..." in apps/assessment-api/app); tests/test_container_layout.py enforces this.
COPY taad_question_control_registry_v1.0.0.json taad_catalog_sha256.txt taad_swaska_agent_manifest_v1.json \
     taad_agent_manifests_v1.json taad_integration_contracts_v1.json ./
# The portal config is served by the API from environment variables (OIDC endpoints), not baked into the image.
USER 10001
EXPOSE 8000
# Cloud Run / ECS inject PORT; default 8000 for local `docker run`.
HEALTHCHECK CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/health')"
CMD ["sh", "-c", "exec uvicorn app.main:app --app-dir apps/assessment-api --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*' --no-server-header"]
