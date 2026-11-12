# Use the exact serving application image; do not replace it with a divergent repo.
FROM us-east4-docker.pkg.dev/trustops-uat/cloud-run-source-deploy/ledgersight@sha256:32f4411685b80de135a34f49c385b1f1e9043e9e8a2c00bca2f7b7a00aed5d8e
COPY integrations/ledgersight/document_gate.py /trustops-gate/document_gate.py
COPY integrations/ledgersight/gated_app.py /trustops-gate/gated_app.py
ENV PYTHONPATH=/trustops-gate
CMD ["sh", "-c", "exec python -m uvicorn gated_app:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1"]
