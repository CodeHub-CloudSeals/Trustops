PY=.venv/bin/python
export PYTHONPATH=packages/question-engine:packages/reporting:apps/assessment-api:.

.PHONY: dev test browser lint typecheck build
dev:       ; $(PY) -m uvicorn app.main:app --app-dir apps/assessment-api --reload --port 8000
test:      ; $(PY) -m pytest -q --ignore=tests/browser
browser:   ; $(PY) -m pytest -q tests/browser
lint:      ; .venv/bin/ruff check .
typecheck: ; .venv/bin/mypy --ignore-missing-imports packages/question-engine/question_engine packages/reporting/reporting
build:     lint typecheck test ; $(PY) validate_registry.py

.PHONY: image
image:     ; docker build -t trustops:local .

.PHONY: openapi
openapi:   ; $(PY) -c "import json;from app.main import app;print(json.dumps(app.openapi(),indent=1))" > docs/openapi.generated.json
