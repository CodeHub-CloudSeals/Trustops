import pytest
from app.main import REG, STORE, app
from app.seed import seed
from fastapi.testclient import TestClient

BANK = {"Q-BASE-002": "banking", "Q-BASE-005": "Agentic AI", "Q-BASE-006": "Yes", "Q-BASE-007": "Unknown",
        "Q-IAM-002": "Yes", "Q-HIT-015": "No", "Q-AIA-017": "No"}


@pytest.fixture()
def env():
    for name in vars(STORE):
        v = getattr(STORE, name)
        if hasattr(v, "clear"):
            v.clear()
    tokens = seed()
    c = TestClient(app)

    def h(sub, **extra):
        return {"Authorization": f"Bearer {tokens[sub]}", **extra}
    return c, h


def fill_required(c, h, sub, aid, overrides):
    """Answer every required org-scope question: overrides first, then first valid option / text."""
    for q in REG.questions.values():
        if q["scope"] != "org" or q["required"] != "yes":
            continue
        qid = q["question_id"]
        if qid in overrides:
            val = overrides[qid]
        elif q["response_type"] == "select_one":
            val = REG.option_sets[q["option_set"]][0]
        elif q["response_type"] == "select_multi":
            val = [REG.option_sets[q["option_set"]][0]]
        elif q["response_type"] == "number":
            val = 1
        else:
            val = "x"
        put(c, h, sub, aid, qid, val)
    for qid, val in overrides.items():
        put(c, h, sub, aid, qid, val)


def put(c, h, sub, aid, qid, val, scope="org", status="answered"):
    cur = c.get(f"/v1/assessments/{aid}/questions", params={"scope_id": scope}, headers=h(sub))
    assert cur.status_code == 200
    from app.main import STORE
    ex = STORE.answers.get((aid, scope, qid))
    r = c.put(f"/v1/assessments/{aid}/answers/{qid}", headers=h(sub, **{"If-Match": ex["etag"] if ex else "0"}),
              json={"scope_id": scope, "value": val, "answer_status": status})
    assert r.status_code == 200, r.text
    return r


def new_assessment(c, h, sub, key="k1", industry="banking"):
    r = c.post("/v1/assessments", headers=h(sub, **{"Idempotency-Key": key}),
               json={"ai_system_name": "Payments agent", "industry": industry, "questionnaire_version": "1.0.0"})
    assert r.status_code == 201, r.text
    return r.json()["assessment_id"]
