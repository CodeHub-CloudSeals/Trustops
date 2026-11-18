"""TrustTwin conversation layer (2026-11-16): small talk without a model, and optional AI phrasing over the exact
rule results (TRUSTOPS_ASSISTANT_MODEL=vertex). A fake model stands in for Gemini."""
import json
import socket
import time

import pytest
from app import app_integrations, assistant, llm
from app.main import STORE


@pytest.fixture()
def public_dns(monkeypatch):
    monkeypatch.setattr(app_integrations.socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, 1, 6, "", ("93.184.216.34", 443))])


class FakeModel:
    """Answers the two calls TrustTwin makes: `understand` (route) and `phrase` (write the reply)."""
    model_id = "fake-gemini"

    def __init__(self, route=None, phrase=None, route_error=None, phrase_error=None, delay=0.0):
        self.route, self.phrase = route, phrase
        self.route_error, self.phrase_error, self.delay = route_error, phrase_error, delay
        self.calls = []

    def complete(self, system, user, max_tokens=600):
        kind = "understand" if system == assistant.UNDERSTAND_SYSTEM else "phrase"
        self.calls.append((kind, json.loads(user)))
        if self.delay:
            time.sleep(self.delay)
        err = self.route_error if kind == "understand" else self.phrase_error
        if err:
            raise err
        out = self.route if kind == "understand" else self.phrase
        return out if isinstance(out, str) else json.dumps(out or {"intent": "unknown"})


@pytest.fixture()
def world(env, public_dns):
    """One item waiting for approval (EX-005, 500.00 USD) and one blocked agent action (FIN-02)."""
    c, h = env
    r = c.post("/v1/integrations", headers=h("admin@t-bank"), json={"name": "Recon app", "category": "Finance",
                                                                    "base_url": "https://app.example.com", "auth_type": "api_key",
                                                                    "api_key": "secret-value-123"})
    key = r.json()["trustops_key"]
    sent = c.post("/v1/decisions", headers={"X-TrustOps-Key": key}, json={
        "actor": {"type": "human", "id": "staff@firm.example"}, "action": "submit_for_review", "client": "client-a",
        "amount_minor": 50_000, "currency": "USD", "title": "Missing receipt EX-005", "facts": [{"label": "Bank line", "value": "500.00"}]}).json()
    c.post("/v1/decisions", headers={"X-TrustOps-Key": key},
           json={"actor": {"type": "agent", "id": "agent:recon"}, "action": "email_client", "client": "client-a"})

    def q(text, who="admin@t-bank"):
        r = c.post("/v1/assistant/ask", headers=h(who), json={"question": text})
        assert r.status_code == 200, r.text
        return r.json()
    return q, sent


def use(monkeypatch, model):
    monkeypatch.setattr(assistant, "model_client", lambda: model)


def test_small_talk_is_answered_without_a_model(world, monkeypatch):
    q, _ = world
    model = FakeModel()
    use(monkeypatch, model)
    for text in ("hi", "Hello there!", "hey", "good morning"):
        a = q(text)
        assert a["status"] == "SMALLTALK" and a["answer"].startswith("Hi! I'm TrustTwin")
        assert "Right now 1 item is waiting for approval." in a["answer"] and a["suggestions"]
    for text, start in (("thanks", "You're welcome"), ("Thank you!", "You're welcome"), ("bye", "Bye for now"),
                        ("help", "I'm TrustTwin"), ("what can you do?", "I'm TrustTwin"), ("who are you", "I'm TrustTwin")):
        a = q(text)
        assert a["status"] == "SMALLTALK" and a["answer"].startswith(start), (text, a["answer"])
        assert a["written_by"] == "rules" and a["model"] == "deterministic"
    assert model.calls == []                      # small talk never reaches the model


def test_greeting_in_front_of_a_question_still_answers_it(world, monkeypatch):
    q, sent = world
    use(monkeypatch, None)
    a = q("hi, what is waiting for approval?")
    assert a["status"] == "ANSWERED" and a["answer"].startswith("1 item is waiting") and a["citations"][0]["ref"] == sent["decision_id"]


def test_no_match_is_friendlier(world, monkeypatch):
    q, _ = world
    use(monkeypatch, None)
    a = q("what's the weather")
    assert a["status"] == "NO_MATCH" and a["answer"].startswith("I'm not sure what you mean yet") and len(a["suggestions"]) == 6


def test_model_routes_a_paraphrase_and_phrases_the_exact_facts(world, monkeypatch):
    q, sent = world
    model = FakeModel(route={"intent": "pending", "params": {"span": None}},
                      phrase={"answer": "One item is still waiting for a person: Missing receipt EX-005 from Recon app."})
    use(monkeypatch, model)
    a = q("anything stuck?")
    assert a["written_by"] == "ai" and a["model"] == "vertex:fake-gemini"
    assert a["answer"] == "One item is still waiting for a person: Missing receipt EX-005 from Recon app."
    # the rows and citations are the rules' own, exactly as for the typed question
    assert a["rows"][0][0] == "Missing receipt EX-005" and a["citations"][0]["ref"] == sent["decision_id"]
    assert [k for k, _ in model.calls] == ["understand", "phrase"]
    understand = model.calls[0][1]
    assert understand["question"] == "anything stuck?" and "pending" in understand["intents"] and "records" not in understand
    facts = model.calls[1][1]["facts"]
    assert facts["rows"][0][0] == "Missing receipt EX-005"
    last = [e for e in STORE.audit if e["action"] == "assistant.ask"][-1]
    assert last["detail"] == {"written_by": "ai", "model": "vertex:fake-gemini"} and "anything stuck" not in json.dumps(last)


def test_model_span_is_applied_by_the_rules(world, monkeypatch):
    q, _ = world
    use(monkeypatch, FakeModel(route={"intent": "blocked", "params": {"span": "today"}}, phrase={"answer": "One action was blocked today."}))
    a = q("did anything get stopped earlier on?")
    assert a["status"] == "ANSWERED" and a["written_by"] == "ai" and a["rows"][0][3] == "FIN-02"


def test_invented_numbers_or_ids_are_rejected_for_the_rules_text(world, monkeypatch):
    q, _ = world
    for bad in ("3 items are waiting.", "One item is waiting: EX-999.", "One item from boss@evil.example is waiting.",
                "Waiting under FIN-77.", "One item worth 900.00 USD is waiting."):
        use(monkeypatch, FakeModel(route={"intent": "pending", "params": {}}, phrase={"answer": bad}))
        a = q("anything stuck?")
        assert a["written_by"] == "rules" and a["answer"].startswith("1 item is waiting"), bad


def test_invalid_intents_and_invented_ids_are_ignored(world, monkeypatch):
    q, _ = world
    model = FakeModel(route={"intent": "delete_everything", "params": {}}, phrase={"answer": "One action was blocked."})
    use(monkeypatch, model)
    a = q("what was blocked today?")                  # the rules read the original question
    assert a["status"] == "ANSWERED" and a["rows"][0][3] == "FIN-02"
    model = FakeModel(route={"intent": "decision", "params": {"decision_id": "dec_0123456789ab"}})
    use(monkeypatch, model)
    a = q("tell me something interesting")            # an id that is not in the question is never used
    assert a["status"] == "NO_MATCH" and a["written_by"] == "rules"
    use(monkeypatch, FakeModel(route={"intent": "policy", "params": {"policy_id": "FIN-99"}}))
    assert q("what about FIN-99 then")["status"] == "NO_MATCH"     # not a policy in this workspace
    use(monkeypatch, FakeModel(route="not json at all"))
    assert q("what was blocked today?")["rows"][0][3] == "FIN-02"


def test_model_failures_and_timeouts_fall_back_to_the_rules(world, monkeypatch, capsys):
    q, _ = world
    use(monkeypatch, FakeModel(route_error=RuntimeError("quota"), phrase_error=ConnectionError("down")))
    a = q("what is waiting for approval?")
    assert a["answer"].startswith("1 item is waiting") and a["written_by"] == "rules" and a["model"] == "vertex:fake-gemini"
    logged = capsys.readouterr().out
    assert "TRUSTTWIN_MODEL_FALLBACK" in logged and "RuntimeError" in logged and "waiting for approval" not in logged
    monkeypatch.setattr(assistant, "BUDGET_SECONDS", 0.4)
    use(monkeypatch, FakeModel(route={"intent": "pending", "params": {}}, phrase={"answer": "One item."}, delay=1.0))
    t0 = time.monotonic()
    a = q("anything stuck?")
    assert time.monotonic() - t0 < 1.0                # the budget holds even when the model hangs
    assert a["written_by"] == "rules"


def test_requests_to_act_are_refused_without_asking_the_model(world, monkeypatch):
    q, sent = world
    model = FakeModel(route={"intent": "pending", "params": {}}, phrase={"answer": "Done, I approved it."})
    use(monkeypatch, model)
    for text in (f"approve {sent['decision_id']}", "hi, approve it", "please disable FIN-04", "Reject everything"):
        a = q(text, who="controller@t-bank")
        assert a["status"] == "REFUSED" and a["written_by"] == "rules", text
    assert model.calls == []
    assert q(f"explain {sent['decision_id']}")["answer"]           # still answerable afterwards


def test_exact_ids_are_read_by_the_rules_and_only_rephrased(world, monkeypatch):
    q, sent = world
    model = FakeModel(phrase={"answer": f"{sent['decision_id']} is still waiting for an approver under FIN-00."})
    use(monkeypatch, model)
    a = q(f"what happened with {sent['decision_id']}?")
    assert [k for k, _ in model.calls] == ["phrase"]      # no routing needed for an exact id
    assert a["written_by"] == "ai" and a["citations"][0]["ref"] == sent["decision_id"]


def test_model_small_talk_route(world, monkeypatch):
    q, _ = world
    use(monkeypatch, FakeModel(route={"intent": "smalltalk", "params": {}}))
    a = q("how's your day going")
    assert a["status"] == "SMALLTALK" and a["answer"].startswith("Hi! I'm TrustTwin")


def test_switch_is_separate_from_the_other_model_settings(monkeypatch):
    monkeypatch.setattr(assistant, "_client_cache", {"client": None, "failed_at": 0.0})
    monkeypatch.delenv("TRUSTOPS_ASSISTANT_MODEL", raising=False)
    monkeypatch.setenv("TAAD_LLM_PROVIDER", "vertex")
    assert assistant.model_client() is None                 # the assessment provider does not switch TrustTwin on
    monkeypatch.delenv("TAAD_LLM_PROVIDER", raising=False)
    monkeypatch.setenv("TRUSTOPS_ASSISTANT_MODEL", "vertex")
    assert llm.provider() == "" and llm.vertex_client() is None   # and TrustTwin's switch does not turn the agents on
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    assert assistant.model_client() is None                 # a broken set-up means "no model", not an error
    assert assistant._client_cache["failed_at"] > 0


def test_without_the_switch_answers_are_the_rules_answers(world, monkeypatch):
    q, _ = world
    monkeypatch.delenv("TRUSTOPS_ASSISTANT_MODEL", raising=False)
    monkeypatch.setattr(assistant, "_client_cache", {"client": None, "failed_at": 0.0})
    for text in ("What is waiting for approval?", "what was blocked today?", "Give me a summary"):
        a = q(text)
        assert a["model"] == "deterministic" and a["written_by"] == "rules"


def test_grounding_check():
    src = json.dumps({"summary": "2 items are waiting; 1,250.50 USD; dec_0123456789ab under FIN-04 for EX-003 by a@b.example",
                      "rows": [["13 Nov 07:19"]]})
    assert assistant.grounded("Two items are waiting, worth 1250.50 USD in total.", src)     # same figure, written differently
    assert assistant.grounded("2 items are waiting, one worth 1,250.50 USD (EX-003, FIN-04).", src)
    assert not assistant.grounded("3 items are waiting.", json.dumps({"summary": "EX-003 is waiting"}))   # digits in ids don't count
    assert not assistant.grounded("Raised on 2026-11-17.", json.dumps({"summary": "Raised on 2026-11-16"}))
    assert assistant.grounded("dec_0123456789ab was raised by a@b.example on 13 Nov at 07:19.", src)
    assert not assistant.grounded("3 items are waiting.", src)
    assert not assistant.grounded("See EX-004.", src)
    assert not assistant.grounded("Ask c@d.example.", src)
    assert not assistant.grounded("dec_ffffffffffff is related.", src)
