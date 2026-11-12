import json

from app import main, trustops_runtime

from tests.e2e.test_trustops_runtime import AgentModelStub, request_body

PATH = '/v1/workflows/ledgersight.ar_cash/runs/stream'


def events(response):
    assert response.status_code == 200, response.text
    assert response.headers['content-type'].startswith('text/event-stream')
    return [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith('data: ')]


def test_stream_reports_actual_worker_boundaries_then_saved_run(env):
    c, h = env
    data = events(c.post(PATH, headers=h('admin@t-bank', **{'Idempotency-Key': 'stream'}), json=request_body()))
    steps = data[:-1]
    assert len(steps) == 12
    for started, finished in zip(steps[::2], steps[1::2]):
        assert started['event'] == 'agent.started' and finished['event'] == 'agent.completed'
        assert started['agent_id'] == finished['agent_id'] == finished['step']['agent_id']
        assert started['at'] <= finished['at']
    final = data[-1]
    assert final['event'] == 'run.completed'
    run = final['run']
    assert run['policy_decision']['decision'] == 'ALLOW' and run['execution'] is None
    assert c.get('/v1/runs/' + run['run_id'], headers=h('admin@t-bank')).status_code == 200
    assert c.get('/v1/runs/' + run['run_id'], headers=h('admin@t-health')).status_code == 404
    replay = events(c.post(PATH, headers=h('admin@t-bank', **{'Idempotency-Key': 'stream'}), json=request_body()))
    assert len(replay) == 1 and replay[0]['run']['run_id'] == run['run_id']
    assert len(main.STORE.workflow_runs) == 1


def test_stream_preserves_approval_gate_and_role_permissions(env):
    c, h = env
    body = request_body(amount=150000)
    assert c.post(PATH, headers=h('contrib@t-bank', **{'Idempotency-Key': 'no'}), json=body).status_code == 403
    assert c.post(PATH, headers=h('admin@t-bank'), json=body).status_code == 400
    run = events(c.post(PATH, headers=h('admin@t-bank', **{'Idempotency-Key': 'high'}), json=body))[-1]['run']
    assert run['status'] == 'approval_required' and run['policy_decision']['approval_required']
    assert run['prepared_action'] is None and run['execution'] is None


def test_stream_model_failures_do_not_claim_completion_or_create_run(env, monkeypatch):
    c, h = env
    monkeypatch.setattr(trustops_runtime, 'configured_model_client', lambda: AgentModelStub(broken=True))
    data = events(c.post(PATH, headers=h('admin@t-bank', **{'Idempotency-Key': 'bad'}), json=request_body()))
    assert data[0]['event'] == 'agent.started'
    assert data[-1]['event'] == 'run.failed'
    assert not any(e['event'] == 'run.completed' for e in data)
    assert main.STORE.workflow_runs == {}


def test_configured_workers_emit_after_each_validated_response(env, monkeypatch):
    c, h = env
    model = AgentModelStub()
    monkeypatch.setattr(trustops_runtime, 'configured_model_client', lambda: model)
    data = events(c.post(PATH, headers=h('admin@t-bank', **{'Idempotency-Key': 'model'}), json=request_body()))
    assert len(model.calls) == 6
    completed = [e for e in data if e['event'] == 'agent.completed']
    assert [e['agent_id'] for e in completed] == model.calls
    assert all(e['step']['recommendation'] for e in completed)
    assert data[-1]['run']['agent_mode'] == 'bedrock'


def test_stream_persists_in_worker_without_buffering_middleware(env, monkeypatch):
    c, h = env
    saved = []
    monkeypatch.setattr(main.persist, 'enabled', lambda: True)
    monkeypatch.setattr(main.persist, 'save', lambda store: saved.append(len(store.workflow_runs)))
    data = events(c.post(PATH, headers=h('admin@t-bank', **{'Idempotency-Key': 'persist'}), json=request_body()))
    assert data[-1]['event'] == 'run.completed'
    assert saved == [1]
