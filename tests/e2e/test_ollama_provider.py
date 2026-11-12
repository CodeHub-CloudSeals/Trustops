import json

import pytest
from app import llm, swaska, trustops_runtime

from tests.e2e.test_openai_provider import Transport


def reply(text='{"ok":true}', **changes):
    return {'done': True, 'done_reason': 'stop', 'message': {'content': text}, **changes}


def test_selfhost_sends_private_bounded_json_request_without_cloud_auth():
    wire = Transport(reply())
    client = llm.OllamaModelClient(opener=wire)
    assert json.loads(client.complete('Use evidence only.', 'Synthetic register', max_tokens=321)) == {'ok': True}
    request = wire.request
    body = json.loads(request.data)
    assert request.full_url == 'http://127.0.0.1:11434/api/chat'
    assert not request.has_header('Authorization')
    assert body['model'] == 'qwen3:4b' and body['think'] is False
    assert body['stream'] is False and body['format'] == 'json'
    assert body['options']['num_predict'] == 321 and body['options']['num_ctx'] == 32768
    assert 'tools' not in body and wire.timeout == 240


@pytest.mark.parametrize('result', [reply('not JSON'), reply('[]'), reply(done=False), reply(done_reason='length'),
                                    reply(message={'content': '{"ok":true}', 'tool_calls': [{'name': 'execute'}]})])
def test_selfhost_rejects_incomplete_invalid_and_tool_outputs(result):
    client = llm.OllamaModelClient(opener=Transport(result))
    with pytest.raises(ValueError):
        client.complete('JSON only.', 'test')


@pytest.mark.parametrize('url', ['https://example.com', 'http://169.254.169.254', 'http://127.0.0.1:11434/other',
                                  'http://user:password@localhost:11434', 'http://localhost:11434?url=external'])
def test_selfhost_is_not_an_outbound_proxy(url):
    with pytest.raises(ValueError, match='private'):
        llm.OllamaModelClient(base_url=url)


def test_selfhost_cannot_select_cloud_models():
    with pytest.raises(ValueError, match='cloud model'):
        llm.OllamaModelClient(model_id='qwen3:cloud')


def test_selfhost_routes_both_agent_families_and_metadata(monkeypatch):
    client = object()
    monkeypatch.setenv('TAAD_LLM_PROVIDER', 'ollama')
    monkeypatch.setattr(llm, 'OllamaModelClient', lambda: client)
    assert swaska.default_client() is client
    assert trustops_runtime.configured_model_client() is client
    assert llm.configured_model_id() == 'qwen3:4b'


@pytest.mark.parametrize('name,mode', [('OllamaModelClient', 'ollama'), ('OpenAIModelClient', 'openai'),
                                     ('VertexModelClient', 'vertex')])
def test_completed_run_records_actual_provider(name, mode):
    from tests.e2e.test_trustops_runtime import AgentModelStub, request_body
    client = type(name, (AgentModelStub,), {})()
    body = request_body()
    run = trustops_runtime.run_agents('tenant', 'actor', **body, client=client)
    assert run['agent_mode'] == mode


def test_selfhost_uses_server_owned_schema_without_changing_grounding_checks():
    from app import model_schemas, use_cases
    wire = Transport(reply('{"use_cases":[]}'))
    client = llm.OllamaModelClient(opener=wire)
    result = use_cases.run_inventory(client, [{'evidence_id': 'synthetic-e1', 'filename': 'register.txt',
                                             'text': 'Our chatbot answers account FAQs.'}])
    assert result['items'] == []
    body = json.loads(wire.request.data)
    assert body['format'] == model_schemas.INVENTORY
    assert 'Required output schema:' in body['messages'][0]['content']

    fabricated = {'name': 'Account bot', 'description': 'Answers account questions.', 'business_owner': None,
                  'technical_owner': None, 'model_type': None, 'foundation_models_used': [], 'decision_authority': 'advisory',
                  'data_sources': [], 'risk_tier': 'limited_risk', 'risk_tier_rationale': 'Customer-facing bot.',
                  'extraction_confidence': 0.9, 'source_quotes': ['The bank has verified all controls.']}
    bad = llm.OllamaModelClient(opener=Transport(reply(json.dumps({'use_cases': [fabricated]}))))
    result = use_cases.run_inventory(bad, [{'evidence_id': 'synthetic-e1', 'filename': 'register.txt',
                                         'text': 'Our chatbot answers account FAQs.'}])
    assert result['items'] == [] and result['rejected'] == 1
