import io
import json
from urllib.error import HTTPError

import pytest
from app import llm, swaska, trustops_runtime


class Transport:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request, self.timeout = request, timeout
        if isinstance(self.response, Exception):
            raise self.response
        return io.BytesIO(json.dumps(self.response).encode())


def completed(text='{"ok":true}'):
    return {'status': 'completed', 'output': [{'type': 'message', 'content': [{'type': 'output_text', 'text': text}]}]}


def test_openai_adapter_sends_only_bounded_text_with_no_tools_or_response_storage():
    wire = Transport(completed())
    client = llm.OpenAIModelClient(api_key='test-key-not-a-real-credential', opener=wire)
    assert json.loads(client.complete('Use evidence only.', 'Synthetic connection check.', max_tokens=321)) == {'ok': True}
    body = json.loads(wire.request.data)
    assert wire.request.full_url == 'https://api.openai.com/v1/responses'
    assert wire.timeout == 60
    assert body['model'] == 'gpt-6-luna' and body['reasoning'] == {'effort': 'none'}
    assert body['max_output_tokens'] == 321 and body['store'] is False
    assert body['text']['format']['type'] == 'json_object' and 'JSON' in body['instructions']
    assert 'tools' not in body and 'test-key' not in wire.request.data.decode()


@pytest.mark.parametrize('response', [
    {'status': 'incomplete', 'output': completed()['output']},
    {'status': 'failed', 'output': []}, completed('not json'), completed('[]'),
    {'status': 'completed', 'output': [{'type': 'message', 'content': [{'type': 'refusal', 'refusal': 'Declined'}]}]},
])
def test_incomplete_invalid_or_refused_openai_output_is_not_accepted(response):
    client = llm.OpenAIModelClient(api_key='test-only', opener=Transport(response))
    with pytest.raises(ValueError):
        client.complete('Return JSON.', 'test')


def test_auth_failure_never_exposes_provider_response_or_credentials():
    failure = HTTPError('https://api.openai.com/v1/responses', 401, 'server-private-message', {}, io.BytesIO(b'private-response'))
    client = llm.OpenAIModelClient(api_key='secret-for-test', opener=Transport(failure))
    with pytest.raises(RuntimeError) as caught:
        client.complete('Return JSON.', 'test')
    assert '401' in str(caught.value)
    assert all(value not in str(caught.value) for value in ('secret-for-test', 'private-response', 'server-private-message'))


def test_openai_secret_file_and_missing_or_multiline_key(monkeypatch, tmp_path):
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    monkeypatch.delenv('OPENAI_API_KEY_FILE', raising=False)
    with pytest.raises(ValueError, match='server-side'):
        llm.OpenAIModelClient()
    file = tmp_path / 'secret'
    file.write_text('local-test-key\n')
    monkeypatch.setenv('OPENAI_API_KEY_FILE', str(file))
    wire = Transport(completed())
    llm.OpenAIModelClient(opener=wire).complete('Return JSON.', 'test')
    assert wire.request.get_header('Authorization') == 'Bearer local-test-key'
    file.write_text('invalid\nheader')
    with pytest.raises(ValueError, match='server-side'):
        llm.OpenAIModelClient()


def test_openai_selection_routes_document_and_payment_agents_and_metadata(monkeypatch):
    client = object()
    monkeypatch.setenv('TAAD_LLM_PROVIDER', 'openai')
    monkeypatch.setenv('TAAD_OPENAI_MODEL', 'approved-model')
    monkeypatch.setattr(llm, 'OpenAIModelClient', lambda: client)
    assert swaska.default_client() is client
    assert trustops_runtime.configured_model_client() is client
    assert llm.configured_model_id() == 'approved-model'


def test_openai_request_budget_is_checked_before_sending():
    wire = Transport(completed())
    client = llm.OpenAIModelClient(api_key='test-only', opener=wire)
    with pytest.raises(ValueError, match='token budget'):
        client.complete('Return JSON.', 'test', max_tokens=0)
    assert wire.request is None
