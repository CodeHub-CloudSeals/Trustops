import pytest
from app import main
from fastapi.testclient import TestClient

from tests.e2e.test_use_cases import Fake, uc


def test_model_startup_gate_requires_a_real_usable_connection(env, monkeypatch):
    monkeypatch.setenv('TAAD_MODEL_STARTUP_CHECK', '1')
    monkeypatch.setattr(main, 'SWASKA_CLIENT', None)
    with pytest.raises(RuntimeError, match='configured provider'), TestClient(main.app):
        pass
    monkeypatch.setattr(main, 'SWASKA_CLIENT', Fake('not json'))
    with pytest.raises(RuntimeError, match='verification failed'), TestClient(main.app):
        pass


def test_model_startup_can_check_synthetic_document_grounding_without_saving_data(env, monkeypatch):
    monkeypatch.setenv('TAAD_MODEL_STARTUP_CHECK', '1')
    monkeypatch.setenv('TAAD_MODEL_DOCUMENT_CHECK', '1')
    source = 'customer support chatbot answers account FAQs'
    client = Fake({'ok': True}, {'use_cases': [uc(name='Support chatbot', source_quotes=[source])]})
    monkeypatch.setattr(main, 'SWASKA_CLIENT', client)
    before = dict(main.STORE.inventory)
    with TestClient(main.app) as c:
        assert c.get('/health').status_code == 200
    assert len(client.calls) == 2 and main.STORE.inventory == before
    assert 'No customer data' in client.calls[0][1]


def test_ungrounded_document_output_blocks_model_startup(env, monkeypatch):
    monkeypatch.setenv('TAAD_MODEL_STARTUP_CHECK', '1')
    monkeypatch.setenv('TAAD_MODEL_DOCUMENT_CHECK', '1')
    monkeypatch.setattr(main, 'SWASKA_CLIENT', Fake({'ok': True}, {'use_cases': [uc(source_quotes=['invented quote'])]}))
    with pytest.raises(RuntimeError, match='verification failed'), TestClient(main.app):
        pass
