import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from app import application_evidence as tech
from app import main, persist
from app.store import Store

from tests.conftest import new_assessment


def capture():
    end = datetime.now(timezone.utc)
    return {'schema_version': 'trustops.rea.capture.v1', 'producer': 'rea-agents', 'producer_version': '6.5.0',
            'rea_evidence_id': 'ev_' + '1' * 64, 'source_sha256': '2' * 64,
            'target_url': 'http://127.0.0.1:8033/', 'started_at': (end - timedelta(seconds=5)).isoformat(),
            'ended_at': end.isoformat(), 'observation_ms': 5000, 'dom_nodes': 35,
            'scripts': [{'url': 'http://127.0.0.1:8033/app.js', 'reported_hash': 'abc'}],
            'requests': [{'url': 'http://127.0.0.1:8033/api/health', 'method': 'GET', 'status': 200}], 'limitations': ['Prior activity unknown.']}


def upload(c, h, aid, value):
    raw = json.dumps(value).encode()
    r = c.post(f'/v1/assessments/{aid}/evidence/upload-url', headers=h('admin@t-bank'),
               json={'filename': 'rea-capture.json', 'content_type': 'application/json', 'file_size_bytes': len(raw),
                     'claimed_sha256': hashlib.sha256(raw).hexdigest()})
    assert r.status_code == 201, r.text
    grant = r.json()
    r = c.put(grant['upload_url'], headers=h('admin@t-bank', **{'Content-Type': 'application/octet-stream'}), content=raw)
    assert r.json()['state'] == 'clean', r.text
    return grant['evidence_id']


def attach(env, value=None):
    c, h = env
    aid = new_assessment(c, h, 'admin@t-bank')
    eid = upload(c, h, aid, value or capture())
    path = f'/v1/assessments/{aid}/application-evidence'
    r = c.post(path, headers=h('admin@t-bank'), json={'evidence_id': eid})
    assert r.status_code == 201, r.text
    return c, h, aid, path, r.json()


def test_real_graph_pauses_then_reviewer_publishes_immutable_customer_report(env):
    c, h, aid, path, run = attach(env)
    assert run['engine'] == 'langgraph' and run['status'] == 'awaiting_review'
    assert [x['step'] for x in run['events']] == ['validate_capture', 'analyse_metadata']
    assert 'checkpoints' not in run
    url = f"{path}/{run['run_id']}"
    assert c.get(url + '/report', headers=h('admin@t-bank')).status_code == 403
    decision = {'decision': 'validated', 'reason': 'Reviewed source and scope limits.', 'source_digest': run['source_digest']}
    assert c.post(url + '/review', headers=h('admin@t-bank'), json=decision).status_code == 403
    reviewed = c.post(url + '/review', headers=h('reviewer@cloudseals'), json=decision)
    assert reviewed.status_code == 200, reviewed.text
    r = reviewed.json()
    assert r['status'] == 'reviewed_draft'
    assert [x['step'] for x in r['events']] == ['validate_capture', 'analyse_metadata', 'human_review', 'report_draft']
    assert c.get(url + '/report', headers=h('admin@t-bank')).status_code == 403
    assert c.get(url + '/report?preview=true', headers=h('admin@t-bank')).status_code == 403
    preview = c.get(url + '/report?preview=true', headers=h('reviewer@cloudseals'))
    assert preview.status_code == 200 and 'UNPUBLISHED PREVIEW' in preview.text
    pub = {'source_digest': r['source_digest'], 'reason': 'Release reviewed technical observations.'}
    released = c.post(url + '/publish', headers=h('reviewer@cloudseals'), json=pub)
    assert released.status_code == 200, released.text
    report = c.get(url + '/report', headers=h('admin@t-bank'))
    assert report.status_code == 200 and 'Backend access controls' in report.text and 'capture.requests' in report.text
    assert 'prior' in report.text.lower() and 'not a security certification' in report.text
    assert 'Release reviewed' not in report.text
    assert any(r['kind'] == 'application_evidence' for r in c.get('/v1/report-library', headers=h('admin@t-bank')).json()['items'])
    assert c.get(url + '/report', headers=h('admin@t-health')).status_code == 404
    original = report.content
    main.STORE.inventory[aid]['technical_runs'][run['run_id']]['state']['observations'][0]['text'] = 'Later working edit'
    assert c.get(url + '/report', headers=h('admin@t-bank')).content == original


def test_pending_graph_survives_durable_store_round_trip(env, tmp_path):
    c, h, aid, path, run = attach(env)
    url = 'sqlite:///' + str(tmp_path / 'state.db')
    persist.save(main.STORE, url)
    restored = Store()
    assert persist.load(restored, url)
    loaded = restored.inventory[aid]['technical_runs'][run['run_id']]
    assert loaded['checkpoints']['latest']
    tech.execute(loaded, 'validated')
    assert loaded['status'] == 'reviewed_draft'
    assert [e['step'] for e in loaded['events']].count('analyse_metadata') == 1


@pytest.mark.parametrize('bad', ['stale', 'rejected', 'source_changed'])
def test_publication_fails_closed(env, bad):
    c, h, aid, path, run = attach(env)
    url = f"{path}/{run['run_id']}"
    if bad != 'stale':
        r = c.post(url + '/review', headers=h('reviewer@cloudseals'),
                   json={'decision': 'rejected' if bad == 'rejected' else 'validated', 'reason': 'Scope review',
                         'source_digest': run['source_digest']})
        assert r.status_code == 200, r.text
        run = r.json()
    if bad == 'source_changed':
        main.STORE.evidence[run['evidence_id']]['state'] = 'rejected'
    r = c.post(url + '/publish', headers=h('reviewer@cloudseals'),
               json={'source_digest': '0' * 64 if bad == 'stale' else run['source_digest'], 'reason': 'Release'})
    assert r.status_code == 409 and not main.STORE.inventory[aid]['technical_runs'][run['run_id']]['releases']


def test_ingestion_deduplicates_rejects_wrong_sources_and_unexpected_fields(env):
    c, h, aid, path, run = attach(env)
    again = c.post(path, headers=h('admin@t-bank'), json={'evidence_id': run['evidence_id']})
    assert again.json()['run_id'] == run['run_id']
    assert c.post(path, headers=h('admin@t-health'), json={'evidence_id': run['evidence_id']}).status_code == 404
    bad = {**capture(), 'cookies': {'token': 'not accepted'}}
    eid = upload(c, h, aid, bad)
    assert c.post(path, headers=h('admin@t-bank'), json={'evidence_id': eid}).status_code == 422
    assert len(main.STORE.inventory[aid]['technical_runs']) == 1


def test_metadata_does_not_become_an_unfounded_security_claim_and_urls_are_redacted():
    data = capture()
    data['requests'][0].update(url='https://example.org/api?token=sensitive#fragment', status=503)
    parsed = tech.Capture.model_validate(data).model_dump(mode='json')
    assert parsed['requests'][0]['url'] == 'https://example.org/api'
    run = {'run_id': 'test', 'capture': parsed, 'evidence_sha256': 'a' * 64}
    tech.execute(run)
    assert run['state']['findings'][0]['type'] == 'observed_failure'
    assert run['state']['findings'][0]['evidence_refs'] == ['capture.requests[0]']
    assert len(run['state']['missing_information']) == 3
    tech.execute(run, 'validated')
    doc = tech.render_report(run, '<img src=x onerror=alert(1)>', 1)
    assert '<img' not in doc and '&lt;img' in doc and 'sensitive' not in doc
    forged = copy.deepcopy(data)
    forged['target_url'] = 'http://user:password@example.org/'
    with pytest.raises(ValueError):
        tech.Capture.model_validate(forged)


def test_missing_source_storage_blocks_review_without_mutating_pending_work(env, monkeypatch):
    c, h, aid, path, run = attach(env)
    before = copy.deepcopy(main.STORE.inventory[aid]['technical_runs'])
    monkeypatch.setattr(main.OBJECTS, 'get', lambda *_: (_ for _ in ()).throw(FileNotFoundError()))
    r = c.post(f"{path}/{run['run_id']}/review", headers=h('reviewer@cloudseals'),
               json={'decision': 'validated', 'reason': 'Review', 'source_digest': run['source_digest']})
    assert r.status_code == 503 and main.STORE.inventory[aid]['technical_runs'] == before


def test_client_collector_removes_payloads_and_url_secrets_from_export():
    from scripts.collect_rea import normalize
    value = capture()
    raw = {'ok': True, 'data': {'operation': 'inspect_web_page', 'provider': {'id': 'rea-cdp-browser'},
        'evidence_id': value['rea_evidence_id'], 'limitations': ['Bounded observation.'], 'normalized_result': {
            'target': {'origin': 'http://127.0.0.1:8033', 'url': value['target_url'] + '?token=secret'},
            'capture_window': {k: value[k] for k in ('started_at', 'ended_at', 'observation_ms')},
            'dom': {'total_nodes': 35, 'nodes': [{'text': 'Customer private text'}]},
            'scripts': {'items': [{'url': 'http://127.0.0.1:8033/app.js?key=secret', 'cdp_hash': 'a' * 64,
                                  'source': 'Do not export source text'}]},
            'network': {'requests': [{**value['requests'][0], 'body': 'Private request body', 'cookies': 'private-cookie'}]}}}}
    out = normalize(raw, '6.5.0', 'http://127.0.0.1:8033')
    serialized = json.dumps(out)
    assert all(x not in serialized for x in ('secret', 'Customer private text', 'Do not export', 'Private request body', 'private-cookie'))
    assert len(out['requests']) == 1 and out['target_url'] == value['target_url']
    with pytest.raises(ValueError, match='origin'):
        normalize(raw, '6.5.0', 'https://another.example')
