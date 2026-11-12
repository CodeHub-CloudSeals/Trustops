import hashlib

import pytest
from app import main, persist

from tests.conftest import new_assessment
from tests.e2e.test_studio import DOC, Fake, gap, item, maturity_json, uc, upload


@pytest.fixture()
def reviewed(env, monkeypatch):
    c, h = env
    aid = new_assessment(c, h, 'admin@t-bank')
    upload(c, h, aid, DOC.encode())
    rev = 'reviewer@cloudseals'
    ok = {'status': 'validated', 'reason': 'Checked against source evidence'}
    root = f'/v1/assessments/{aid}'
    monkeypatch.setattr(main, 'SWASKA_CLIENT', Fake({'use_cases': [uc()]}))
    uid = c.post(root + '/inventory/run', headers=h('admin@t-bank'), json={}).json()['use_cases'][0]['use_case_id']
    c.patch(root + f'/inventory/use-cases/{uid}', headers=h(rev), json=ok)
    monkeypatch.setattr(main, 'SWASKA_CLIENT', Fake({'findings': [gap(severity='critical', evidence_use_case_ids=[uid])]}))
    gid = c.post(root + '/gap-analysis/run', headers=h(rev), json={'framework_id': 'eu_ai_act'}).json()['gaps'][0]['gap_id']
    c.patch(root + f'/gaps/{gid}', headers=h(rev), json=ok)
    refs = {p: [uid] for p in main.studio.PRINCIPLES}
    monkeypatch.setattr(main, 'SWASKA_CLIENT', Fake(maturity_json(evidence_refs=refs)))
    c.post(root + '/maturity/run', headers=h(rev))
    c.patch(root + '/maturity', headers=h(rev), json=ok)
    monkeypatch.setattr(main, 'SWASKA_CLIENT', Fake({'roadmap_items': [item('a', gap_ids_addressed=[gid])], 'executive_summary': 'Act now.'}))
    rid = c.post(root + '/roadmap/run', headers=h(rev)).json()['roadmap'][0]['item_id']
    c.patch(root + f'/roadmap/{rid}', headers=h(rev), json=ok)
    return c, h, aid, uid, gid, rid


def preview(c, h, aid):
    return c.get(f'/v1/assessments/{aid}/diagnostic-report?format=json', headers=h('reviewer@cloudseals')).json()


def publish(c, h, aid, *, sub='reviewer@cloudseals', digest=None, key='publish', reason='Final report and roadmap checked'):
    digest = digest or preview(c, h, aid)['source_digest']
    return c.post(f'/v1/assessments/{aid}/diagnostic-report/publish', headers=h(sub, **{'Idempotency-Key': key}),
                  json={'source_digest': digest, 'reason': reason})


def test_publication_requires_reviewer_and_is_idempotent_tenant_scoped_and_frozen(reviewed):
    c, h, aid, uid, gid, rid = reviewed
    root = f'/v1/assessments/{aid}'
    assert c.get(root + '/diagnostic-report', headers=h('admin@t-bank')).status_code == 403
    assert c.get(root + '/inventory', headers=h('admin@t-bank')).json()['delivery'] is None
    assert publish(c, h, aid, sub='admin@t-bank').status_code == 403
    main.STORE.users['architect@cloudseals']['roles'] = ['cloudseals_assessor']
    assert publish(c, h, aid, sub='architect@cloudseals').status_code == 403  # assessors preview; reviewers publish
    assert publish(c, h, aid, sub='admin@t-health').status_code == 404
    assert publish(c, h, aid, reason='   ').status_code == 422
    no_key = c.post(root + '/diagnostic-report/publish', headers=h('reviewer@cloudseals'),
                    json={'source_digest': preview(c, h, aid)['source_digest'], 'reason': 'Checked'})
    assert no_key.status_code == 400
    released = publish(c, h, aid)
    assert released.status_code == 200, released.text
    r = released.json()
    assert publish(c, h, aid).json() == r
    assert publish(c, h, aid, key='another-request').json() == r
    assert len(main.STORE.inventory[aid]['published_diagnostics']) == 1
    assert sum(a['action'] == 'report.diagnostic_published' for a in main.STORE.audit) == 1
    delivered = c.get(root + '/inventory', headers=h('admin@t-bank')).json()['delivery']
    assert delivered['snapshot']['maturity']['overall_score'] == 1.5
    assert delivered['snapshot']['roadmap'][0]['item_id'] == rid and 'html' not in delivered
    download = c.get(root + '/diagnostic-report?narrative=true', headers=h('admin@t-bank'))
    assert download.status_code == 200 and download.headers['x-report-version'] == '1'
    assert download.headers['x-content-digest'] == hashlib.sha256(download.content).hexdigest() == r['content_digest']
    assert 'FINAL' in download.text and 'Item a' in download.text
    seen_by_customer = c.get(root + '/diagnostic-report?format=json', headers=h('admin@t-bank')).json()['published']
    assert seen_by_customer == {k: v for k, v in r.items() if k not in ('published_by', 'publication_reason')}     # who published and why stay internal
    assert c.get(root + '/diagnostic-report', headers=h('admin@t-health')).status_code == 404
    assert c.get(root + '/diagnostic-report?report_id=missing', headers=h('admin@t-bank')).status_code == 404

    # Later review decisions change working material but never the customer's released version.
    rejected = {'status': 'rejected', 'reason': 'New evidence requires another review'}
    c.patch(root + f'/gaps/{gid}', headers=h('reviewer@cloudseals'), json=rejected)
    c.patch(root + f'/inventory/use-cases/{uid}', headers=h('reviewer@cloudseals'), json=rejected)
    assert c.get(root + '/diagnostic-report', headers=h('admin@t-bank')).content == download.content
    assert c.get(root + '/inventory', headers=h('admin@t-bank')).json()['delivery'] == delivered
    assert preview(c, h, aid)['status'] == 'DRAFT'


def test_stale_preview_and_uncovered_or_invalid_reviewed_work_block_publication(reviewed):
    c, h, aid, uid, gid, rid = reviewed
    root = f'/v1/assessments/{aid}'
    old_digest = preview(c, h, aid)['source_digest']
    # A review reason is part of the checked material, so even a concurrent review invalidates an old preview.
    c.patch(root + '/maturity', headers=h('reviewer@cloudseals'), json={'status': 'validated', 'reason': 'Reviewed again'})
    stale = publish(c, h, aid, digest=old_digest)
    assert stale.status_code == 409 and stale.json()['code'] == 'report_changed'
    inv = main.STORE.inventory[aid]
    inv['roadmap'][0]['gap_ids_addressed'] = []
    blocked = publish(c, h, aid)
    assert blocked.status_code == 409 and 'critical/high gaps' in blocked.json()['message']
    inv['roadmap'][0]['gap_ids_addressed'] = [gid]
    c.patch(root + f'/inventory/use-cases/{uid}', headers=h('reviewer@cloudseals'), json={'status': 'rejected', 'reason': 'No longer evidenced'})
    bad = publish(c, h, aid)
    assert bad.status_code == 409 and 'no longer validated' in bad.json()['message']
    assert main.STORE.inventory[aid]['published_diagnostics'] == []


def test_new_versions_and_published_html_survive_storage_reload(reviewed, tmp_path):
    c, h, aid, uid, gid, rid = reviewed
    one = publish(c, h, aid).json()
    root = f'/v1/assessments/{aid}'
    old_html = c.get(root + '/diagnostic-report', headers=h('admin@t-bank')).content
    c.patch(root + '/maturity', headers=h('reviewer@cloudseals'), json={'status': 'validated', 'reason': 'Follow-up review completed'})
    two = publish(c, h, aid, key='second-version').json()
    assert two['version'] == 2 and one['report_id'] != two['report_id']
    url = f'sqlite:///{tmp_path / "delivery.db"}'
    persist.save(main.STORE, url)
    main.STORE.inventory.clear()
    assert persist.load(main.STORE, url)
    assert c.get(root + '/diagnostic-report?format=json', headers=h('admin@t-bank')).json()['published']['version'] == 2
    assert c.get(root + '/diagnostic-report?report_id=' + one['report_id'], headers=h('admin@t-bank')).content == old_html
    other = new_assessment(c, h, 'admin@t-bank', key='another-assessment')
    assert c.get(f'/v1/assessments/{other}/diagnostic-report?report_id=' + one['report_id'], headers=h('admin@t-bank')).status_code == 404


def test_customers_never_see_who_reviewed_or_the_reviewers_internal_notes(reviewed):
    import json
    c, h, aid, uid, gid, rid = reviewed
    assert publish(c, h, aid).status_code == 200
    customer = c.get(f'/v1/assessments/{aid}/inventory', headers=h('admin@t-bank')).json()
    blob = json.dumps(customer)
    for leaked in ('reviewer@cloudseals', 'reviewed_by', 'review_reason', 'reviewed_at', 'notes_for_architect', 'Checked against source evidence'):
        assert leaked not in blob, leaked
    assert customer['delivery']['snapshot']['gaps'][0]['status'] == 'VALIDATED'          # the content itself is still delivered
    assert customer['use_cases'][0]['status'] == 'VALIDATED' and customer['delivery']['snapshot']['maturity']['overall_score'] == 1.5
    staff = json.dumps(c.get(f'/v1/assessments/{aid}/inventory', headers=h('reviewer@cloudseals')).json())
    assert 'reviewer@cloudseals' in staff and 'notes_for_architect' in staff                # reviewers keep the full record


@pytest.mark.parametrize('operation,body,target', [
    ('inventory', {}, 'use_cases'), ('gap-analysis', {'framework_id': 'eu_ai_act'}, 'gaps'),
    ('maturity', None, 'maturity'), ('roadmap', None, 'roadmap'), ('overlay', None, 'overlay'),
])
@pytest.mark.parametrize('failure,expected', [(None, 503), (RuntimeError('upstream failed'), 502), ('not json', 502)])
def test_failed_analysis_never_erases_saved_work_or_reports_success(reviewed, monkeypatch, operation, body, target, failure, expected):
    import copy
    c, h, aid, *_ = reviewed
    inv = main.STORE.inventory[aid]
    if target == 'overlay':
        inv[target] = {'status': 'UNREVIEWED', 'marker': 'saved architecture'}
    elif isinstance(inv[target], list):
        for row in inv[target]:
            row['status'] = 'UNREVIEWED'
    else:
        inv[target]['status'] = 'UNREVIEWED'
    before = copy.deepcopy(inv)
    monkeypatch.setattr(main, 'SWASKA_CLIENT', None if failure is None else Fake(failure))
    sub = 'admin@t-bank' if operation == 'inventory' else 'reviewer@cloudseals'
    response = c.post(f'/v1/assessments/{aid}/{operation}/run', headers=h(sub), json=body)
    assert response.status_code == expected, response.text
    assert response.json()['code'] == ('model_unavailable' if expected == 503 else 'analysis_failed')
    assert inv == before


def test_report_library_lists_both_published_types_without_leaking_drafts_or_other_tenants(reviewed):
    import json

    from tests.conftest import BANK, fill_required
    c, h, aid, *_ = reviewed
    assert c.get('/v1/report-library').status_code == 401
    assert c.get('/v1/report-library', headers=h('admin@t-bank')).json()['items'] == []
    release = publish(c, h, aid).json()
    library = c.get('/v1/report-library', headers=h('admin@t-bank')).json()
    assert library['total'] == 1
    row = library['items'][0]
    assert row['report_id'] == release['report_id'] and row['kind'] == 'document_diagnostic'
    assert c.get(row['download_urls']['html'], headers=h('admin@t-bank')).status_code == 200
    assert c.get(row['download_urls']['html'], headers=h('admin@t-health')).status_code == 404
    assert c.get('/v1/report-library', headers=h('admin@t-health')).json()['items'] == []
    assert c.get('/v1/report-library', params={'assessment_id': aid}, headers=h('admin@t-health')).status_code == 404
    for private in ('reviewer@cloudseals', 'publication_reason', 'reviewed_by', 'snapshot', 'html": "<!doctype'):
        assert private not in json.dumps(library)
    fill_required(c, h, 'admin@t-bank', aid, BANK)
    assert c.post(f'/v1/assessments/{aid}/submit', headers=h('admin@t-bank', **{'Idempotency-Key': 'submit-library'})).status_code == 202
    draft = c.get(f'/v1/assessments/{aid}/reports', headers=h('reviewer@cloudseals')).json()['items'][0]
    assert c.get('/v1/report-library', headers=h('reviewer@cloudseals')).json()['total'] == 1
    approved = c.post(f'/v1/assessments/{aid}/reviews/{draft["report_id"]}/decision', headers=h('reviewer@cloudseals', **{'Idempotency-Key': 'approve-library'}),
                      json={'decision': 'approve', 'reviewer_reason': 'Engineering test review'})
    assert approved.status_code == 200
    rows = c.get('/v1/report-library', headers=h('admin@t-bank')).json()['items']
    assert {r['kind'] for r in rows} == {'document_diagnostic', 'questionnaire'}
    questionnaire = next(r for r in rows if r['kind'] == 'questionnaire')
    pdf = c.get(questionnaire['download_urls']['pdf'], headers=h('admin@t-bank'))
    assert pdf.status_code == 200 and pdf.content.startswith(b'%PDF')
    word = c.get(questionnaire['download_urls']['docx'], headers=h('admin@t-bank'))
    assert word.status_code == 200 and word.content.startswith(b'PK')


@pytest.mark.parametrize('change', ['bytes', 'metadata', 'unavailable'])
def test_publication_rechecks_original_source_integrity(reviewed, monkeypatch, change):
    c, h, aid, uid, *_ = reviewed
    uc_record = main.STORE.inventory[aid]['use_cases'][0]
    evidence = main.STORE.evidence[uc_record['evidence_id']]
    original_preview = preview(c, h, aid)
    assert original_preview['source_digest']
    if change == 'bytes':
        main.OBJECTS.put(evidence['tenant_id'], 'evidence', evidence['evidence_id'], b'Changed source bytes')
    elif change == 'metadata':
        evidence['sha256'] = '0' * 64
    else:
        monkeypatch.setattr(main.OBJECTS, 'get', lambda *_: (_ for _ in ()).throw(FileNotFoundError()))
    response = publish(c, h, aid)
    assert response.status_code == 409
    assert main.STORE.inventory[aid]['published_diagnostics'] == []
    assert main.STORE.inventory[aid]['use_cases'][0]['status'] == 'VALIDATED'
