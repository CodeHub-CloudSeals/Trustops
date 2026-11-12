import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from playwright.sync_api import expect


def http_capture():
    now = datetime.now(timezone.utc).isoformat()
    return {'schema_version': 'trustops.rea.capture.v1', 'producer': 'trustops-http-inspector', 'producer_version': '1.0',
            'rea_evidence_id': 'ev_' + 'c' * 64, 'source_sha256': hashlib.sha256(b'owned HTML fixture').hexdigest(),
            'target_url': 'https://owned.example/', 'started_at': now, 'ended_at': now, 'observation_ms': 20,
            'dom_nodes': 8, 'scripts': [{'url': 'https://owned.example/app.js', 'reported_hash': None}],
            'requests': [{'url': 'https://owned.example/', 'method': 'GET', 'status': 200}],
            'page': {'title': 'Owned browser fixture', 'http_status': 200, 'content_type': 'text/html',
                     'security_headers': {'x-content-type-options': 'nosniff'}},
            'limitations': ['HTTP-only fixture: JavaScript was not executed.']}


@pytest.mark.parametrize('width', [1440, 390])
def test_url_inspection_attaches_clean_evidence_and_leaves_report_for_review(as_user, assessment, width):
    page = as_user('admin@t-bank', f'assessment/{assessment}', width=width)
    page.get_by_role('button', name=re.compile('Documents')).click()
    calls = []

    def inspected(route):
        calls.append(route.request.post_data_json)
        route.fulfill(status=200, content_type='application/json', body=json.dumps({'capture': http_capture()}))

    page.route('**/website-inspection', inspected)
    form = page.locator('.website-inspection-form')
    expect(form.get_by_label('Website URL', exact=True)).to_be_visible()
    form.get_by_label('Website URL', exact=True).fill('owned.example/')
    form.get_by_role('button', name='Inspect website', exact=True).click()
    assert calls == []  # Browser-required permission checkbox prevents the request.
    form.get_by_role('checkbox').check()
    form.get_by_role('button', name='Inspect website', exact=True).click()
    card = page.locator('.application-evidence-card', has_text='https://owned.example/')
    expect(card).to_be_visible()
    expect(card).to_contain_text('Public-page HTTP inspection')
    expect(card).to_contain_text('awaiting review')
    expect(card).to_contain_text('HTML elements')
    assert calls == [{'url': 'https://owned.example/', 'authorized': True}]
    card.get_by_text('What was observed', exact=True).click()
    expect(card).to_contain_text('Owned browser fixture')
    card.get_by_text('Page response details', exact=True).click()
    expect(card).to_contain_text('nosniff')
    expect(card.get_by_role('button', name='Download published application report')).to_have_count(0)
    page.reload()
    expect(page.locator('.application-evidence-card', has_text='https://owned.example/')).to_be_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
    assert page.errors == []
    if os.environ.get('TRUSTOPS_UI_OUTPUT'):
        output = Path(os.environ['TRUSTOPS_UI_OUTPUT'])
        output.mkdir(parents=True, exist_ok=True)
        page.locator('#application-evidence').screenshot(path=str(output / f'website-inspection-{width}.png'), animations='disabled')


def test_failed_url_inspection_shows_error_and_does_not_attach_a_capture(as_user, assessment):
    page = as_user('admin@t-bank', f'assessment/{assessment}')
    page.get_by_role('button', name=re.compile('Documents')).click()
    page.route('**/website-inspection', lambda route: route.fulfill(status=422, content_type='application/json',
               body=json.dumps({'code': 'website_inspection_failed', 'message': 'Use a public website. Local addresses are blocked.'})))
    form = page.locator('.website-inspection-form')
    form.get_by_label('Website URL', exact=True).fill('http://127.0.0.1/')
    form.get_by_role('checkbox').check()
    form.get_by_role('button', name='Inspect website', exact=True).click()
    expect(form.get_by_role('status')).to_contain_text('Use a public website.')
    expect(form.get_by_role('button', name='Inspect website', exact=True)).to_be_enabled()
    expect(page.locator('.application-evidence-card')).to_have_count(0)
    expect(form.get_by_label('Website URL', exact=True)).to_have_value('http://127.0.0.1/')


def test_assessment_offers_actual_reports_without_a_static_sample_link(as_user, assessment):
    page = as_user('admin@t-bank', f'assessment/{assessment}')
    page.get_by_role('button', name=re.compile('Review & report')).click()
    expect(page.get_by_role('heading', name='Your reports', exact=True)).to_be_visible()
    expect(page.locator('a[href="sample-assessment-report.html"]')).to_have_count(0)
    expect(page.get_by_text('No published assessment report yet. Complete the assessment and send it for review.')).to_be_visible()
    page.goto(page.url.split('#')[0] + 'sample-assessment-report.html')
    expect(page.get_by_role('heading', name='Reports', exact=True)).to_be_visible()
    assert page.errors == []
