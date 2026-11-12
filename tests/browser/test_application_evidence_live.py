"""Opt-in real local REA artifact + UI delivery test through a dedicated externally started browser."""
import json
import os
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect, sync_playwright

pytestmark = pytest.mark.skipif(not os.environ.get('TRUSTOPS_REA_CDP'), reason='Requires the explicitly started dedicated REA test browser')


def test_actual_capture_upload_review_publish_and_customer_download(tmp_path):
    base = os.environ.get('TRUSTOPS_REA_URL', 'http://127.0.0.1:8018')
    endpoint = os.environ['TRUSTOPS_REA_CDP']
    assert urlsplit(base).hostname == '127.0.0.1' and urlsplit(endpoint).hostname == '127.0.0.1'
    capture = Path(os.environ['TRUSTOPS_REA_CAPTURE']).resolve()
    metadata = json.loads(capture.read_text())
    users = json.load(urllib.request.urlopen(base + '/v1/dev/users'))['items']
    tokens = {u['sub']: u['token'] for u in users}
    name = 'REA live browser verification ' + uuid.uuid4().hex[:6]
    request = urllib.request.Request(base + '/v1/assessments', method='POST',
        headers={'Authorization': 'Bearer ' + tokens['admin@t-bank'], 'Content-Type': 'application/json', 'Idempotency-Key': uuid.uuid4().hex},
        data=json.dumps({'ai_system_name': name, 'industry': 'banking', 'questionnaire_version': '1.0.0'}).encode())
    aid = json.load(urllib.request.urlopen(request))['assessment_id']
    output = Path(os.environ.get('TRUSTOPS_REA_UI_OUTPUT', str(tmp_path)))
    output.mkdir(parents=True, exist_ok=True)
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(endpoint)
        contexts = []

        def page_for(user, width=1440):
            context = browser.new_context(viewport={'width': width, 'height': 1000}, accept_downloads=True)
            context.add_init_script('sessionStorage.setItem("taad_token",' + json.dumps(tokens[user]) + ')')
            contexts.append(context)
            page = context.new_page()
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(base + '/portal/#/assessment/' + aid)
            expect(page.get_by_role('heading', name=name, exact=True)).to_be_visible()
            page.locator('.assessment-step').nth(1).click()
            return page

        try:
            customer = page_for('admin@t-bank')
            customer.get_by_text('Advanced: import REA browser capture', exact=True).click()
            customer.get_by_label('REA application capture JSON').set_input_files(str(capture))
            customer.get_by_role('button', name='Attach application capture', exact=True).click()
            panel = customer.locator('#application-evidence')
            expect(panel.get_by_text('awaiting review', exact=True)).to_be_visible()
            expect(panel.get_by_text(str(metadata['dom_nodes']), exact=True)).to_be_visible()
            expect(panel.get_by_role('button', name='Validate evidence & build report')).to_have_count(0)
            reviewer = page_for('reviewer@cloudseals')
            panel = reviewer.locator('#application-evidence')
            panel.get_by_label('Application evidence review reason').fill('Engineering UI rehearsal: actual owned-app capture checked with explicit scope limits.')
            panel.get_by_role('button', name='Validate evidence & build report', exact=True).click()
            expect(panel.get_by_role('button', name='Preview reviewed report', exact=True)).to_be_visible()
            with reviewer.expect_download() as event:
                panel.get_by_role('button', name='Preview reviewed report', exact=True).click()
            preview = output / 'ui-reviewed-preview.html'
            event.value.save_as(preview)
            assert 'UNPUBLISHED PREVIEW' in preview.read_text()
            panel.get_by_label('Application evidence review reason').fill('Release for local engineering verification; this is not a customer sign-off.')
            panel.get_by_role('button', name='Publish to customer', exact=True).click()
            expect(panel.get_by_text('Published', exact=True)).to_be_visible()
            customer.reload()
            panel = customer.locator('#application-evidence')
            expect(panel.get_by_text('Published', exact=True)).to_be_visible()
            panel.get_by_text('What was observed', exact=True).click()
            panel.screenshot(path=str(output / 'application-evidence-desktop.png'))
            with customer.expect_download() as event:
                panel.get_by_role('button', name='Download published application report', exact=True).click()
            report = output / 'ui-published-report.html'
            event.value.save_as(report)
            doc = report.read_text()
            assert metadata['rea_evidence_id'] in doc and 'Missing information' in doc and 'UNPUBLISHED PREVIEW' not in doc
            assert 'Engineering UI rehearsal' not in doc
            expect(customer.get_by_role('link', name='Preview a sample report (synthetic example)')).to_have_count(0)
            with customer.expect_download() as actual_report:
                customer.get_by_role('button', name='Download application evidence report', exact=True).click()
            published_copy = output / 'actual-assessment-report.html'
            actual_report.value.save_as(published_copy)
            assert published_copy.read_text() == doc
            customer.goto(base + '/portal/#/reports')
            expect(customer.get_by_role('heading', name=name, exact=True)).to_be_visible()
            mobile = page_for('admin@t-bank', 390)
            mobile.locator('#application-evidence').screenshot(path=str(output / 'application-evidence-mobile.png'))
            assert mobile.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 2')
            assert not errors, errors
        finally:
            for context in contexts:
                context.close()
            browser.close()
