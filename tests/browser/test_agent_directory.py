import os
import re
from pathlib import Path

import pytest
from playwright.sync_api import expect


@pytest.mark.parametrize('width', [1440, 390])
def test_customer_directory_lists_all_teams_without_clutter(as_user, width):
    page = as_user('admin@t-bank', 'agents', width=width)
    expect(page.get_by_role('heading', name='Assessment team', exact=True).first).to_be_visible()
    expect(page.locator('.agent-directory-card')).to_have_count(9)
    for name in ('Assessment assistants', 'Application evidence'):
        expect(page.get_by_role('heading', name=name, exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='Assessment interviewer', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='Report narrative', exact=True)).to_be_visible()
    nav = page.locator('#nav')
    expect(nav.get_by_role('link', name=re.compile('Shadow ROI|Readiness|Demo Studio|AgentOps|Workflow runs'))).to_have_count(0)
    expect(page.locator('.workflow-presenter-guide')).to_have_count(0)
    assert page.evaluate('document.documentElement.scrollWidth - innerWidth') <= 1
    assert page.errors == []
    if os.environ.get('TRUSTOPS_UI_OUTPUT'):
        output = Path(os.environ['TRUSTOPS_UI_OUTPUT'])
        output.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(output / f'agents-{width}.png'), full_page=True, animations="disabled")


def test_navigation_only_offers_case_management_to_case_roles(as_user, api):
    api('architect@cloudseals', 'PATCH', '/v1/admin/users/reviewer@cloudseals', {'roles': ['cloudseals_platform_ops']})
    try:
        page = as_user('reviewer@cloudseals', 'agents')
        expect(page.get_by_role('heading', name='Assessment team', exact=True).first).to_be_visible()
        nav = page.locator('#nav')
        expect(nav.get_by_role('link', name='Cases', exact=True)).to_have_count(0)
        expect(nav.get_by_role('link', name='Review queue', exact=True)).to_be_visible()
    finally:
        api('architect@cloudseals', 'PATCH', '/v1/admin/users/reviewer@cloudseals', {'roles': ['cloudseals_reviewer']})


@pytest.mark.parametrize('width', [1440, 390])
def test_assessment_process_shows_actual_stages(as_user, assessment, width):
    page = as_user('admin@t-bank', f'agent-flow/{assessment}', width=width)
    expect(page.get_by_role('heading', name='Assessment process', exact=True)).to_be_visible()
    expect(page.locator('.assessment-process-stage')).to_have_count(4)
    for name in ('Details', 'Evidence', 'Assessment', 'Review & report'):
        expect(page.locator('.assessment-process-stage').get_by_role('heading', name=name, exact=True)).to_be_visible()
    expect(page.locator('.process-evidence-summary')).to_contain_text('1 uploaded file(s)')
    expect(page.get_by_role('button', name='▶ Run agents')).to_have_count(0)
    expect(page.locator('main')).not_to_contain_text('Payment workflow')
    assert page.evaluate('document.documentElement.scrollWidth - innerWidth') <= 1
    assert page.errors == []
    if os.environ.get('TRUSTOPS_UI_OUTPUT'):
        output = Path(os.environ['TRUSTOPS_UI_OUTPUT'])
        output.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(output / f'assessment-process-{width}.png'), full_page=True, animations="disabled")
