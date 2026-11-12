import pytest

JS = """() => {
  const name = (e) => (e.getAttribute('aria-label') || e.getAttribute('title') || (e.labels && e.labels[0] && e.labels[0].textContent) ||
      (e.id && document.querySelector(`label[for="${e.id}"]`)?.textContent) || e.closest('label')?.textContent || '').trim();
  const bad = [];
  for (const e of document.querySelectorAll('main input:not([type=hidden]), main select, main textarea')) {
    if (e.offsetParent !== null && !name(e)) bad.push(`${e.tagName.toLowerCase()}[${e.type || ''}] ${e.placeholder || e.name || ''}`);
  }
  for (const b of document.querySelectorAll('main button, main a[href]')) {
    if (b.offsetParent !== null && !(b.textContent.trim() || b.getAttribute('aria-label'))) bad.push(`${b.tagName.toLowerCase()} without a name`);
  }
  for (const i of document.querySelectorAll('img')) if (!i.hasAttribute('alt')) bad.push('img without alt');
  const h1 = document.querySelectorAll('h1').length, h2 = document.querySelectorAll('main h2').length;
  if (h1 !== 1) bad.push(`expected one h1, found ${h1}`);
  if (h2 < 1) bad.push('page has no h2 heading');
  if (!document.documentElement.lang) bad.push('html has no lang');
  return bad;
}"""

CUSTOMER = ["dashboard", "assessments", "trustops", "agent-flow", "use-cases", "frameworks", "approvals", "evidence"]
STAFF = ["cases", "users", "activity", "service-health", "workspaces", "queue"]


@pytest.mark.parametrize("route", CUSTOMER)
def test_customer_pages_have_accessible_names(as_user, assessment, route):
    page = as_user("admin@t-bank", route)
    page.wait_for_selector("main h2", timeout=10_000)
    page.wait_for_timeout(400)
    assert page.evaluate(JS) == []


@pytest.mark.parametrize("route", STAFF)
def test_staff_pages_have_accessible_names(as_user, assessment, route):
    page = as_user("architect@cloudseals", route)
    page.wait_for_selector("main h2", timeout=10_000)
    page.wait_for_timeout(400)
    assert page.evaluate(JS) == []


def test_assessment_and_studio_pages_have_accessible_names(as_user, assessment):
    for who, route in (("admin@t-bank", f"assessment/{assessment}"), ("reviewer@cloudseals", f"use-cases/{assessment}")):
        page = as_user(who, route)
        page.wait_for_selector("main h2", timeout=10_000)
        page.wait_for_timeout(500)
        assert page.evaluate(JS) == [], route


def test_focus_moves_to_the_content_on_navigation_and_the_skip_link_exists(as_user):
    page = as_user("admin@t-bank", "dashboard")
    page.wait_for_selector(".tb .gov-page-heading")
    assert page.evaluate("document.activeElement.id") == "main"                       # a screen reader starts at the new page content
    assert page.evaluate("document.querySelector('a.skip').getAttribute('href')") == "#main"
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.tagName") in ("A", "BUTTON")            # keyboard users reach controls in order
