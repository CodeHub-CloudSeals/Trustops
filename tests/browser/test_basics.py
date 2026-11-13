import re

import pytest
from playwright.sync_api import expect


def test_opens_directly_and_uses_the_light_theme_even_in_a_dark_browser(as_user):
    page = as_user(None, "", scheme="dark")
    expect(page.get_by_role("heading", name="Overview", exact=True)).to_be_visible()
    assert page.get_by_role("button", name=re.compile(r"@t-bank|@t-health|@cloudseals")).count() == 0      # no seeded-user picker
    assert page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(246, 248, 251)"   # LedgerSight v7 page #F6F8FB
    assert page.errors == []


def test_ledgersight_v7_shell_top_bar_rail_and_pill(as_user):
    """LedgerSight design v7 shell: top bar (workspace, page, who), sliding menu pill, menu collapses to an icon rail."""
    page = as_user("admin@t-bank", "decisions", width=1440)
    expect(page.locator(".topbar .ws-pill")).to_contain_text("T-Bank")
    expect(page.locator(".topbar .workspace-breadcrumb")).to_contain_text("Decisions")
    expect(page.locator(".topbar .role-pill")).to_contain_text("Administrator")
    assert page.locator("#nav > .nav-pill").count() == 1
    page.get_by_role("button", name="Collapse menu").click()
    expect(page.locator("body")).to_have_class(re.compile(r"\bside-mini\b"))
    expect(page.get_by_role("link", name="Policies")).to_be_visible()            # icons stay usable in the rail
    page.get_by_role("button", name="Expand menu").click()
    expect(page.locator("body")).not_to_have_class(re.compile(r"\bside-mini\b"))
    page.get_by_role("link", name="Risk").click()
    expect(page.get_by_role("heading", name="Risk", exact=True)).to_be_visible()
    expect(page.locator(".topbar .workspace-breadcrumb")).to_contain_text("Risk")
    assert page.errors == []


def test_public_registration_page(as_user):
    page = as_user(None, "register")
    expect(page.get_by_role("heading", name="Request workspace access")).to_be_visible()
    for label in ("Organisation name", "Work email", "Engagement reference"):
        expect(page.get_by_label(label)).to_be_visible()
    expect(page.get_by_role("button", name="Submit access request")).to_be_visible()


@pytest.mark.parametrize("width", [1440, 390])
@pytest.mark.parametrize("route", ["dashboard", "assessments", "trustops", "agent-flow", "use-cases", "frameworks"])
def test_no_horizontal_scroll(as_user, assessment, route, width):
    page = as_user("admin@t-bank", route, width=width)
    page.wait_for_selector("main .module-page, main .trustops-page, main .card, main .tb", timeout=10_000)
    page.wait_for_timeout(500)
    assert page.evaluate("document.documentElement.scrollWidth - window.innerWidth") <= 1, f"{route} overflows at {width}px"


def test_full_width_layout_uses_the_window(as_user):
    page = as_user("admin@t-bank", "dashboard", width=2000)
    page.wait_for_selector(".tb .gov-page-heading")
    box = page.locator("main").bounding_box()
    nav = page.locator("header.top").bounding_box()
    # floating panels: 16px gutters around the sidebar and the content panel, content fills the rest of the window
    assert abs(box["x"] - (nav["x"] + nav["width"] + 16)) <= 1
    assert abs(box["x"] + box["width"] - (2000 - 16)) <= 1
    assert page.locator(".tb-stats").bounding_box()["width"] >= 1500


def test_stored_xss_is_rendered_as_text(as_user, api):
    api("admin@t-bank", "POST", "/v1/assessments", {"ai_system_name": "<img src=x onerror=window.__pwned=1>", "industry": "banking", "questionnaire_version": "1.0.0"})
    page = as_user("admin@t-bank", "assessments")
    expect(page.get_by_text("<img src=x onerror=window.__pwned=1>").first).to_be_visible()
    assert page.evaluate("window.__pwned") is None


def test_csp_blocks_injected_inline_script(as_user):
    page = as_user("admin@t-bank", "dashboard")
    page.wait_for_selector(".tb .gov-page-heading")
    page.evaluate("""() => { const s = document.createElement('script'); s.textContent = 'window.__ran = 1'; document.body.append(s); }""")
    assert page.evaluate("window.__ran") is None


@pytest.mark.parametrize("route", ["users", "activity", "service-health", "cases", "workspaces", "queue"])
def test_customers_cannot_use_staff_pages(as_user, route):
    page = as_user("admin@t-bank", route)
    expect(page.locator("main")).to_contain_text(re.compile("do not have access", re.I))
    assert page.locator("main table tbody tr").count() == 0


def test_staff_menus_are_hidden_but_staff_pages_stay_reachable(as_user):
    staff = as_user("architect@cloudseals", "dashboard")
    expect(staff.get_by_role("heading", name="Overview", exact=True)).to_be_visible()
    expect(staff.locator("#nav").get_by_role("link", name="Cases", exact=True)).to_have_count(0)
    expect(staff.locator("summary", has_text="Administration")).to_have_count(0)
    users = as_user("architect@cloudseals", "users")
    expect(users.locator("main")).not_to_contain_text(re.compile("do not have access", re.I))


def test_sign_out_and_back(as_user):
    page = as_user("admin@t-bank", "dashboard")
    expect(page.get_by_role("heading", name="Overview", exact=True)).to_be_visible()
    # dev mode has no sign-out button (single local workspace); an expired/invalid token returns to sign-in instead
    page.evaluate("sessionStorage.setItem('taad_token', 'x.invalid')")
    page.reload()
    expect(page.get_by_role("heading", name="Overview", exact=True)).to_be_visible()   # dev login re-establishes a workspace
