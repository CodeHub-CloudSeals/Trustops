import re
import uuid

from playwright.sync_api import expect


def test_cases_create_status_link_and_activity(as_user, assessment):
    page = as_user("architect@cloudseals", "cases")
    title = f"Demo Bank review {uuid.uuid4().hex[:6]}"
    page.get_by_role("button", name="+ New case").click()
    page.get_by_label("Case title").fill(title)
    page.get_by_label("Customer", exact=True).fill("Demo Bank plc")
    page.get_by_role("button", name="Create case").click()
    expect(page.get_by_role("heading", name=title)).to_be_visible()
    expect(page.locator(".case-status", has_text="Draft").first).to_be_visible()

    # status needs a reason; delivery needs a FINAL report
    page.get_by_role("button", name="Update status").click()
    expect(page.locator("#toast")).to_have_text("Enter a reason first")
    page.get_by_label("New status").select_option("delivered")
    page.get_by_label("Reason for status change").fill("Report sent")
    page.get_by_role("button", name="Update status").click()
    expect(page.locator("#toast")).to_contain_text("Publish a diagnostic report to the customer")
    page.get_by_label("New status").select_option("intake")
    page.get_by_role("button", name="Update status").click()
    expect(page.locator(".case-history li").first).to_contain_text("Report sent")

    # link the customer's assessment, see its documents, then the activity trail
    page.get_by_role("tab", name=re.compile("Assessments")).click()
    page.get_by_label("Assessment to link").select_option(assessment)
    page.get_by_role("button", name="Link assessment").click()
    expect(page.locator(".uc-card", has_text="Retail banking AI")).to_contain_text("ai-register.txt")
    page.get_by_role("tab", name="Activity").click()
    for action in ("case.created", "case.status.intake", "case.assessment_linked"):
        expect(page.locator("td", has_text=action).first).to_be_visible()

    page.goto(page.url.split("#")[0] + "#/cases")
    expect(page.get_by_role("link", name=title).first).to_be_visible()
    page.get_by_placeholder("Search cases or customers").fill(title)
    expect(page.locator("tbody tr")).to_have_count(1)
    page.get_by_role("button", name=re.compile(r"^Intake")).click()
    expect(page.locator("tbody tr")).to_have_count(1)


def test_cases_are_staff_only_and_acl_scoped(as_user, api):
    case = api("architect@cloudseals", "POST", "/v1/cases", {"title": "Private case", "customer_name": "Acme", "architects": []})
    rev = as_user("reviewer@cloudseals", f"case/{case['case_id']}")
    expect(rev.locator("main")).to_contain_text("Something went wrong")                  # reviewer is not assigned: it does not exist for them


def test_users_page_owner_and_self_protection(as_user, api):
    page = as_user("architect@cloudseals", "users")
    me = page.locator("tr", has_text="architect@cloudseals")
    expect(me.get_by_text("you", exact=True)).to_be_visible()
    expect(me.get_by_role("button", name="Remove")).to_be_disabled()
    expect(page.get_by_text("needs Google sign-in")).to_be_visible()                      # email pre-registration is Google-only
    expect(page.get_by_role("button", name="Add user")).to_be_disabled()
    reviewer = page.locator("tr", has_text="reviewer@cloudseals")
    reviewer.get_by_role("button", name="Edit roles").click()
    expect(reviewer.locator(".user-edit")).to_be_visible()
    reviewer.get_by_role("button", name="Cancel").click()
    expect(reviewer.locator(".user-edit")).to_be_hidden()
    reviewer.get_by_role("button", name="Make owner").click()
    try:
        expect(page.locator("tr", has_text="reviewer@cloudseals").get_by_text("Owner (all CloudSeals roles)")).to_be_visible()
    finally:       # the server is shared by every test: put the demo reviewer back
        api("architect@cloudseals", "PATCH", "/v1/admin/users/reviewer@cloudseals", {"roles": ["cloudseals_reviewer"]})


def test_only_admins_open_the_users_page(as_user):
    page = as_user("reviewer@cloudseals", "users")
    expect(page.get_by_text("do not have access")).to_be_visible()


def test_audit_logs_filter_page_and_export(as_user, api, assessment, tmp_path):
    api("architect@cloudseals", "POST", "/v1/cases", {"title": "Audit trail case", "customer_name": "Acme"})
    page = as_user("architect@cloudseals", "activity")
    expect(page.locator("tbody tr").first).to_be_visible()
    expect(page.locator(".case-filters .chip", has_text="case")).to_be_visible()
    with page.expect_response(lambda response: '/v1/admin/activity?' in response.url and 'action=case.' in response.url) as filtered:
        page.locator(".case-filters .chip", has_text=re.compile(r"^case")).click()
    count = len(filtered.value.json()['items'])
    assert count > 0
    expect(page.locator(".audit-action")).to_have_text([re.compile(r"^case\.")] * count)
    page.get_by_placeholder("Search action, reference or person").fill("zzz-no-such-event")
    page.get_by_placeholder("Search action, reference or person").press("Enter")
    expect(page.get_by_text("No events match these filters.")).to_be_visible()
    page.get_by_placeholder("Search action, reference or person").fill("")
    page.get_by_placeholder("Search action, reference or person").press("Enter")
    with page.expect_download() as dl:
        page.get_by_role("button", name="Export CSV").click()
    text = open(dl.value.path(), encoding="utf-8").read()
    assert text.startswith("when_utc,actor,email,tenant,action,reference") and "case.created" in text


def test_service_health_page_and_live_checks(as_user):
    page = as_user("architect@cloudseals", "service-health")
    for card in ("Service", "Application state", "Evidence storage", "Malware scanning", "AI model", "Evidence signing", "Agents, last 24 hours", "Records"):
        expect(page.locator(".health-card h3", has_text=card).first).to_be_visible()
    expect(page.locator(".health-card", has_text="AI model")).to_contain_text("none (deterministic agents only)")
    page.get_by_role("button", name="Run live checks").click()
    expect(page.get_by_role("button", name="Run live checks")).to_be_enabled()
    assert page.errors == []


def test_customer_workspaces_are_read_only_for_staff(as_user, assessment):
    page = as_user("reviewer@cloudseals", "workspaces")
    page.get_by_role("link", name=re.compile("Demo Bank")).click()
    expect(page.get_by_text("Read-only assessment view for CloudSeals staff.", exact=False)).to_be_visible()
    expect(page.get_by_role("heading", name=re.compile(r"^\d+ assessments?$")).first).to_be_visible()
    expect(page.get_by_role("link", name="Open run →")).to_have_count(0)
    expect(page.get_by_role("button", name="Approve", exact=True)).to_have_count(0)
    assert page.errors == []
