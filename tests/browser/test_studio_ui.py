import re

from playwright.sync_api import expect

REASON = "Checked against the source document"


def validate_first(page, scope):
    box = scope.locator(".uc-review input").first
    box.fill(REASON)
    scope.get_by_role("button", name="Validate").first.click()


def test_customer_sees_use_cases_but_no_reviewer_material(as_user, assessment):
    page = as_user("admin@t-bank", f"use-cases/{assessment}")
    page.get_by_role("button", name="Find AI use cases in the documents").click()
    expect(page.locator(".uc-card")).to_have_count(2)
    expect(page.get_by_role("heading", name="Credit scoring model")).to_be_visible()
    expect(page.get_by_text("credit scoring model assigns loan applicants a score").first).to_be_visible()     # verbatim evidence is shown
    expect(page.get_by_text("Low confidence")).to_be_visible()                                                 # 55% candidate is flagged
    expect(page.get_by_text("follow reviewer approval")).to_be_visible()                                # gaps are reviewer-only
    expect(page.get_by_role("button", name="Validate")).to_have_count(0)                                       # customers cannot validate
    expect(page.locator(".pipe-steps")).to_have_count(0)
    assert page.errors == []


def test_reviewer_runs_the_whole_pipeline_to_a_final_report(as_user, api, assessment):
    api("admin@t-bank", "POST", f"/v1/assessments/{assessment}/inventory/run", {})
    page = as_user("reviewer@cloudseals", f"use-cases/{assessment}")
    expect(page.locator(".uc-card")).to_have_count(2)
    expect(page.locator(".pipe-steps li.is-done")).to_have_count(0)

    # step 1: validate the first use case
    validate_first(page, page.locator(".uc-card").first)
    expect(page.locator(".uc-card").first.get_by_text("Validated", exact=True)).to_be_visible()
    expect(page.locator(".pipe-steps li.is-done")).to_have_count(1)

    # step 2: gap analysis -> candidate gap with a real requirement ID -> validate
    page.get_by_role("button", name="Run gap analysis").click()
    gap = page.locator(".uc-gap").first
    expect(gap).to_contain_text("Article 5")
    expect(gap.get_by_text("CRITICAL")).to_be_visible()
    validate_first(page, gap)
    expect(gap.get_by_text("Validated", exact=True)).to_be_visible()

    # step 3: maturity: overall is computed, an unevidenced 3.0 is capped at 2.0
    page.get_by_role("button", name="Run maturity scoring").click()
    expect(page.locator(".mat-overall")).to_have_text("1.6")
    expect(page.get_by_text("were capped at 2.0")).to_be_visible()
    panel = page.locator("section", has=page.get_by_role("heading", name="Governance maturity"))
    validate_first(page, panel)
    expect(panel.get_by_text("Validated", exact=True)).to_be_visible()

    # step 4: roadmap: a critical gap forces the item into the first 90 days
    page.get_by_role("button", name="Build roadmap").click()
    road = page.locator("section", has=page.get_by_text("STEP 4 · ROADMAP AGENT"))
    expect(road.get_by_role("heading", name="0 to 90 days")).to_be_visible()
    expect(road.get_by_text("Moved into the first 90 days")).to_be_visible()
    validate_first(page, road)

    # step 5: the report is FINAL and downloads, containing only reviewed material
    expect(page.locator(".pipe-steps li.is-done")).to_have_count(5)
    report = page.locator("section", has=page.get_by_text("STEP 5 · REPORT"))
    expect(report.get_by_text("FINAL", exact=True)).to_be_visible()
    with page.expect_download() as dl:
        report.get_by_role("button", name="Download report (HTML)").click()
    text = open(dl.value.path(), encoding="utf-8").read()
    assert dl.value.suggested_filename.endswith("FINAL.html")
    assert "Retail banking AI" in text and "Credit scoring model" in text and "No documented Article 5" in text and "DRAFT" not in text
    assert "Customer service chatbot" not in text                      # the unvalidated candidate never reaches the report
    assert page.errors == []

    # Final preview does not expose the result to a customer until a reviewer publishes it.
    customer = as_user("admin@t-bank", f"use-cases/{assessment}")
    expect(customer.get_by_role("button", name="Download published report (HTML)")).to_have_count(0)
    expect(customer.get_by_text("after publication", exact=False)).to_be_visible()
    report.get_by_label("Final report review reason").fill("Final report and roadmap checked against evidence")
    report.get_by_role("button", name="Publish report to customer").click()
    expect(page.get_by_text("This reviewed material is already published to the customer.")).to_be_visible()
    expect(page.get_by_role("button", name="Publish report to customer")).to_be_disabled()
    customer.reload()
    expect(customer.get_by_role("heading", name="Your report and improvement roadmap")).to_be_visible()
    expect(customer.get_by_role("heading", name="Run and document an Article 5 screening", exact=True)).to_be_visible()
    expect(customer.get_by_role("button", name="Publish report to customer")).to_have_count(0)
    with customer.expect_download() as delivered:
        customer.get_by_role("button", name="Download published report (HTML)").click()
    released = open(delivered.value.path(), encoding="utf-8").read()
    assert "Credit scoring model" in released and "Customer service chatbot" not in released
    assert customer.errors == []


def test_report_stays_draft_until_everything_is_validated(as_user, api, assessment):
    api("admin@t-bank", "POST", f"/v1/assessments/{assessment}/inventory/run", {})
    page = as_user("reviewer@cloudseals", f"use-cases/{assessment}")
    report = page.locator("section", has=page.get_by_text("STEP 5 · REPORT"))
    expect(report.get_by_text("DRAFT", exact=True)).to_be_visible()
    expect(report).to_contain_text("no validated AI use cases")
    expect(page.get_by_role("button", name="Run gap analysis")).to_be_disabled()                  # gated on a validated use case
    expect(page.get_by_role("button", name="Run maturity scoring")).to_be_disabled()
    expect(page.get_by_role("button", name="Build roadmap")).to_be_disabled()


def test_rejecting_a_use_case_is_recorded_and_excluded(as_user, api, assessment):
    api("admin@t-bank", "POST", f"/v1/assessments/{assessment}/inventory/run", {})
    page = as_user("reviewer@cloudseals", f"use-cases/{assessment}")
    card = page.locator(".uc-card").nth(1)
    card.locator(".uc-review input").fill("Duplicate of another entry")
    card.get_by_role("button", name="Reject").click()
    expect(card.get_by_text("Rejected", exact=True)).to_be_visible()
    expect(card).to_contain_text(re.compile("Rejected by reviewer@cloudseals: Duplicate"))


def test_frameworks_library_is_read_only_and_marked_unreviewed(as_user):
    page = as_user("admin@t-bank", "frameworks")
    expect(page.get_by_text("PENDING LEGAL REVIEW")).to_have_count(5)
    page.get_by_role("link", name=re.compile("EU AI Act")).click()
    expect(page.get_by_text("Not legal advice")).to_be_visible()
    page.locator(".fw-req summary", has_text="Prohibited AI Practices").click()
    expect(page.get_by_text("Article_5.C1")).to_be_visible()


def test_architecture_overlay_is_drawn_reviewed_and_joins_the_report(as_user, api, assessment):
    api("admin@t-bank", "POST", f"/v1/assessments/{assessment}/inventory/run", {})
    page = as_user("reviewer@cloudseals", f"use-cases/{assessment}")
    panel = page.locator("section", has=page.get_by_text("OPTIONAL · ARCHITECTURE OVERLAY"))
    expect(panel.get_by_role("button", name="Draw architecture")).to_be_disabled()               # needs a validated use case first
    validate_first(page, page.locator(".uc-card").first)
    panel.get_by_role("button", name="Draw architecture").click()
    current = panel.get_by_role("img", name=re.compile("Current architecture"))
    target = panel.get_by_role("img", name=re.compile("Recommended target"))
    expect(current).to_be_visible()
    expect(target).to_be_visible()
    assert page.evaluate("[...document.querySelectorAll('.overlay-img')].every(i => i.naturalWidth > 100)")      # the SVGs really render
    expect(panel.get_by_text("dashed boxes are things the documents do not evidence")).to_be_visible()
    expect(panel.get_by_text("Items marked unknown")).to_be_visible()                           # the un-evidenced node is flagged, not asserted
    expect(panel.get_by_text("Current: direct model call")).to_be_visible()
    validate_first(page, panel)
    expect(panel.get_by_text("Validated", exact=True)).to_be_visible()
    expect(page.locator(".pipe-steps li.optional.is-done")).to_have_count(1)
    report = page.locator("section", has=page.get_by_text("STEP 5 · REPORT"))
    with page.expect_download() as dl:
        report.get_by_role("button", name="Download report (HTML)").click()
    text = open(dl.value.path(), encoding="utf-8").read()
    assert "Architecture overlay" in text and "data:image/svg+xml;base64," in text and "<script" not in text
