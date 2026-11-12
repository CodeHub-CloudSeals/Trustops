from playwright.sync_api import expect


def test_overview_has_no_product_tour_but_keeps_the_customer_workflow(as_user):
    page = as_user("admin@t-bank", "assessment-overview")

    expect(page.get_by_role("heading", name="AI oversight. A clear next step.")).to_be_visible()
    expect(page.get_by_role("button", name="Product tour")).to_have_count(0)
    expect(page.locator(".product-tour-guide")).to_have_count(0)
    expect(page.get_by_role("dialog")).to_have_count(0)

    flow = page.locator(".workflow-infographic")
    expect(flow.get_by_role("heading", name="How a TrustOps assessment works")).to_be_visible()
    for stage in ("Define the AI system", "Share evidence", "Check evidence", "Human review", "Get the report"):
        expect(flow.get_by_role("heading", name=stage)).to_be_visible()

    assert page.errors == []
