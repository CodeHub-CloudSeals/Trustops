from playwright.sync_api import expect


def test_ledgersight_poc_is_truthful_and_shows_the_four_controlled_scenarios(as_user):
    page = as_user("admin@t-bank", "ledger-sight")
    expect(page.get_by_role("heading", name="LedgerSight AR/Cash")).to_be_visible()
    expect(page.get_by_text("SAMPLE DATA · CONTROLLED WORKFLOW")).to_be_visible()
    expect(page.get_by_text("No bank account, real payment, or customer ERP is accessed or changed.")).to_be_visible()
    for label in ("Exact match", "Ambiguous match", "High-value match", "No match"):
        expect(page.get_by_role("heading", name=label)).to_be_visible()
    assert page.errors == []


def test_ledgersight_exact_match_runs_policy_prepare_mock_and_evidence(as_user):
    page = as_user("admin@t-bank", "ledger-sight")
    page.get_by_role("button", name="Run exact-match scenario").click()
    expect(page.get_by_role("heading", name="Six-step agent trace")).to_be_visible(timeout=30_000)
    expect(page.locator(".ledger-agent-trace li")).to_have_count(6)
    expect(page.get_by_text("Policy allows preparation")).to_be_visible()
    page.get_by_role("button", name="Prepare with evidence").click()
    page.get_by_role("button", name="Run controlled action").click()
    expect(page.locator("#toast")).to_contain_text("Controlled action completed through mock_sap.")
    page.get_by_role("button", name="Verify run evidence").click()
    expect(page.locator("#toast")).to_contain_text("Evidence verified (local_hash_chain_only).")
    assert page.errors == []


def test_ledgersight_high_value_requires_a_separate_controller(as_user):
    maker = as_user("admin@t-bank", "ledger-sight")
    maker.get_by_role("button", name="Run high-value scenario").click()
    expect(maker.get_by_text("Waiting for a separate customer controller.")).to_be_visible(timeout=30_000)
    run_id = maker.url.rsplit("/", 1)[-1]
    expect(maker.get_by_role("button", name="Approve proposal")).to_have_count(0)

    controller = as_user("controller@t-bank", f"ledger-sight/{run_id}")
    expect(controller.get_by_role("heading", name="Controller approval required")).to_be_visible()
    controller.get_by_label("Controller decision reason").fill("Verified against the synthetic remittance advice.")
    controller.get_by_role("button", name="Approve proposal").click()
    expect(controller.get_by_role("button", name="Prepare with evidence")).to_be_visible()
    assert maker.errors == [] and controller.errors == []
