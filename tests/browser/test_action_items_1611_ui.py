"""Console action items 16/11: bulk approvals, the named approver, plain explanations (Test a decision, Verify the whole
evidence chain, Recent changes), one date format, TrustTwin scrolling, and links from LedgerSight opening signed in."""
import json
import re
import uuid

from playwright.sync_api import expect

DATE_TIME = re.compile(r"\b\d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4}, \d{2}:\d{2}\b")


def _app(api):
    return api("admin@t-bank", "POST", "/v1/integrations", {"name": f"LS {uuid.uuid4().hex[:6]}"})["trustops_key"]


def _send(api, key, title, who="staff-preparer", assign_to=None, facts=True):
    body = {"actor": {"type": "human", "id": who}, "action": "submit_for_review", "client": "client-a", "amount_minor": 90_000, "currency": "USD",
            "title": title, **({"facts": [{"label": "Bank line", "value": "900.00"}]} if facts else {}), **({"assign_to": assign_to} if assign_to else {})}
    return api("admin@t-bank", "POST", "/v1/decisions", body, headers={"X-TrustOps-Key": key})["decision_id"]


def test_bulk_select_all_approve_and_report_what_could_not_be_done(as_user, api):
    key = _app(api)
    tag = uuid.uuid4().hex[:5]
    ok = [_send(api, key, f"Bulk {tag} ok {i}") for i in range(2)]
    _send(api, key, f"Bulk {tag} elsewhere", assign_to="controller2@t-bank")
    page = as_user("controller@t-bank", "approvals")
    expect(page.get_by_role("heading", name=re.compile("Waiting for your approval"))).to_be_visible()
    buttons = page.get_by_role("group", name="Act on selected items")
    expect(buttons.get_by_role("button", name="Approve selected")).to_be_disabled()             # nothing selected yet
    for title in (f"Bulk {tag} ok 0", f"Bulk {tag} ok 1", f"Bulk {tag} elsewhere"):
        page.get_by_role("checkbox", name=f"Select {title}").check()
    expect(page.locator(".ap-count")).to_have_text("3 selected")
    buttons.get_by_role("button", name="Approve selected").click()
    expect(page.locator(".ap-bulk-msg")).to_contain_text("Write one reason first")
    page.get_by_role("textbox", name="Reason for the selected items").fill("Checked against the bank letter")
    page.once("dialog", lambda d: d.accept())
    buttons.get_by_role("button", name="Approve selected").click()
    msg = page.locator(".ap-bulk-msg")
    expect(msg).to_contain_text("Approved: 2 of 3.")
    expect(msg).to_contain_text(f"Bulk {tag} elsewhere: This item is assigned to controller2@t-bank")
    for did in ok:
        assert api("admin@t-bank", "GET", f"/v1/decisions/{did}")["resolution"]["reason"] == "Checked against the bank letter"
    # Select all ticks every item shown
    page.get_by_role("checkbox", name="Select all").check()
    n = page.locator(".ap-pick").count()
    expect(page.locator(".ap-count")).to_have_text(f"{n} selected")
    assert page.errors == []


def test_review_page_says_who_must_decide_and_hides_the_requester(as_user, api):
    key = _app(api)
    did = _send(api, key, f"Named {uuid.uuid4().hex[:5]}", who="controller@t-bank", assign_to="controller2@t-bank")
    page = as_user("admin@t-bank", f"approval/{did}")
    expect(page.get_by_text("Assigned to controller2@t-bank.")).to_be_visible()
    expect(page.get_by_role("button", name="Approve", exact=True)).to_be_disabled()
    expect(page.get_by_role("button", name="Reject", exact=True)).to_be_disabled()
    options = page.locator("#ap-assign option").all_text_contents()
    assert not any(o.startswith("controller@t-bank") for o in options)                          # the sender is never offered
    assert page.errors == []


def test_plain_explanations_and_one_date_format(as_user, api):
    key = _app(api)
    _send(api, key, f"Dates {uuid.uuid4().hex[:5]}")
    page = as_user("admin@t-bank", "policies")
    expect(page.get_by_text("What it is for:")).to_be_visible()
    expect(page.get_by_text("nothing is sent to any application and nothing is approved", exact=False)).to_be_visible()
    page.get_by_label("Action").fill("ledger.post")
    page.get_by_role("button", name="Test decision").click()
    expect(page.locator(".tb-result")).to_contain_text("Simulated · not counted")

    page.goto(page.url.split("#")[0] + "#/evidence")
    expect(page.get_by_role("heading", name="Is the evidence intact?")).to_be_visible()
    expect(page.get_by_text("so there is nothing to select", exact=False)).to_be_visible()
    page.get_by_role("button", name="Verify the whole evidence chain").click()
    out = page.locator(".ev-verify-out")
    expect(out).to_contain_text(re.compile(r"Intact\. All \d+ records were checked"))
    expect(out).to_contain_text("Latest record hash")
    assert DATE_TIME.search(out.inner_text())

    page.goto(page.url.split("#")[0] + "#/decisions")
    expect(page.locator(".gov-table tbody tr").first).to_be_visible()
    first = page.locator(".gov-table tbody tr td").first.inner_text()
    assert re.match(r"\d{1,2} [A-Z][a-z]{2} \d{4}\s+\d{2}:\d{2}$", first.strip()), first   # "16 Nov 2026" / "14:05", not 16/11/2026, 14:05:33
    assert page.errors == []


def test_authority_recent_changes_read_as_sentences(as_user, api):
    key = _app(api)
    api("admin@t-bank", "POST", "/v1/decisions", {"actor": {"type": "agent", "id": "agent:probe"}, "action": "query.answer"}, headers={"X-TrustOps-Key": key})
    aid = next(a["id"] for a in api("admin@t-bank", "GET", "/v1/authority")["agents"] if a["actor_id"] == "agent:probe")
    api("admin@t-bank", "PATCH", f"/v1/authority/agents/{aid}", {"status": "suspended", "reason": "Probe test"})
    page = as_user("admin@t-bank", "authority")
    changes = page.locator(".au-changes")
    expect(changes).to_contain_text(re.compile(r"Suspended agent:probe in LS \w+ — reason: Probe test"))
    expect(changes.locator("li").first.locator(".au-who")).to_contain_text("admin@t-bank")
    assert DATE_TIME.search(changes.locator("li").first.inner_text())
    assert "authority.agent." not in changes.inner_text()
    assert page.errors == []


def test_trusttwin_conversation_scrolls_and_the_question_box_stays_visible(as_user):
    """16/11 "scrolling is not working properly in the TrustOps chatbot": at the end of the conversation the mouse wheel
    scrolled the page behind the panel instead (on the Decisions page the window moved 127 px), and long answers were
    shown from their end. Now the wheel stays in the panel and the newest answer is in view from its question."""
    page = as_user("admin@t-bank", "decisions", width=1280, height=620)
    expect(page.get_by_role("heading", name="Decisions", exact=True)).to_be_visible()
    page.get_by_role("button", name=re.compile("TrustTwin")).click()
    box = page.get_by_role("textbox", name="Question")
    scroll = page.locator("#ask-scroll")
    for q in ["What is waiting for approval?", "Give me a summary", "What was blocked today?", "What does FIN-04 do?",
              "Is the evidence chain intact?", "What was rejected?"]:
        box.fill(q)
        box.press("Enter")
        expect(page.locator("#ask-out .qa").last.locator(".typing")).to_have_count(0)
        page.wait_for_timeout(50)
        last = page.locator("#ask-out .qa").last.locator(".q-bubble")
        top, box_top, box_bottom = last.evaluate("e => [e.getBoundingClientRect().top, ...(r => [r.top, r.bottom])(document.getElementById('ask-scroll').getBoundingClientRect())]")
        assert box_top - 1 <= top < box_bottom, (q, top, box_top, box_bottom)                # the newest question/answer is in the panel
    expect(box).to_be_in_viewport()
    assert scroll.evaluate("s => s.scrollHeight > s.clientHeight")
    bb = scroll.bounding_box()
    page.mouse.move(bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2)
    scroll.evaluate("s => { s.scrollTop = 0; }")
    page.mouse.wheel(0, 600)
    page.wait_for_timeout(300)
    assert scroll.evaluate("s => s.scrollTop") > 0                                            # the wheel scrolls the conversation
    page.mouse.wheel(0, 20000)
    page.wait_for_timeout(300)
    page.mouse.wheel(0, 600)
    page.wait_for_timeout(300)
    assert page.evaluate("scrollY") == 0                                                       # ...and never the page behind it
    assert page.errors == []


def test_link_from_ledgersight_opens_signed_in_on_the_page(browser, base_url, tokens):
    """A new tab opened from LedgerSight shares the sign-in (for under an hour) and lands on the page in the link."""
    ctx = browser.new_context()
    ctx.add_init_script(f"localStorage.setItem('taad_token_shared', JSON.stringify({{token: {json.dumps(tokens['controller@t-bank'])}, at: Date.now()}}));")
    page = ctx.new_page()
    page.goto(f"{base_url}/portal/#/approvals")
    expect(page.get_by_role("heading", name="Approvals", exact=True)).to_be_visible()
    expect(page.locator(".role-pill")).to_contain_text("Approver")                             # the shared sign-in, not the dev fallback
    ctx.close()
    old = browser.new_context()                                                                 # more than an hour old: not used
    old.add_init_script("localStorage.setItem('taad_token_shared', " + json.dumps(json.dumps({"token": tokens["controller@t-bank"], "at": 1})) + ");")
    p2 = old.new_page()
    p2.goto(f"{base_url}/portal/#/approvals")
    expect(p2.locator(".role-pill")).to_contain_text("Administrator")                          # dev mode falls back to its local admin
    old.close()
