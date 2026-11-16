"""TrustTwin feels like a chat (2026-11-16): a greeting gets a plain friendly reply (no status badge), a greeting in
front of a question still answers the question, and the reply is not labelled as AI-written when no model is on."""
import re

from playwright.sync_api import expect


def test_greeting_is_a_plain_reply_and_questions_still_answer(as_user):
    page = as_user("admin@t-bank", "evidence", width=1440)
    twin = page.get_by_role("button", name=re.compile("TrustTwin"))
    expect(twin).to_be_visible()                                 # the workspace is ready
    twin.click()
    expect(page.locator("#ask-drawer")).to_have_attribute("aria-hidden", "false")
    page.locator("#ask-q").fill("hi")
    page.locator("#ask-q").press("Enter")
    last = page.locator("#ask-out .qa").last
    expect(last.locator(".a-bubble .a")).to_contain_text("Hi! I'm TrustTwin")
    expect(last.locator(".gov-pill")).to_have_count(0)          # small talk: no "No match" badge
    expect(last.locator(".chip").first).to_be_visible()
    page.locator("#ask-q").fill("hello, what was blocked recently?")
    page.locator("#ask-q").press("Enter")
    last = page.locator("#ask-out .qa").last
    expect(last.locator(".gov-pill")).to_be_visible()
    expect(last.locator(".ai-note")).to_have_count(0)            # no model in this test server: the rules wrote it
    assert page.errors == []
