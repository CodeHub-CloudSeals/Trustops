"""Smoke checks against a deployed environment: DEPLOYED_URL=https://trustops.cloudseals.com pytest tests/browser/test_deployed_smoke.py

Signing in with Google cannot be automated, so these cover everything reachable without a session: the page shell, the sign-in
screen and its configuration, redirects, headers, and that every protected API refuses anonymous callers.
"""
import json
import os
import re
import urllib.error
import urllib.request

import pytest
from playwright.sync_api import expect

URL = os.environ.get("DEPLOYED_URL", "").rstrip("/")
pytestmark = pytest.mark.skipif(not URL, reason="set DEPLOYED_URL to run the deployed-environment smoke test")


def fetch(path, method="GET", follow=True):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(urllib.request.Request(URL + path, method=method), timeout=20)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_health_and_registry():
    status, _, body = fetch("/health")
    d = json.loads(body)
    assert status == 200 and d["status"] == "ok" and d["question_count"] == 318


def test_root_redirects_to_the_portal_and_headers_are_hardened():
    status, headers, _ = fetch("/", follow=False)
    assert status == 302 and {k.lower(): v for k, v in headers.items()}["location"] == "/portal/"
    _, h, _ = fetch("/portal/")
    h = {k.lower(): v for k, v in h.items()}
    assert "script-src 'self'" in h["content-security-policy"] and h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
    assert h["cache-control"] == "no-store"


@pytest.mark.parametrize("path", ["/v1/me", "/v1/cases", "/v1/assessments", "/v1/admin/users", "/v1/admin/activity", "/v1/admin/health",
                                  "/v1/admin/workspaces", "/v1/agents", "/v1/frameworks", "/v1/runs", "/v1/agentops", "/v1/staff"])
def test_protected_apis_refuse_anonymous_callers(path):
    assert fetch(path)[0] == 401


def test_dev_helpers_and_docs_are_not_exposed():
    assert fetch("/v1/dev/users")[0] in (404, 405)
    status, _, body = fetch("/portal/config.json")
    cfg = json.loads(body)
    assert status == 200 and cfg["mode"] == "oidc" and cfg["oidc"]["provider"] == "google" and cfg["oidc"]["client_id"].endswith(".apps.googleusercontent.com")
    assert "client_secret" not in body.decode().lower()


def test_google_callback_forwards_only_oauth_parameters():
    status, headers, _ = fetch("/api/auth/callback/google?code=abc&state=xyz&evil=1", follow=False)
    loc = {k.lower(): v for k, v in headers.items()}["location"]
    assert status == 302 and "code=abc" in loc and "state=xyz" in loc and "evil" not in loc and "/portal/" in loc


def test_token_exchange_rejects_foreign_clients():
    req = urllib.request.Request(URL + "/v1/auth/token", method="POST", data=b"grant_type=authorization_code&client_id=attacker&code=x&code_verifier=y&redirect_uri=https://evil.example/")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=20)
    assert e.value.code == 400


def test_sign_in_screen_renders_and_starts_google_sign_in(page):
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(URL + "/")
    expect(page.get_by_role("heading", name="Sign in to your workspace")).to_be_visible()
    expect(page.locator("body")).to_have_css("background-color", "rgb(246, 248, 252)")
    button = page.get_by_role("button", name=re.compile("Sign in with Google"))
    expect(button).to_be_enabled()
    expect(page.get_by_role("link", name=re.compile("Request workspace access"))).to_be_visible()
    with page.expect_navigation(url=re.compile(r"^https://accounts\.google\.com/")) as nav:
        button.click()
    assert "code_challenge_method=S256" in nav.value.url and "redirect_uri=" in nav.value.url and errors == []


def test_website_inspection_requires_authentication_before_any_fetch():
    request = urllib.request.Request(URL + '/v1/assessments/unassigned/website-inspection', method='POST',
                                     headers={'Content-Type': 'application/json'},
                                     data=json.dumps({'url': 'https://example.org/', 'authorized': True}).encode())
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, timeout=20)
    assert error.value.code == 401


def test_portal_includes_the_url_inspection_form():
    status, _, script = fetch('/portal/app.js')
    assert status == 200 and b'Website URL' in script and b'Inspect website' in script
    assert b'website-inspection' in script and b'Public HTML page and response metadata only' in script


def test_retired_sample_report_points_to_the_actual_report_library():
    status, _, body = fetch('/portal/sample-assessment-report.html')
    assert status == 200 and b'url=./#/reports' in body
    assert b'SYNTHETIC SAMPLE' not in body and b'Example Bank' not in body
