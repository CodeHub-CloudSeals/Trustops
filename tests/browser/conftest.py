import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

import pytest
from playwright.sync_api import expect

ROOT = Path(__file__).resolve().parents[2]
expect.set_options(timeout=10_000)

DOC = (b"AI Register. Our credit scoring model assigns loan applicants a score and decides approvals automatically. "
       b"The chatbot answers customer questions about accounts.")


@pytest.fixture(scope="session")
def base_url(tmp_path_factory):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    env = {**os.environ, "TAAD_OBJECT_ROOT": str(tmp_path_factory.mktemp("objs")), "TAAD_DB": str(tmp_path_factory.mktemp("db") / "t.db"),
           "PYTHONPATH": os.pathsep.join(str(ROOT / p) for p in ("packages/question-engine", "packages/reporting", "apps/assessment-api", "."))}
    for k in ("TAAD_LLM_PROVIDER", "TAAD_SWASKA_MODEL", "TRUSTOPS_AGENT_MODEL_ID", "TAAD_STATE_GCS_URI", "TAAD_OBJECT_BACKEND"):
        env.pop(k, None)
    proc = subprocess.Popen([sys.executable, str(ROOT / "tests/browser/serve.py"), str(port)], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            urllib.request.urlopen(url + "/health")
            break
        except Exception:
            if proc.poll() is not None:
                raise RuntimeError("server exited: " + proc.stderr.read().decode()[-1500:]) from None
            time.sleep(0.25)
    else:
        proc.kill()
        raise RuntimeError("server did not start")
    yield url
    proc.terminate()


@pytest.fixture(scope="session")
def tokens(base_url):
    users = json.load(urllib.request.urlopen(base_url + "/v1/dev/users"))["items"]
    return {u["sub"]: u["token"] for u in users}


@pytest.fixture()
def api(base_url, tokens):
    def call(sub, method, path, body=None, raw=None, headers=None):
        h = {"Authorization": f"Bearer {tokens[sub]}", "Content-Type": "application/json", "Idempotency-Key": str(uuid.uuid4()), **(headers or {})}
        req = urllib.request.Request(base_url + path, method=method, headers=h, data=raw if raw is not None else (json.dumps(body).encode() if body is not None else None))
        try:
            with urllib.request.urlopen(req) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise AssertionError(f"{method} {path} -> {e.code} {e.read()[:300]}") from None
    return call


@pytest.fixture()
def as_user(browser, base_url, tokens):
    """as_user('reviewer@cloudseals', 'cases') -> a page signed in as that user. Console errors are collected on page.errors."""
    contexts = []

    def open_page(sub, route="", width=1440, height=900, scheme="light"):
        ctx = browser.new_context(viewport={"width": width, "height": height}, color_scheme=scheme, accept_downloads=True)
        if sub:
            ctx.add_init_script(f"sessionStorage.setItem('taad_token','{tokens[sub]}');")
        contexts.append(ctx)
        page = ctx.new_page()
        page.errors = []
        page.on("pageerror", lambda e: page.errors.append(str(e)))
        page.on("console", lambda m: page.errors.append(m.text) if m.type == "error" else None)
        page.goto(f"{base_url}/portal/" + (f"#/{route}" if route else ""))
        return page
    yield open_page
    for c in contexts:
        c.close()


@pytest.fixture()
def assessment(api):
    """A fresh T-Bank assessment with the sample AI register uploaded and clean."""
    import hashlib
    aid = api("admin@t-bank", "POST", "/v1/assessments", {"ai_system_name": "Retail banking AI", "industry": "banking", "questionnaire_version": "1.0.0"})["assessment_id"]
    g = api("admin@t-bank", "POST", f"/v1/assessments/{aid}/evidence/upload-url", {"filename": "ai-register.txt", "content_type": "text/plain",
            "file_size_bytes": len(DOC), "claimed_sha256": hashlib.sha256(DOC).hexdigest()})
    api("admin@t-bank", "PUT", g["upload_url"], raw=DOC)
    return aid


@pytest.fixture(scope="session")
def browser(playwright, browser_type, browser_type_launch_args):
    """Opt into an explicitly started dedicated Chrome; otherwise preserve normal Playwright launch."""
    cdp = os.environ.get("TRUSTOPS_TEST_CDP")
    instance = playwright.chromium.connect_over_cdp(cdp) if cdp else browser_type.launch(**browser_type_launch_args)
    yield instance
    instance.close()
