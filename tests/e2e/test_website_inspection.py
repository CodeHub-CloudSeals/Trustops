import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from app import application_evidence as tech
from app import main
from app import website_inspection as web

from tests.conftest import new_assessment

HTML = b'<html><head><title>Owned test page</title><script src="/app.js?secret=excluded"></script></head><body>Hello</body></html>'


def response(url, timeout):
    return 200, {'content-type': 'text/html', 'x-content-type-options': 'nosniff', 'set-cookie': 'private=excluded'}, HTML


@pytest.mark.parametrize('url', ['file:///etc/passwd', 'ftp://example.org/', 'https://u:p@example.org',
                                'http://example.org:8080', 'http://example.org/\r\nHost:x', 'https://example.org\\@localhost/'])
def test_invalid_destinations_are_rejected(url):
    with pytest.raises(web.InspectionError):
        web.clean_url(url)


@pytest.mark.parametrize('address', ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', '::ffff:127.0.0.1', '224.0.0.1'])
def test_all_nonpublic_addresses_are_rejected(monkeypatch, address):
    monkeypatch.setattr(web.socket, 'getaddrinfo', lambda *a, **k: [(0, 0, 0, '', (address, 80))])
    with pytest.raises(web.InspectionError, match='public website'):
        web.public_address('example.org', 80)


def test_mixed_dns_answers_fail_closed_and_public_ip_is_pinned(monkeypatch):
    monkeypatch.setattr(web.socket, 'getaddrinfo', lambda *a, **k: [(0, 0, 0, '', ('93.184.215.14', 80)), (0, 0, 0, '', ('127.0.0.1', 80))])
    with pytest.raises(web.InspectionError):
        web.public_address('example.org', 80)
    monkeypatch.setattr(web.socket, 'getaddrinfo', lambda *a, **k: [(0, 0, 0, '', ('93.184.215.14', 80))])
    assert web.public_address('example.org', 80) == '93.184.215.14'


def test_real_http_page_is_parsed_without_executing_scripts_or_retaining_secrets(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Set-Cookie', 'secret=never-retained')
            self.end_headers()
            self.wfile.write(HTML)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original = web.PinnedHTTP

    class TestConnection(original):
        def __init__(self, host, address, port, timeout):
            super().__init__(host, address, server.server_port, timeout)

    # Only this owned fixture may resolve to loopback. Production resolution/port rules stay unchanged.
    monkeypatch.setattr(web, 'public_address', lambda *a: '127.0.0.1')
    monkeypatch.setattr(web, 'PinnedHTTP', TestConnection)
    try:
        capture = tech.Capture.model_validate(web.inspect_website('http://owned.test/?token=excluded')).model_dump(mode='json')
    finally:
        server.shutdown()
        server.server_close()
    assert capture['page']['title'] == 'Owned test page'
    assert capture['source_sha256'] == hashlib.sha256(HTML).hexdigest()
    assert capture['scripts'] == [{'url': 'http://owned.test/app.js', 'reported_hash': None}]
    assert capture['page']['security_headers'] == {'x-content-type-options': 'nosniff'}
    assert 'secret=' not in json.dumps(capture) and 'token=' not in json.dumps(capture)
    assert len(capture['requests']) == 1
    assert capture['dom_nodes'] == 5


def test_redirects_revalidate_destination_and_limit_loops(monkeypatch):
    calls = []

    def redirected(url, timeout):
        calls.append(url)
        return 302, {'location': 'http://127.0.0.1/'}, b''

    real_fetch = web.fetch_page
    monkeypatch.setattr(web, 'fetch_page', lambda url, timeout: redirected(url, timeout) if len(calls) == 0 else real_fetch(url, timeout))
    with pytest.raises(web.InspectionError, match='public website'):
        web.inspect_website('https://example.org')
    monkeypatch.setattr(web, 'fetch_page', lambda *a: (302, {'location': '/'}, b''))
    with pytest.raises(web.InspectionError, match='redirect loop'):
        web.inspect_website('https://example.org/')


def test_authorized_inspection_attaches_and_publishes_via_existing_evidence_flow(env, monkeypatch):
    c, h = env
    aid = new_assessment(c, h, 'admin@t-bank')
    path = f'/v1/assessments/{aid}'
    calls = []
    monkeypatch.setattr(web, 'fetch_page', lambda u, t: (calls.append(u) or response(u, t)))
    assert c.post(path + '/website-inspection', headers=h('admin@t-bank'), json={'url': 'https://example.org', 'authorized': False}).status_code == 422
    assert not calls
    assert c.post(path + '/website-inspection', headers=h('admin@t-health'), json={'url': 'https://example.org', 'authorized': True}).status_code == 404
    assert c.post(path + '/website-inspection', headers=h('risk@t-bank'), json={'url': 'https://example.org', 'authorized': True}).status_code == 403
    r = c.post(path + '/website-inspection', headers=h('admin@t-bank'), json={'url': 'example.org/?secret=excluded', 'authorized': True})
    assert r.status_code == 200, r.text
    assert calls == ['https://example.org/']
    raw = json.dumps(r.json()['capture']).encode()
    grant = c.post(path + '/evidence/upload-url', headers=h('admin@t-bank'), json={
        'filename': 'website-inspection.json', 'content_type': 'application/json', 'file_size_bytes': len(raw),
        'claimed_sha256': hashlib.sha256(raw).hexdigest()}).json()
    assert c.put(grant['upload_url'], headers=h('admin@t-bank'), content=raw).json()['state'] == 'clean'
    r = c.post(path + '/application-evidence', headers=h('admin@t-bank'), json={'evidence_id': grant['evidence_id']})
    assert r.status_code == 201, r.text
    run = r.json()
    assert any('Owned test page' in o['text'] for o in run['observations'])
    assert run['status'] == 'awaiting_review' and not run['published']
    url = path + '/application-evidence/' + run['run_id']
    assert c.get(url + '/report', headers=h('admin@t-bank')).status_code == 403
    reviewed = c.post(url + '/review', headers=h('reviewer@cloudseals'), json={
        'decision': 'validated', 'reason': 'Checked owned test response', 'source_digest': run['source_digest']}).json()
    published = c.post(url + '/publish', headers=h('reviewer@cloudseals'), json={
        'reason': 'Release checked HTTP observations', 'source_digest': reviewed['source_digest']})
    assert published.status_code == 200, published.text
    report = c.get(url + '/report', headers=h('admin@t-bank'))
    assert 'Public-page HTTP inspection' in report.text and 'Owned test page' in report.text
    assert 'JavaScript was not executed' in report.text
    assert 'Source: REA' not in report.text


def test_failed_inspection_saves_no_evidence_or_report(env, monkeypatch):
    c, h = env
    aid = new_assessment(c, h, 'admin@t-bank')

    def unavailable(*args):
        raise OSError('private connection details not returned')

    monkeypatch.setattr(web, 'fetch_page', unavailable)
    before = len(main.STORE.evidence)
    r = c.post(f'/v1/assessments/{aid}/website-inspection', headers=h('admin@t-bank'), json={'url': 'https://example.org', 'authorized': True})
    assert r.status_code == 422 and 'private connection' not in r.text
    assert len(main.STORE.evidence) == before
    assert not c.get(f'/v1/assessments/{aid}/application-evidence', headers=h('admin@t-bank')).json()['items']


@pytest.mark.parametrize(('entered', 'expected'), [
    ('www.cloudseals.com', 'https://www.cloudseals.com/'),
    ('example.org/path', 'https://example.org/path'),
    ('  example.org  ', 'https://example.org/'),
    ('//example.org/path', 'https://example.org/path'),
    ('example.org:443/path', 'https://example.org/path'),
    ('https://example.org/path', 'https://example.org/path'),
    ('http://example.org/path', 'http://example.org/path'),
    ('x.co', 'https://x.co/'),
])
def test_domain_input_defaults_to_https_and_preserves_explicit_http(entered, expected):
    assert web.normalize_website_url(entered) == expected


@pytest.mark.parametrize('entered', ['javascript:alert(1)', 'data:text/html,test', 'ftp://example.org', 'https:example.org'])
def test_domain_normalization_does_not_convert_forbidden_schemes(entered):
    with pytest.raises(web.InspectionError):
        web.normalize_website_url(entered)
