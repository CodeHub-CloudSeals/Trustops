"""Bounded, anonymous HTTP page inspection. No JavaScript, credentials or browser actions.

Resolve and pin a public destination for every redirect; never use proxy environment variables.
Only selected response metadata is exported. The response body is hashed, never retained.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_BYTES = 1_000_000
MAX_SECONDS = 20
HEADERS = ('content-security-policy', 'strict-transport-security', 'x-content-type-options',
           'x-frame-options', 'referrer-policy', 'permissions-policy')


class InspectionError(ValueError):
    pass


class PageParser(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url, self.elements, self.scripts, self.title = url, 0, [], ''
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        self.elements += 1
        if tag == 'title':
            self.in_title = True
        if tag == 'script' and len(self.scripts) < 200:
            src = dict(attrs).get('src')
            if src:
                try:
                    u = clean_url(urljoin(self.url, src))
                except (ValueError, InspectionError):
                    return
                self.scripts.append({'url': u, 'reported_hash': None})

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title = (self.title + data)[:300]


def normalize_website_url(value):
    value = value.strip()
    if value.startswith('//'):
        value = 'https:' + value
    elif not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', value) or re.match(r'^[^/?#]+:\d+(?:[/#?]|$)', value):
        value = 'https://' + value
    return clean_url(value)


def clean_url(value):
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or '\\' in value:
        raise InspectionError('Use an HTTP(S) URL without spaces or control characters.')
    try:
        u = urlsplit(value)
        port = u.port
        host = u.hostname
        if u.scheme not in ('http', 'https') or not host or u.username is not None or u.password is not None:
            raise ValueError()
        if port not in (None, 80 if u.scheme == 'http' else 443):
            raise InspectionError('Only public web ports 80 and 443 are supported.')
        host = host.encode('idna').decode('ascii')
        # A trailing dot is valid DNS; normalize it before checking/resolving.
        host = host.rstrip('.').lower()
        if not host or '%' in host:
            raise ValueError()
        netloc = '[' + host + ']' if ':' in host else host
        return urlunsplit((u.scheme, netloc, u.path or '/', '', ''))
    except InspectionError:
        raise
    except (ValueError, UnicodeError):
        raise InspectionError('Enter a valid public HTTP(S) website URL without login credentials.') from None


def public_address(host, port):
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise InspectionError('The website hostname could not be resolved.') from None
    addresses = list(dict.fromkeys(a[4][0] for a in answers))
    if not addresses or any(not ipaddress.ip_address(a).is_global or ipaddress.ip_address(a).is_multicast for a in addresses):
        raise InspectionError('Use a public website. Local, private and cloud metadata addresses are blocked.')
    return addresses[0]


class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, address, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class PinnedHTTPS(PinnedHTTP):
    def connect(self):
        super().connect()
        raw = self.sock
        try:
            self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def fetch_page(url, timeout):
    deadline = time.monotonic() + timeout
    u = urlsplit(url)
    port = 443 if u.scheme == 'https' else 80
    address = public_address(u.hostname, port)
    connection = (PinnedHTTPS if u.scheme == 'https' else PinnedHTTP)(u.hostname, address, port, timeout)
    try:
        connection.request('GET', u.path or '/', headers={'User-Agent': 'CloudSeals-TrustOps-WebsiteInspector/1.0',
                           'Accept': 'text/html,application/xhtml+xml', 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        headers = {name.lower(): value for name, value in response.getheaders()}
        if response.status in (301, 302, 303, 307, 308):
            return response.status, headers, b''
        if headers.get('content-encoding', 'identity').lower() not in ('identity', ''):
            raise InspectionError('The site returned compressed content that this inspector cannot process.')
        content_type = headers.get('content-type', '').split(';')[0].strip().lower()
        if content_type not in ('text/html', 'application/xhtml+xml'):
            raise InspectionError('This URL did not return an HTML page. Enter the website page URL.')
        content = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InspectionError('The website took too long to respond. No partial result was attached.')
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(65_536, MAX_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > MAX_BYTES:
                raise InspectionError('The page exceeds the 1 MB inspection limit. No partial result was attached.')
        content = bytes(content)
        return response.status, headers, content
    finally:
        connection.close()


def inspect_website(value):
    start = datetime.now(timezone.utc)
    deadline = time.monotonic() + MAX_SECONDS
    url = normalize_website_url(value)
    requests, visited = [], set()
    try:
        for _ in range(5):
            if url in visited:
                raise InspectionError('The website has a redirect loop.')
            visited.add(url)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InspectionError('The website took too long to respond. Try again later.')
            status, headers, content = fetch_page(url, min(remaining, 8))
            requests.append({'url': url, 'method': 'GET', 'status': status})
            if status not in (301, 302, 303, 307, 308):
                break
            if not headers.get('location'):
                raise InspectionError('The site returned a redirect without a destination.')
            url = clean_url(urljoin(url, headers['location']))
        else:
            raise InspectionError('The website exceeded the redirect limit.')
    except InspectionError:
        raise
    except (OSError, http.client.HTTPException, UnicodeError):
        raise InspectionError('The website could not be inspected. Check the URL, TLS certificate and site availability.') from None
    if time.monotonic() > deadline:
        raise InspectionError('Inspection timed out. No partial result was attached.')
    parser = PageParser(url)
    parser.feed(content.decode('utf-8', 'replace'))
    end = datetime.now(timezone.utc)
    sha = hashlib.sha256(content).hexdigest()
    return {'schema_version': 'trustops.rea.capture.v1', 'producer': 'trustops-http-inspector', 'producer_version': '1.0',
            'rea_evidence_id': 'ev_' + hashlib.sha256((url + end.isoformat() + sha).encode()).hexdigest(),
            'source_sha256': sha, 'target_url': url, 'started_at': start.isoformat(), 'ended_at': end.isoformat(),
            'observation_ms': max(1, round((end - start).total_seconds() * 1000)), 'dom_nodes': parser.elements,
            'scripts': parser.scripts, 'requests': requests,
            'page': {'title': parser.title.strip(), 'http_status': status, 'content_type': headers.get('content-type', '')[:200],
                     'security_headers': {name: headers[name][:1000] for name in HEADERS if name in headers}},
            'limitations': [
                'Anonymous HTTP page inspection only; JavaScript was not executed and interactive or logged-in journeys were not tested.',
                'HTML element count describes the returned HTML, not the rendered browser DOM.',
                'Script URLs were found in HTML; scripts were not downloaded or executed. Requests list only this page and redirects.',
                'No forms, chatbot prompts, vulnerability probes or authenticated requests were sent.',
                'URL query strings/fragments were excluded. Only selected response headers and a body SHA-256 were retained; HTML body was discarded.',
                'A successful page fetch does not prove that an AI model ran or that the application is secure or compliant.',
            ]}
