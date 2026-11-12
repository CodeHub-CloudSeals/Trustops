import hashlib
import socketserver
import struct
import threading

import pytest
from app import scanner

from tests.conftest import new_assessment


class FakeClamd(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                cmd = b""
                while not cmd.endswith(b"\0"):
                    cmd += self.request.recv(1)
                if cmd == b"zPING\0":
                    self.request.sendall(b"PONG\0")
                    return
                assert cmd == b"zINSTREAM\0"
                data = b""
                while True:
                    n = struct.unpack(">I", self._read(4))[0]
                    if n == 0:
                        break
                    data += self._read(n)
                outer.seen.append(len(data))
                self.request.sendall(b"stream: Eicar-Test-Signature FOUND\0" if b"EICAR" in data else b"stream: OK\0")

            def _read(self, n):
                buf = b""
                while len(buf) < n:
                    chunk = self.request.recv(n - len(buf))
                    if not chunk:
                        raise ConnectionError
                    buf += chunk
                return buf
        self.seen = []
        super().__init__(("127.0.0.1", 0), Handler)


@pytest.fixture
def clamd():
    srv = FakeClamd()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_instream_protocol_clean_infected_and_chunking(clamd):
    av = scanner.ClamdScanner("127.0.0.1", clamd.server_address[1])
    assert av.scan(b"hello") == (True, "clean")
    ok, detail = av.scan(b"..EICAR..")
    assert ok is False and detail == "Eicar-Test-Signature"
    big = b"a" * (scanner.CHUNK * 3 + 17)                            # several chunks and a ragged tail are reassembled exactly
    assert av.scan(big)[0] is True and clamd.seen[-1] == len(big)
    assert av.ping() is True


def test_scanner_down_raises_instead_of_guessing():
    av = scanner.ClamdScanner("127.0.0.1", 1, timeout=1)
    with pytest.raises(scanner.ScannerError):
        av.scan(b"x")
    assert av.ping() is False


def upload(c, h, aid, data):
    g = c.post(f"/v1/assessments/{aid}/evidence/upload-url", headers=h("admin@t-bank"), json={
        "filename": "doc.txt", "content_type": "text/plain", "file_size_bytes": len(data), "claimed_sha256": hashlib.sha256(data).hexdigest()}).json()
    return c.put(g["upload_url"], headers=h("admin@t-bank"), content=data).json()


def test_uploads_go_through_the_scanner_and_fail_closed(env, clamd, monkeypatch):
    c, h = env
    aid = new_assessment(c, h, "admin@t-bank")
    monkeypatch.setenv("TAAD_CLAMD_HOST", "127.0.0.1")
    monkeypatch.setenv("TAAD_CLAMD_PORT", str(clamd.server_address[1]))
    assert upload(c, h, aid, b"plain notes")["state"] == "clean"
    bad = upload(c, h, aid, b"harmless text but the daemon says EICAR")             # the daemon's verdict wins over our own prefilter
    assert bad["state"] == "infected" and "Eicar-Test-Signature" in bad["reason"]
    monkeypatch.setenv("TAAD_CLAMD_PORT", "1")                                      # daemon unreachable: no verdict, no evidence
    down = upload(c, h, aid, b"another document")
    assert down["state"] == "rejected" and down["reason"] == "malware_scanner_unavailable"


def test_without_a_scanner_behaviour_is_unchanged(env, monkeypatch):
    c, h = env
    monkeypatch.delenv("TAAD_CLAMD_HOST", raising=False)
    aid = new_assessment(c, h, "admin@t-bank")
    assert upload(c, h, aid, b"plain notes")["state"] == "clean"
