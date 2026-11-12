"""Malware scanning through a ClamAV daemon (clamd) over its INSTREAM protocol.

Configure with TAAD_CLAMD_HOST (and optionally TAAD_CLAMD_PORT, default 3310). On Cloud Run clamd runs as a sidecar container, so the
host is 127.0.0.1. When configured the scan is mandatory: if the scanner cannot answer, the upload is rejected (fail closed).
"""
from __future__ import annotations

import os
import socket
import struct
from typing import Optional

CHUNK = 64 * 1024


class ScannerError(RuntimeError):
    pass


class ClamdScanner:
    def __init__(self, host: str, port: int = 3310, timeout: float = 30.0) -> None:
        self.host, self.port, self.timeout = host, port, timeout

    def scan(self, data: bytes) -> tuple[bool, str]:
        """Returns (clean, detail). Raises ScannerError when the daemon cannot give a verdict."""
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                s.settimeout(self.timeout)
                s.sendall(b"zINSTREAM\0")
                for i in range(0, len(data), CHUNK):
                    part = data[i:i + CHUNK]
                    s.sendall(struct.pack(">I", len(part)) + part)
                s.sendall(struct.pack(">I", 0))
                reply = b""
                while not reply.endswith(b"\0") and not reply.endswith(b"\n") and len(reply) < 4096:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    reply += chunk
        except (OSError, struct.error) as exc:
            raise ScannerError(f"scanner unreachable: {exc}") from None
        text = reply.rstrip(b"\0\n").decode("utf-8", "replace")
        if text.endswith("OK"):
            return True, "clean"
        if text.endswith("FOUND"):
            return False, text.split(":", 1)[-1].replace("FOUND", "").strip() or "malware"
        raise ScannerError(f"unexpected scanner reply: {text[:120]}")

    def ping(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=5) as s:
                s.sendall(b"zPING\0")
                return s.recv(16).startswith(b"PONG")
        except OSError:
            return False


def from_env() -> Optional[ClamdScanner]:
    host = os.environ.get("TAAD_CLAMD_HOST", "").strip()
    return ClamdScanner(host, int(os.environ.get("TAAD_CLAMD_PORT", "3310"))) if host else None
