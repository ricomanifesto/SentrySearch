"""Shared TLS verification for outbound HTTPS clients."""

from __future__ import annotations

import ssl
from threading import Lock

import httpx

_context_lock = Lock()
_context: ssl.SSLContext | None = None


def default_verify_context() -> ssl.SSLContext:
    """Return HTTPX's default verification context, built once per process.

    Building a context loads and parses the whole CA bundle. Short-lived clients
    that each built their own spent most of source capture doing that. One
    context is safe to share across clients and threads; it keeps the same
    trust settings, including ``SSL_CERT_FILE`` and ``SSL_CERT_DIR``, read when
    it is first built. The lock keeps concurrent first callers from each
    building one.
    """

    global _context
    with _context_lock:
        if _context is None:
            _context = httpx.create_ssl_context()
        return _context
