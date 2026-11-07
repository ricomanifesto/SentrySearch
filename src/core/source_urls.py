"""One HTTP URL parser with two named canonical forms.

Source URLs are compared for two different purposes, and the purposes need
different equivalence rules:

``canonical_source_url``
    The stored identity of a researched source. It is what request-local source
    IDs are assigned to, what ``webSearchSources.primarySources`` persists, and
    what the persist-time ledger consistency gate compares. It must never change
    a URL that a retained report already stores, so it only removes what is not
    part of the resource identity: the fragment, plus scheme and host case.
    The path, trailing slash, and query string are kept exactly.

``attestation_match_key``
    A comparison key used only while attesting model-cited URLs against the
    researched catalog. Models routinely drop the scheme, add or remove a
    trailing slash, reorder query parameters, or keep marketing parameters, so
    this key ignores the scheme, trailing slashes, query order, ``utm_*``,
    ``fbclid``, and ``gclid``. It is never stored or rendered.

Both reject anything that is not an absolute ``http`` or ``https`` URL with a
network location. ``tests/test_source_urls.py`` pins every rule that differs.
"""

from __future__ import annotations

from urllib.parse import SplitResult, parse_qsl, urlencode, urlsplit, urlunsplit

_TRACKING_PARAMETERS = frozenset({"fbclid", "gclid"})
_TRACKING_PREFIX = "utm_"


def parse_http_url(value: object) -> SplitResult | None:
    """Return the split URL when ``value`` is an absolute HTTP(S) URL."""

    candidate = str(value or "").strip()
    if not candidate:
        return None
    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return None
    return parts


def canonical_source_url(value: object) -> str:
    """Return the stored source identity, or an empty string when invalid."""

    parts = parse_http_url(value)
    if parts is None:
        return ""
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path or "", parts.query, "")
    )


def attestation_match_key(value: object) -> str:
    """Return the tolerant attestation comparison key, or an empty string."""

    parts = parse_http_url(value)
    if parts is None:
        return ""
    path = parts.path.rstrip("/") or "/"
    query = urlencode(
        sorted(
            (key, item)
            for key, item in parse_qsl(parts.query, keep_blank_values=True)
            if not key.lower().startswith(_TRACKING_PREFIX)
            and key.lower() not in _TRACKING_PARAMETERS
        )
    )
    suffix = f"?{query}" if query else ""
    return f"{parts.netloc.lower()}{path}{suffix}"
