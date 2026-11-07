"""The two canonical URL forms share one parser and differ only where documented."""

import pytest

from src.core.source_urls import attestation_match_key, canonical_source_url, parse_http_url


@pytest.mark.parametrize(
    "value",
    ["", "   ", None, "ftp://example.org/file", "mailto:analyst@example.org", "/relative/path"],
)
def test_both_forms_reject_non_http_values(value):
    assert parse_http_url(value) is None
    assert canonical_source_url(value) == ""
    assert attestation_match_key(value) == ""


def test_both_forms_lowercase_the_host_and_drop_the_fragment():
    url = "HTTPS://Research.Vendor.COM/Report#section-2"

    assert canonical_source_url(url) == "https://research.vendor.com/Report"
    assert attestation_match_key(url) == "research.vendor.com/Report"


def test_stored_identity_keeps_the_scheme_but_attestation_ignores_it():
    assert canonical_source_url("http://vendor.com/a") != canonical_source_url(
        "https://vendor.com/a"
    )
    assert attestation_match_key("http://vendor.com/a") == attestation_match_key(
        "https://vendor.com/a"
    )


def test_stored_identity_keeps_a_trailing_slash_but_attestation_ignores_it():
    assert canonical_source_url("https://vendor.com/a/") == "https://vendor.com/a/"
    assert attestation_match_key("https://vendor.com/a/") == attestation_match_key(
        "https://vendor.com/a"
    )


def test_stored_identity_keeps_tracking_parameters_but_attestation_drops_them():
    url = "https://vendor.com/a?utm_source=x&id=7&fbclid=y&gclid=z"

    assert canonical_source_url(url) == url
    assert attestation_match_key(url) == "vendor.com/a?id=7"


def test_stored_identity_keeps_query_order_but_attestation_sorts_it():
    assert canonical_source_url("https://vendor.com/a?b=2&a=1") == "https://vendor.com/a?b=2&a=1"
    assert attestation_match_key("https://vendor.com/a?b=2&a=1") == attestation_match_key(
        "https://vendor.com/a?a=1&b=2"
    )
