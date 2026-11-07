from datetime import UTC, datetime
import socket

import httpx

from src.core.source_snapshot import (
    MAX_SNAPSHOT_BYTES,
    capture_source_snapshot,
    capture_source_snapshots,
)


def _public_dns(*_args, **_kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


def test_source_snapshot_captures_visible_text_and_fingerprint(monkeypatch):
    monkeypatch.setattr("src.core.source_snapshot.socket.getaddrinfo", _public_dns)

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            text="<html><style>hidden</style><body>Observed <b>Noodle RAT</b> behavior.</body></html>",
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        snapshot = capture_source_snapshot(
            {"url": "https://security.example.test/report", "page_age": "2026-08-14"},
            client=client,
            now=datetime(2026, 8, 15, tzinfo=UTC),
        )

    assert snapshot["status"] == "captured"
    assert snapshot["text"] == "Observed Noodle RAT behavior."
    assert len(snapshot["sha256"]) == 64
    assert snapshot["pageAge"] == "2026-08-14"


def test_owned_snapshot_clients_share_one_verification_context(monkeypatch):
    monkeypatch.setattr("src.core.source_snapshot.socket.getaddrinfo", _public_dns)
    monkeypatch.setattr("src.core.tls._context", None)
    built = []
    create_ssl_context = httpx.create_ssl_context
    monkeypatch.setattr(
        "src.core.tls.httpx.create_ssl_context",
        lambda: built.append(create_ssl_context()) or built[-1],
    )

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/plain"}, text="Observed.", request=request
        )

    verify_contexts = []
    client = httpx.Client

    def owned_client(**kwargs):
        verify_contexts.append(kwargs["verify"])
        return client(**kwargs, transport=httpx.MockTransport(handle))

    monkeypatch.setattr("src.core.source_snapshot.httpx.Client", owned_client)

    enriched = capture_source_snapshots(
        [{"sourceId": f"S{index}", "url": f"https://s{index}.example.test/r"} for index in range(4)]
    )

    assert [item["contentSnapshot"]["status"] for item in enriched] == ["captured"] * 4
    assert len(built) == 1
    assert verify_contexts == [built[0]] * 4


def test_source_snapshot_rejects_non_public_resolution(monkeypatch):
    monkeypatch.setattr(
        "src.core.source_snapshot.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )

    snapshot = capture_source_snapshot({"url": "https://internal.example.test/report"})

    assert snapshot["status"] == "unavailable"
    assert "non-public" in snapshot["reason"]


def test_source_snapshot_revalidates_each_redirect_target(monkeypatch):
    def route_dns(hostname, *_args, **_kwargs):
        address = "127.0.0.1" if hostname == "127.0.0.1" else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]

    monkeypatch.setattr("src.core.source_snapshot.socket.getaddrinfo", route_dns)

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "http://127.0.0.1/admin"},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        snapshot = capture_source_snapshot(
            {"url": "https://security.example.test/report"},
            client=client,
        )

    assert snapshot["status"] == "unavailable"
    assert "non-public" in snapshot["reason"]


def test_source_snapshot_rejects_binary_and_oversized_responses(monkeypatch):
    monkeypatch.setattr("src.core.source_snapshot.socket.getaddrinfo", _public_dns)

    def binary(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/octet-stream"},
            content=b"binary",
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(binary)) as client:
        binary_snapshot = capture_source_snapshot(
            {"url": "https://security.example.test/report.bin"},
            client=client,
        )

    def oversized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            content=b"x" * (MAX_SNAPSHOT_BYTES + 1),
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(oversized)) as client:
        oversized_snapshot = capture_source_snapshot(
            {"url": "https://security.example.test/report.txt"},
            client=client,
        )

    assert binary_snapshot["status"] == "unavailable"
    assert "not text" in binary_snapshot["reason"]
    assert oversized_snapshot["status"] == "unavailable"
    assert "byte limit" in oversized_snapshot["reason"]


def test_bounded_catalog_keeps_unfetched_sources_named():
    sources = [
        {"sourceId": "S1", "url": "https://one.example/report"},
        {"sourceId": "S2", "url": "https://two.example/report"},
    ]

    enriched = capture_source_snapshots(
        sources,
        fetcher=lambda source: {
            "status": "captured",
            "capturedAt": "2026-08-15T12:00:00+00:00",
            "finalUrl": source["url"],
            "contentType": "text/plain",
            "sha256": "a" * 64,
            "text": f"Captured {source['sourceId']}",
            "pageAge": None,
        },
    )

    assert [item["sourceId"] for item in enriched] == ["S1", "S2"]
    assert [item["contentSnapshot"]["text"] for item in enriched] == [
        "Captured S1",
        "Captured S2",
    ]
