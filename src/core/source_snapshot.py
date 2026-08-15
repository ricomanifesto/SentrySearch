"""Bounded source capture for deterministic evidence-intent and support checks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from hashlib import sha256
from html.parser import HTMLParser
from ipaddress import ip_address
import socket
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

MAX_SNAPSHOT_SOURCES = 12
MAX_SNAPSHOT_BYTES = 1_048_576
MAX_SNAPSHOT_TEXT = 12_000
MAX_REDIRECTS = 3
SNAPSHOT_WORKERS = 6


class SourceSnapshotError(ValueError):
    """Raised when a source cannot be captured within the safety boundary."""


class _VisibleTextParser(HTMLParser):
    """Extract human-visible text without accepting document instructions."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in {"script", "style", "svg", "noscript"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style", "svg", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth and data.strip():
            self.parts.append(data)


def _normalized_text(value: str) -> str:
    return " ".join(value.split())


def _github_raw_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.hostname not in {"github.com", "www.github.com"}:
        return url
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 5 or parts[2] != "blob":
        return url
    owner, repository, _, revision, *path = parts
    return urlunsplit(
        (
            "https",
            "raw.githubusercontent.com",
            f"/{owner}/{repository}/{revision}/{'/'.join(path)}",
            "",
            "",
        )
    )


def _validate_public_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SourceSnapshotError("Source snapshot requires an HTTP or HTTPS URL")
    if parsed.username or parsed.password:
        raise SourceSnapshotError("Source snapshot URLs cannot contain credentials")
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        }
    except OSError as error:
        raise SourceSnapshotError("Source hostname could not be resolved") from error
    if not addresses:
        raise SourceSnapshotError("Source hostname did not resolve to an address")
    for value in addresses:
        address = ip_address(value)
        if not address.is_global:
            raise SourceSnapshotError("Source hostname resolves to non-public infrastructure")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _response_text(response: httpx.Response, body: bytes) -> str:
    content_type = response.headers.get("content-type", "").split(";", 1)[0].casefold()
    if content_type and not (
        content_type.startswith("text/")
        or content_type in {"application/json", "application/xml", "application/xhtml+xml"}
    ):
        raise SourceSnapshotError(f"Source content type {content_type} is not text")
    encoding = response.encoding or "utf-8"
    decoded = body.decode(encoding, errors="replace")
    if "html" in content_type or "<html" in decoded[:500].casefold():
        parser = _VisibleTextParser()
        parser.feed(decoded)
        decoded = " ".join(parser.parts)
    return _normalized_text(decoded)[:MAX_SNAPSHOT_TEXT]


def capture_source_snapshot(
    source: Mapping[str, Any],
    *,
    client: httpx.Client | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Capture one public text source with bounded redirects, bytes, and time."""

    requested_url = _github_raw_url(str(source.get("url") or "").strip())
    captured_at = (now or datetime.now(UTC)).isoformat()
    owned_client = client is None
    active_client = client or httpx.Client(
        follow_redirects=False,
        timeout=httpx.Timeout(6.0, connect=2.0),
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0 Safari/537.36 "
                "SentrySearch-Evidence-Capture/1.0"
            ),
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.1",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    try:
        current_url = requested_url
        response: httpx.Response | None = None
        for _ in range(MAX_REDIRECTS + 1):
            current_url = _validate_public_url(current_url)
            with active_client.stream("GET", current_url) as streamed:
                if streamed.status_code in {301, 302, 303, 307, 308}:
                    location = streamed.headers.get("location")
                    if not location:
                        raise SourceSnapshotError("Source redirect did not provide a location")
                    current_url = urljoin(current_url, location)
                    continue
                streamed.raise_for_status()
                chunks: list[bytes] = []
                byte_count = 0
                for chunk in streamed.iter_bytes():
                    byte_count += len(chunk)
                    if byte_count > MAX_SNAPSHOT_BYTES:
                        raise SourceSnapshotError("Source exceeded the snapshot byte limit")
                    chunks.append(chunk)
                response = httpx.Response(
                    streamed.status_code,
                    headers={
                        key: value
                        for key, value in streamed.headers.items()
                        if key.casefold() not in {"content-encoding", "content-length"}
                    },
                    content=b"".join(chunks),
                    request=streamed.request,
                )
                break
        else:
            raise SourceSnapshotError("Source exceeded the redirect limit")
        if response is None or response.is_redirect:
            raise SourceSnapshotError("Source exceeded the redirect limit")
        body = response.content
        text = _response_text(response, body)
        if not text:
            raise SourceSnapshotError("Source did not contain readable text")
        return {
            "status": "captured",
            "capturedAt": captured_at,
            "finalUrl": str(response.url),
            "contentType": response.headers.get("content-type", "Unknown").split(";", 1)[0],
            "sha256": sha256(text.encode("utf-8")).hexdigest(),
            "text": text,
            "pageAge": str(source.get("page_age") or source.get("pageAge") or "").strip() or None,
        }
    except (httpx.HTTPError, SourceSnapshotError, UnicodeError) as error:
        return {
            "status": "unavailable",
            "capturedAt": captured_at,
            "finalUrl": requested_url,
            "contentType": None,
            "sha256": None,
            "text": None,
            "pageAge": str(source.get("page_age") or source.get("pageAge") or "").strip() or None,
            "reason": str(error),
        }
    finally:
        if owned_client:
            active_client.close()


def capture_source_snapshots(
    sources: Iterable[Mapping[str, Any]],
    *,
    fetcher: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Enrich a bounded source catalog concurrently while preserving source order."""

    source_list = [dict(source) for source in sources]
    capture = fetcher or capture_source_snapshot
    captured: dict[int, Mapping[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=SNAPSHOT_WORKERS) as executor:
        futures = {
            executor.submit(capture, source): index
            for index, source in enumerate(source_list[:MAX_SNAPSHOT_SOURCES])
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                captured[index] = future.result()
            except Exception as error:  # pragma: no cover - defensive fetcher boundary
                captured[index] = {
                    "status": "unavailable",
                    "capturedAt": datetime.now(UTC).isoformat(),
                    "finalUrl": str(source_list[index].get("url") or ""),
                    "contentType": None,
                    "sha256": None,
                    "text": None,
                    "pageAge": None,
                    "reason": f"Snapshot worker failed: {type(error).__name__}",
                }

    enriched: list[dict[str, Any]] = []
    for index, source in enumerate(source_list):
        item = dict(source)
        item["contentSnapshot"] = dict(
            captured.get(
                index,
                {
                    "status": "unavailable",
                    "capturedAt": datetime.now(UTC).isoformat(),
                    "finalUrl": str(source.get("url") or ""),
                    "contentType": None,
                    "sha256": None,
                    "text": None,
                    "pageAge": str(source.get("page_age") or "").strip() or None,
                    "reason": "Source was outside the bounded capture set",
                },
            )
        )
        enriched.append(item)
    return enriched
