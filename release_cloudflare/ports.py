"""Narrow Cloudflare ports the release platform depends on. Nothing here talks to Cloudflare.

The shapes are the subset of the Workers versions/deployments and container
application APIs the release contract needs, plus the signed control route to
the release's Durable Objects (``control_client.ControlClient`` implements
``ControlPort`` over an injected transport). A future adapter must translate
exactly these calls: no other script, version, application or account call,
no internal paging that drops results, and no retries. A reply the adapter
cannot classify raises ``release.ports.AmbiguousResponse``.

Hypotheses H-V1 and H-V2 (an uploaded version carries the image map; the
account APIs expose versions, deployments and instances well enough to
reconcile) are proven only against these fakes here; live proof is CF-07a/b.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from release_cloudflare.control_client import ControlReply


@dataclass(frozen=True)
class Deployment:
    """A script's current deployment: (version id, percentage) pairs, newest first."""

    id: str
    versions: tuple[tuple[str, int], ...]

    def exactly(self, version_id: str) -> bool:
        return self.versions == ((version_id, 100),)


@dataclass(frozen=True)
class VersionInfo:
    id: str
    tag: str | None
    message: str | None


@dataclass(frozen=True)
class ApplicationState:
    """A container application's settings as Cloudflare reports them."""

    id: str
    scheduling_policy: str
    instance_type: str
    ssh_enabled: bool
    logs_enabled: bool
    images: tuple[str, ...]


@dataclass(frozen=True)
class InstancePage:
    """One page of an application's instances.

    ``instances`` are mappings with ``durable_object_id`` and ``state``.
    ``next`` is the following page's cursor or None at the end.
    """

    instances: tuple[Mapping[str, Any], ...]
    next: str | None


class VersionsPort(Protocol):
    def deployment(self, script: str) -> Deployment: ...

    def deploy(
        self, script: str, version_id: str, *, message: str, not_after: datetime
    ) -> Deployment: ...

    def versions(self, script: str) -> list[VersionInfo]: ...

    def upload(
        self, script: str, *, tag: str, message: str, bundle_sha256: str, not_after: datetime
    ) -> VersionInfo: ...

    def application(self, application_id: str) -> ApplicationState: ...

    def instances(self, application_id: str, *, cursor: str | None) -> InstancePage: ...


class ControlPort(Protocol):
    def bind(self, session: str, fence: int) -> None: ...

    def send(
        self,
        *,
        method: str,
        service: str,
        name: str,
        action: str,
        body: Mapping[str, Any] | None,
        command_id: str,
        not_after: datetime,
    ) -> ControlReply: ...


class ReceiptPort(Protocol):
    """Operational check receipts (the probes' sanitized results), never raw logs.

    Worker readiness and job receipts are read from the owning Durable Object
    through ``ControlPort``; Workers Logs is never evidence.
    """

    def operational_receipt(self, release_id: str, check_id: str) -> dict[str, Any] | None: ...
