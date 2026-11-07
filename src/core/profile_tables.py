"""Flat relations for one threat profile, parsed once and rendered once.

The model's JSON is an input format. ``flatten`` parses it into frozen rows and
``render`` reproduces the exact ``threat_data`` dictionary shape from those rows.
Evidence gates are functions from tables to tables plus findings; they never
walk the nested profile themselves.

Relations
---------
``sources``      one row per researched catalog record (snapshot plus purpose).
``claims``       one row per item in a high-risk claim list. ``claim_id`` is
                 assigned at flatten time and survives gating; ``ordinal`` is
                 the position in the surviving list and equals the legacy
                 ``claimIndex`` selector.
``attributions`` one row per ``claimAttribution.claims`` record, linked to the
                 claim it selects when the selector resolves.
``claim_support`` one row per support excerpt, owned by a claim (embedded
                 generation shape) or an attribution record (stored shape).
``prose``        every reader-visible string with its stable profile path.

Everything the relations do not model stays in ``document``: the profile with
each claim list emptied in place and ``claimAttribution`` replaced by a
placeholder, so ``render`` keeps every key at its original position.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Iterator, Mapping

# One table drives every high-risk claim path. Order is significant: it is the
# order schema-5 attribution records are derived in.
CLAIM_FIELDS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("threat_activity", "riskFactors", ("threatIntelligence", "riskAssessment", "riskFactors")),
    ("forensic_artifact", "fileSystemArtifacts", ("forensicArtifacts", "fileSystemArtifacts")),
    ("forensic_artifact", "registryArtifacts", ("forensicArtifacts", "registryArtifacts")),
    ("forensic_artifact", "networkArtifacts", ("forensicArtifacts", "networkArtifacts")),
    ("forensic_artifact", "memoryArtifacts", ("forensicArtifacts", "memoryArtifacts")),
    ("forensic_artifact", "logArtifacts", ("forensicArtifacts", "logArtifacts")),
    ("detection_indicator", "hashes", ("detectionAndMitigation", "iocs", "hashes")),
    ("detection_indicator", "domains", ("detectionAndMitigation", "iocs", "domains")),
    ("detection_indicator", "ips", ("detectionAndMitigation", "iocs", "ips")),
    ("detection_indicator", "urls", ("detectionAndMitigation", "iocs", "urls")),
    ("detection_indicator", "filenames", ("detectionAndMitigation", "iocs", "filenames")),
    (
        "detection_indicator",
        "behavioralIndicators",
        ("detectionAndMitigation", "behavioralIndicators"),
    ),
    (
        "mitigation_action",
        "preventiveMeasures",
        ("mitigationAndResponse", "preventiveMeasures"),
    ),
    ("mitigation_action", "detectionMethods", ("mitigationAndResponse", "detectionMethods")),
    ("mitigation_action", "responseActions", ("mitigationAndResponse", "responseActions")),
    ("mitigation_action", "recoveryGuidance", ("mitigationAndResponse", "recoveryGuidance")),
)
CLAIM_FIELD_CLASS = {claim_field: claim_class for claim_class, claim_field, _ in CLAIM_FIELDS}
CLAIM_FIELD_PATHS = {claim_field: path for _, claim_field, path in CLAIM_FIELDS}
INDICATOR_FIELDS = ("hashes", "domains", "ips", "urls", "filenames")

_ATTRIBUTION_PLACEHOLDER = "claimAttribution"


def resolve_lists(value: Any, path: tuple[str, ...]) -> list[list[Any]]:
    """Resolve every list at ``path``; ``*`` expands the items of a list."""

    values = [value]
    for key in path:
        resolved: list[Any] = []
        for candidate in values:
            if key == "*" and isinstance(candidate, list):
                resolved.extend(candidate)
            elif isinstance(candidate, Mapping) and key in candidate:
                resolved.append(candidate[key])
        values = resolved
    return [candidate for candidate in values if isinstance(candidate, list)]


def _list_at(profile: Any, path: tuple[str, ...]) -> list[Any] | None:
    selected: Any = profile
    for key in path:
        if not isinstance(selected, Mapping):
            return None
        selected = selected.get(key)
    return selected if isinstance(selected, list) else None


def item_text(raw: Any) -> str:
    """The reader-visible text of one stored claim-list item."""

    return str(raw or "").strip()


def _string_list(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    return tuple(str(item).strip() for item in value)


@dataclass(frozen=True)
class SourceRow:
    """One researched catalog record. Purpose fields are set by classification."""

    source_id: str
    url: str
    title: str
    snapshot_status: str
    snapshot_sha256: str
    snapshot_text: str
    snapshot_captured_at: Any = None
    snapshot_final_url: Any = None
    snapshot_page_age: Any = None
    page_age: Any = None
    access_date: Any = None
    relevance_score: Any = None
    content_type: Any = None
    key_findings: Any = None
    evidence_page_age: Any = None
    promotion: bool = False
    purpose: str | None = None
    disposition: str | None = None
    rule_id: str | None = None
    reason: str | None = None
    record: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "SourceRow":
        snapshot = record.get("contentSnapshot")
        snapshot = snapshot if isinstance(snapshot, Mapping) else {}
        return cls(
            source_id=str(record.get("sourceId") or record.get("source_id") or "").strip(),
            url=str(record.get("url") or ""),
            title=str(record.get("title") or ""),
            snapshot_status=str(snapshot.get("status") or ""),
            snapshot_sha256=str(snapshot.get("sha256") or "").strip(),
            snapshot_text=str(snapshot.get("text") or ""),
            snapshot_captured_at=snapshot.get("capturedAt"),
            snapshot_final_url=snapshot.get("finalUrl"),
            snapshot_page_age=snapshot.get("pageAge"),
            page_age=record.get("page_age"),
            access_date=record.get("accessDate"),
            relevance_score=record.get("relevanceScore"),
            content_type=record.get("contentType"),
            key_findings=record.get("keyFindings"),
            evidence_page_age=record.get("evidencePageAge"),
            record=record,
        )

    @property
    def captured_snapshot(self) -> tuple[str, str] | None:
        """The verbatim snapshot text and digest when the capture is complete."""

        if self.snapshot_status == "captured" and self.snapshot_text and self.snapshot_sha256:
            return self.snapshot_text, self.snapshot_sha256
        return None


@dataclass(frozen=True)
class ClaimRow:
    """One item in a high-risk claim list."""

    claim_id: str
    claim_class: str
    claim_field: str
    ordinal: int
    raw: Any = field(compare=False)

    @property
    def embedded(self) -> bool:
        return isinstance(self.raw, Mapping)

    @property
    def value(self) -> str:
        if isinstance(self.raw, Mapping):
            return str(self.raw.get("value") or "").strip()
        return item_text(self.raw)

    @property
    def evidence_role(self) -> str:
        if isinstance(self.raw, Mapping):
            return str(self.raw.get("evidenceRole") or "").strip()
        return ""

    @property
    def source_ids(self) -> tuple[str, ...]:
        if not isinstance(self.raw, Mapping):
            return ()
        return tuple(
            source_id for source_id in _string_list(self.raw.get("sourceIds")) or () if source_id
        )


@dataclass(frozen=True)
class AttributionRow:
    """One stored ``claimAttribution.claims`` record."""

    attribution_id: str
    position: int
    claim_id: str | None
    raw: Any = field(compare=False)

    @property
    def valid(self) -> bool:
        return isinstance(self.raw, Mapping)

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default) if isinstance(self.raw, Mapping) else default

    @property
    def claim_class(self) -> str:
        return str(self.get("claimClass") or "")

    @property
    def claim_field(self) -> str:
        return str(self.get("claimField") or "")

    @property
    def claim_index(self) -> Any:
        return self.get("claimIndex")

    @property
    def claim_text(self) -> str:
        return str(self.get("claim") or "").strip()

    @property
    def evidence_role(self) -> str:
        return str(self.get("evidenceRole") or "")

    @property
    def source_ids(self) -> tuple[str, ...] | None:
        """Cited IDs as strings, or ``None`` when the record has no ID list."""

        value = self.get("sourceIds")
        return tuple(str(item) for item in value) if isinstance(value, list) else None

    @property
    def supports(self) -> list[Any] | None:
        value = self.get("supportingEvidence")
        return value if isinstance(value, list) else None


@dataclass(frozen=True)
class ClaimSupportRow:
    """One support excerpt for one claim or attribution record."""

    owner_id: str
    position: int
    source_id: str
    excerpt: str
    snapshot_sha256: str
    verified: bool | None = None
    anchor_ok: bool | None = None


@dataclass(frozen=True)
class IndicatorObservation:
    """One deterministic decision about a value that looks like infrastructure."""

    claim_id: str | None
    field: str
    ordinal: int
    value: str
    disposition: str
    rule_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "claimField": self.field,
            "claimIndex": self.ordinal,
            "value": self.value,
            "disposition": self.disposition,
            "reason": self.reason,
            "ruleId": self.rule_id,
        }


@dataclass(frozen=True)
class ProseRow:
    """One reader-visible string at a stable ``profile.``-prefixed path."""

    path: str
    text: str


@dataclass(frozen=True)
class Finding:
    """One deterministic gate finding. ``kind`` is ``safety`` or ``coverage``."""

    kind: str
    rule_id: str
    selector: str
    message: str


@dataclass(frozen=True)
class ProfileTables:
    """The flat form of one profile. Treat ``document`` as read-only."""

    document: dict[str, Any]
    present_fields: frozenset[str]
    claims: tuple[ClaimRow, ...]
    attribution_header: dict[str, Any] | None
    attribution_listed: bool
    attributions: tuple[AttributionRow, ...]
    claim_support: tuple[ClaimSupportRow, ...]
    sources: tuple[SourceRow, ...] = ()
    attribution_key_present: bool = False

    # -- lookups ---------------------------------------------------------

    def field_rows(self, claim_field: str) -> tuple[ClaimRow, ...]:
        return tuple(
            sorted(
                (row for row in self.claims if row.claim_field == claim_field),
                key=lambda row: row.ordinal,
            )
        )

    def claim_at(self, claim_field: str, ordinal: int) -> ClaimRow | None:
        for row in self.claims:
            if row.claim_field == claim_field and row.ordinal == ordinal:
                return row
        return None

    def support_for(self, owner_id: str) -> tuple[ClaimSupportRow, ...]:
        return tuple(
            sorted(
                (row for row in self.claim_support if row.owner_id == owner_id),
                key=lambda row: row.position,
            )
        )

    def source(self, source_id: str) -> SourceRow | None:
        for row in self.sources:
            if row.source_id == source_id:
                return row
        return None

    @property
    def has_attribution_mapping(self) -> bool:
        return self.attribution_header is not None

    @property
    def schema_version(self) -> Any:
        if self.attribution_header is None:
            return None
        return self.attribution_header.get("schemaVersion")

    # -- copy-on-write helpers -------------------------------------------

    def with_document(self, document: dict[str, Any]) -> "ProfileTables":
        return replace(self, document=document)

    def with_sources(self, sources: Iterable[SourceRow]) -> "ProfileTables":
        return replace(self, sources=tuple(sources))


def resolve_selector(tables: ProfileTables, claim_class: Any, claim_field: Any, index: Any):
    """Return the claim row a legacy (class, field, index) selector names."""

    if CLAIM_FIELD_CLASS.get(str(claim_field)) != str(claim_class) or not claim_class:
        return None
    if isinstance(index, bool) or not isinstance(index, int):
        return None
    if str(claim_field) not in tables.present_fields:
        return None
    return tables.claim_at(str(claim_field), index)


def _attribution_rows(
    claims: tuple[ClaimRow, ...],
    present_fields: frozenset[str],
    raw_claims: list[Any],
) -> tuple[tuple[AttributionRow, ...], tuple[ClaimSupportRow, ...]]:
    by_selector = {(row.claim_field, row.ordinal): row for row in claims}
    rows: list[AttributionRow] = []
    supports: list[ClaimSupportRow] = []
    for position, raw in enumerate(raw_claims):
        attribution_id = f"A{position + 1}"
        claim_id = None
        if isinstance(raw, Mapping):
            claim_field = str(raw.get("claimField") or "")
            index = raw.get("claimIndex")
            if (
                CLAIM_FIELD_CLASS.get(claim_field) == str(raw.get("claimClass") or "")
                and claim_field in present_fields
                and isinstance(index, int)
                and not isinstance(index, bool)
            ):
                linked = by_selector.get((claim_field, index))
                claim_id = linked.claim_id if linked is not None else None
            supports.extend(_support_rows(attribution_id, raw.get("supportingEvidence")))
        rows.append(AttributionRow(attribution_id, position, claim_id, raw))
    return tuple(rows), tuple(supports)


def _support_rows(owner_id: str, raw_supports: Any) -> list[ClaimSupportRow]:
    if not isinstance(raw_supports, list):
        return []
    return [
        ClaimSupportRow(
            owner_id=owner_id,
            position=position,
            source_id=str(support.get("sourceId") or "").strip(),
            excerpt=str(support.get("excerpt") or "").strip(),
            snapshot_sha256=str(support.get("snapshotSha256") or "").strip(),
        )
        for position, support in enumerate(raw_supports)
        if isinstance(support, Mapping)
    ]


def flatten(
    raw_profile: Mapping[str, Any],
    sources: Iterable[SourceRow | Mapping[str, Any]] = (),
) -> ProfileTables:
    """Parse one profile (generated or stored) into flat relations."""

    document = deepcopy(dict(raw_profile))
    claims: list[ClaimRow] = []
    supports: list[ClaimSupportRow] = []
    present: set[str] = set()
    for claim_class, claim_field, path in CLAIM_FIELDS:
        values = _list_at(document, path)
        if values is None:
            continue
        present.add(claim_field)
        for ordinal, raw in enumerate(values):
            claim_id = f"C{len(claims) + 1}"
            claims.append(ClaimRow(claim_id, claim_class, claim_field, ordinal, raw))
            if isinstance(raw, Mapping):
                supports.extend(_support_rows(claim_id, raw.get("supportingEvidence")))
        # Keep the key in place; render refills it from the claim rows.
        values.clear()

    attribution_key_present = _ATTRIBUTION_PLACEHOLDER in document
    header: dict[str, Any] | None = None
    listed = False
    attributions: tuple[AttributionRow, ...] = ()
    attribution = document.get(_ATTRIBUTION_PLACEHOLDER)
    if isinstance(attribution, Mapping):
        header = dict(attribution)
        raw_claims = header.get("claims")
        if isinstance(raw_claims, list):
            listed = True
            header.pop("claims")
            attributions, attribution_supports = _attribution_rows(
                tuple(claims), frozenset(present), raw_claims
            )
            supports.extend(attribution_supports)
        document[_ATTRIBUTION_PLACEHOLDER] = None

    return ProfileTables(
        document=document,
        present_fields=frozenset(present),
        claims=tuple(claims),
        attribution_header=header,
        attribution_listed=listed,
        attributions=attributions,
        claim_support=tuple(supports),
        sources=tuple(
            source if isinstance(source, SourceRow) else SourceRow.from_record(source)
            for source in sources
            if isinstance(source, (SourceRow, Mapping))
        ),
        attribution_key_present=attribution_key_present,
    )


def render(tables: ProfileTables) -> dict[str, Any]:
    """Reproduce the stored ``threat_data`` dictionary from the relations."""

    document = deepcopy(tables.document)
    for _, claim_field, path in CLAIM_FIELDS:
        if claim_field not in tables.present_fields:
            continue
        values = _list_at(document, path)
        if values is None:  # pragma: no cover - document keeps every present list
            continue
        values[:] = [deepcopy(row.raw) for row in tables.field_rows(claim_field)]
    if tables.attribution_header is not None:
        attribution = deepcopy(tables.attribution_header)
        if tables.attribution_listed:
            attribution["claims"] = [deepcopy(row.raw) for row in tables.attributions]
        document[_ATTRIBUTION_PLACEHOLDER] = attribution
    return document


def with_claims(
    tables: ProfileTables,
    claims: Iterable[ClaimRow],
    *,
    claim_support: Iterable[ClaimSupportRow] | None = None,
) -> ProfileTables:
    """Replace claim rows and renumber ``ordinal`` to the surviving positions."""

    by_field: dict[str, list[ClaimRow]] = {}
    for row in claims:
        by_field.setdefault(row.claim_field, []).append(row)
    renumbered: list[ClaimRow] = []
    for _, claim_field, _ in CLAIM_FIELDS:
        rows = sorted(by_field.get(claim_field, ()), key=lambda row: row.ordinal)
        renumbered.extend(replace(row, ordinal=ordinal) for ordinal, row in enumerate(rows))
    kept_ids = {row.claim_id for row in renumbered}
    kept_ids.update(row.attribution_id for row in tables.attributions)
    support = (
        tuple(claim_support)
        if claim_support is not None
        else tuple(row for row in tables.claim_support if row.owner_id in kept_ids)
    )
    return replace(tables, claims=tuple(renumbered), claim_support=support)


def with_attribution(
    tables: ProfileTables,
    header: dict[str, Any],
    records: Iterable[tuple[str | None, dict[str, Any]]],
    support: Iterable[ClaimSupportRow] = (),
) -> ProfileTables:
    """Replace the attribution relation with (claim_id, record) pairs."""

    rows = tuple(
        AttributionRow(f"A{position + 1}", position, claim_id, record)
        for position, (claim_id, record) in enumerate(records)
    )
    claim_ids = {row.claim_id for row in tables.claims}
    claim_owned = tuple(row for row in tables.claim_support if row.owner_id in claim_ids)
    return replace(
        tables,
        attribution_header=header,
        attribution_listed=True,
        attributions=rows,
        claim_support=(*claim_owned, *support),
    )


def iter_prose(
    value: Any,
    path: str = "profile",
    *,
    include_sources: bool = False,
) -> Iterator[ProseRow]:
    """Yield reader-visible strings without rescanning source metadata."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            if key == "evidenceAdmissibility":
                continue
            if (
                not include_sources
                and path == "profile"
                and key in {"claimAttribution", "references", "webSearchSources"}
            ):
                continue
            yield from iter_prose(child, f"{path}.{key}", include_sources=include_sources)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_prose(child, f"{path}[{index}]", include_sources=include_sources)
        return
    if isinstance(value, str) and value.strip():
        yield ProseRow(path, value)


def prose(tables: ProfileTables, *, include_sources: bool = False) -> tuple[ProseRow, ...]:
    """Every reader-visible string of the rendered profile, with its path."""

    return tuple(iter_prose(render(tables), include_sources=include_sources))


def write_back(target: dict[str, Any], rendered: Mapping[str, Any]) -> None:
    """Make ``target`` equal ``rendered`` while keeping nested object identity.

    The dictionary adapters keep their historical in-place contract: callers
    holding a nested section or list observe the gated result.
    """

    for key in [key for key in target if key not in rendered]:
        del target[key]
    for key, value in rendered.items():
        current = target.get(key)
        if key in target and isinstance(current, dict) and isinstance(value, Mapping):
            write_back(current, value)
        elif key in target and isinstance(current, list) and isinstance(value, list):
            _write_back_list(current, value)
        else:
            target[key] = deepcopy(value)


def _write_back_list(target: list[Any], rendered: list[Any]) -> None:
    if len(target) == len(rendered) and all(
        isinstance(current, dict) and isinstance(value, Mapping)
        for current, value in zip(target, rendered)
    ):
        for current, value in zip(target, rendered):
            write_back(current, value)
        return
    target[:] = deepcopy(rendered)
