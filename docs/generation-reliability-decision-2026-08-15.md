# Generation Reliability Decision — 2026-08-15

## Evidence window

The authenticated 30-day operations view contained 33 terminal generation records: 19 completed and 14 failed, for a 58% completion rate.

All 14 failures predate typed failure persistence:

- Cause: 14 unrecorded.
- Last pipeline stage: 14 unrecorded.
- Route: 14 unrecorded.
- UTC failure hours: 13:00 (4), 03:00 (3), 04:00 (3), and one each at 11:00, 14:00, 15:00, and 18:00.
- Targets include repeated common tools and frameworks as well as narrower or misspelled names. Havoc and Brute Ratel have both failed and completed records in the same workspace.

## Hypothesis verdict

No causal clustering hypothesis wins from the retained data.

- Route cannot be evaluated because every failed route is unrecorded.
- Stage cannot be evaluated because every failed stage is unrecorded.
- Hour cannot be evaluated from failure counts without terminal-attempt denominators for each hour.
- Target class is not sufficient because the same named targets appear in both failed and completed records.

The dominant observable cluster is the legacy telemetry gap itself. It explains why the failures cannot be attributed; it does not establish why generation failed.

## Decision

Do not change retry limits or provider routing from this historical sample. Keep the existing deterministic same-family fallback and bounded truncated-response retry.

Use post-telemetry production witnesses as the next evidence boundary:

1. Generate one common, one medium-specificity, and one deliberately obscure target.
2. Require each terminal record to persist cause, stage, and route evidence when it fails.
3. For successful records, verify separate research and synthesis provenance, claim-attribution schema 3, evaluation state, and runtime.
4. Treat these witnesses as a release oracle, not as a statistically sufficient reliability baseline.

A future retry or routing change requires typed evidence showing a repeatable route, stage, hour-rate, or target-class cluster.

## First post-telemetry witness

The first common-target witness reached structured validation and failed the
claim-attribution contract because synthesis cited a source ID that was not in
its own primary source ledger. The record persisted the validating stage and
evidence-attestation cause, ruling out target obscurity and making the failure
class reproducible at the contract boundary.

This evidence justifies one narrow behavior change: retry synthesis once with
the same attested dossier and an explicit ledger invariant. The retry applies
only to the exact unknown-source-ID failure. Other source, URL, schema, and
attestation failures remain fail-closed, and a second mismatch remains terminal.
Provider routing and the existing truncation retry are unchanged.

The repeat witness passed the source-ID boundary and later failed the persist
gate because an attributed claim no longer appeared verbatim in its named
section. A further run moved that check before evaluation, used its one bounded
correction, and still failed the same claim-map invariant after more than eight
minutes. More retries would add latency without changing the contract's odds.

Claim attribution schema 3 therefore removes duplicated model-authored claim
text. Synthesis selects a class-specific structured field and index plus the
supporting source IDs; the application copies that exact stored value into the
reader-visible claim map. This preserves model-selected evidence without fuzzy
matching or inferred backfill. The evaluator may score signed sections but may
not rewrite them, and the final persist gate remains authoritative.

The first schema-3 witness still failed after its bounded correction because a
claim cited a source from the attested research catalog that synthesis omitted
from `primarySources`. Most of the observed runtime belonged to the second
corrective synthesis, not the evaluator. The contract was rejecting an
incomplete projection of known evidence rather than an invented source.

The application now adds an omitted source to the canonical reader-visible
ledger only when two facts are both explicit: a claim cites its source ID, and
that exact ID exists in the attested research catalog. It copies the catalog's
title and URL and labels any synthesis-owned metadata it cannot recover as
unknown. IDs absent from the catalog still fail closed, and historical records
are never backfilled by inference.

The generated report is also finalized before quality evaluation begins. A
successful synthesis therefore leaves a readable narrative, source ledger, and
route record even if the optional judge is slow or unavailable. Evaluation
continues as a separately recorded pending, completed, or failed operation and
can be retried without regenerating the report.
