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
3. For successful records, verify separate research and synthesis provenance, claim-attribution schema 2, evaluation state, and runtime.
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
section. The evaluator may propose improvements, but it must not rewrite a
section after claim attribution has signed that section's evidence. Current
claim-bearing sections are therefore evaluation-only, and the same single
correction attempt now covers an initially inconsistent claim map. The final
persist gate remains authoritative.
