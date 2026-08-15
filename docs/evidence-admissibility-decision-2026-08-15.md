# Evidence admissibility decision — 2026-08-15

## Decision

New reports must pass an application-owned evidence gate before they can become completed review records or be accepted for reuse. The model may propose sources, indicators, claims, and quality scores; it does not decide whether special-use infrastructure or non-operational source material is admissible.

New synthesis responses attach `value`, `evidenceRole`, and `sourceIds` to each high-risk field item. The application strips that generation-only wrapper and deterministically derives claim-attribution schema 4 for storage and rendering. The derived ledger records `generationShape: embedded_evidence_items` as a durable production-canary receipt. Target-specific claims require direct source IDs. Generic mitigation guidance may be marked as general practice without pretending it came from a target-specific source.

## Invariants

- Training, tabletop, simulation, fictional-scenario, and reserved-example sources remain named in the audit record but cannot enter the operational source ledger.
- RFC 5737, RFC 3849, loopback, link-local, multicast, unspecified, benchmarking, and other explicitly special-use addresses cannot become operational indicators.
- RFC 1918 and unique-local addresses remain admissible only with a visible victim-environment context flag.
- Documentation addresses are checked across the complete generated profile, not only the IOC arrays.
- A claim cannot cite an excluded or context-only source as direct operational evidence.
- One bounded synthesis correction may repair embedded evidence or remove inadmissible material. A second incomplete projection becomes the typed, retryable `evidence_incomplete` result; a safety rejection becomes the non-retryable `evidence_inadmissible` result.
- Deterministic findings are passed to the evaluator as ground truth and independently force `needs_attention` regardless of the model score.
- Operational readiness is presented before content quality. An older analyst acceptance cannot override a missing or failed evidence assessment.
- Handoff eligibility is backend-owned and requires the current evaluation vintage to be completed, scored, evidence-safe, and accepted. It governs default export scope, explicitly selected export IDs, and direct report download.

## Retained records

Schema-2 and schema-3 reports stay `unassessed`. The system does not infer source purpose, field coverage, or safe indicator status for historical records. Their prior disposition events remain append-only history, but they cannot receive a new “Accept for reuse” judgment or leave through a handoff surface until a current evidence assessment exists and passes.

## Verification oracle

- Backend tests prove embedded-ledger derivation, source classification, full schema-4 coverage, safety-versus-coverage failure taxonomy, special-use rejection, private-address context, persistence, API projection, readiness, acceptance, and handoff gating.
- Reader-experience tests prove named source quarantine, exact blocking findings, coverage-versus-safety failure language, disabled ineligible download, export disclosure, and historical-acceptance precedence.
- The development-only `local-evidence-safety-fixture` preserves the Noodle RAT failure shape: a 4.40 content score, a TEST-NET-2 address, a training source, and a blocked operational-readiness state.
- Production canary 1 of 3 completed after commit `ae76ea0`: fresh Noodle RAT record `0e20b16f-4dff-4181-b169-40a7231a027a` persisted `generationShape: embedded_evidence_items`, schema-4 attribution for 43 claims across all four high-risk classes, and a passed evidence assessment with zero safety or coverage findings. Evaluation completed at 4.57 with a `reviewable` state. The record remains unjudged, so handoff stays disabled until an analyst explicitly accepts that evaluation vintage.

## Append-only correction — source content was not yet examined

The record above was a successful schema-4 shape canary, not a successful safety canary. A reader review found that source S8 was a Noodle RAT training/game artifact whose neutral GitHub URL and title did not contain the markers used by the original source classifier. The application had not fetched source content, so `source.no-non-operational-marker` meant only that no marker appeared in URL/title metadata. S8 then supported ten high-risk claims, while the evaluator assigned 4.57 and `reviewable`. The record must not count toward the cleanup trigger for embedded-evidence compatibility.

The correction is additive and fail closed:

- New research catalogs capture bounded public text content before synthesis. Only a captured, fingerprinted page that passes deterministic intent checks may be `operational`; unavailable or ambiguous content is `context_only`, and training/game/simulation content remains named as excluded evidence.
- Claim-attribution schema 5 requires one short verbatim captured excerpt per direct source ID. Finalization verifies each excerpt by exact substring against the captured snapshot and stores its SHA-256. Source identity alone no longer proves support.
- IOC-population recommendations are checked against admitted captured content. Suggestions with no concrete source value move to `unverified_recommendations` and force `needs_attention` rather than inheriting a high evaluator score.
- Schema-4 retained records remain readable but project as `unassessed` for reuse. No legacy support excerpt or source intent is inferred.
- The renderer applies attribution edits against the original markdown in longest-claim-first, non-overlapping order, so inserted citation syntax cannot become input to a later replacement.

The new release oracle is three successful schema-5 production canaries: one common target, one mid-coverage target, and one deliberately obscure target. Each must persist captured source fingerprints and exact support excerpts, name every exclusion, keep unsupported evaluator advice out of verified recommendations, render non-overlapping citations, and complete the disposition/reload/export loop. An obscure run that lacks evidence is successful only when it terminates with the typed evidence-scarcity outcome; it must not manufacture completeness.
