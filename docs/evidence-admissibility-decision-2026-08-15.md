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
- A production witness is still required after deployment: generate a fresh adversarial Noodle RAT record, confirm the gate outcome and source audit, then exercise the analyst disposition and export paths.
