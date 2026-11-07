"""Stored profiles project to flat rows and back without changing reader output."""

import json

import pytest

from src.domain.reports import (
    READER_STATE_VERSION,
    AnalystDisposition,
    ReviewStatus,
    derive_reader_state,
)
from src.storage.profile_rows import content_address, profile_rows, render_claims
from src.storage.schema import REVISIONS, SCHEMA_VERSION, _pending_revisions
from tests.conftest import build_threat_profile_data


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True)


def test_rows_render_back_to_the_stored_schema_five_profile():
    profile = build_threat_profile_data()
    rows = profile_rows(profile, profile["webSearchSources"]["primarySources"])

    rendered = render_claims(profile, rows.claims, rows.claim_support)

    assert _canonical(rendered) == _canonical(profile)


def test_rows_carry_identity_order_and_verification_state():
    profile = build_threat_profile_data()

    rows = profile_rows(profile)

    assert [row["position"] for row in rows.claims] == list(range(10))
    assert len({row["claim_id"] for row in rows.claims}) == 10
    first = rows.claims[0]
    assert (first["claim_field"], first["ordinal"], first["value"]) == (
        "riskFactors",
        0,
        "Remote access",
    )
    assert {row["evidence_role"] for row in rows.claims} == {
        "direct_evidence",
        "general_practice",
    }
    assert len(rows.claim_support) == 8
    assert all(row["verified"] is True for row in rows.claim_support)
    assert [source["source_id"] for source in rows.sources] == ["S1"]


def test_retained_schema_four_support_is_never_marked_verified():
    profile = build_threat_profile_data()
    profile["claimAttribution"]["schemaVersion"] = "4"

    rows = profile_rows(profile)

    assert rows.claim_support and all(row["verified"] is None for row in rows.claim_support)


def test_assessment_rows_keep_exclusions_named_and_classify_findings():
    assessment = {
        "sourceObservations": [
            {"sourceId": "S1", "purpose": "operational", "ruleId": "r1"},
            {"sourceId": "S2", "purpose": "excluded_non_operational", "ruleId": "training"},
        ],
        "indicatorObservations": [
            {
                "claimField": "ips",
                "claimIndex": 0,
                "value": "192.0.2.1",
                "disposition": "excluded",
                "ruleId": "indicator.ip-documentation",
            },
            {
                "claimField": "filenames",
                "claimIndex": 0,
                "value": "example.exe",
                "disposition": "admitted",
            },
            {
                "claimField": "commandAndControl.communicationMethods",
                "claimIndex": 0,
                "value": "10.0.0.1",
                "disposition": "context_required",
            },
        ],
        "blockingFindings": ["unsafe", "incomplete one", "incomplete two"],
        "summary": {"safetyFindings": 1},
    }

    rows = profile_rows(build_threat_profile_data(), None, assessment)

    assert [row["purpose"] for row in rows.source_observations] == [
        "operational",
        "excluded_non_operational",
    ]
    # A quarantined value never links to a surviving claim; a stored one does.
    assert [row["claim_id"] is not None for row in rows.indicator_observations] == [
        False,
        True,
        False,
    ]
    assert [row["kind"] for row in rows.findings] == ["safety", "coverage", "coverage"]


def test_absent_inputs_produce_no_rows():
    rows = profile_rows(None, None, None)

    assert not any(
        (
            rows.sources,
            rows.claims,
            rows.claim_support,
            rows.indicator_observations,
            rows.source_observations,
            rows.findings,
        )
    )


def test_content_addressed_keys_expose_their_digest():
    assert content_address(f"reports/r/artifacts/{'a' * 64}.md") == "a" * 64
    assert content_address("reports/r/report.md") is None
    assert content_address(None) is None


@pytest.mark.parametrize(
    ("disposition", "handoff"),
    [(AnalystDisposition.ACCEPTED, True), (AnalystDisposition.UNREVIEWED, False)],
)
def test_reader_state_is_derived_from_the_domain_rules(disposition, handoff):
    state = derive_reader_state(
        report_status="completed",
        evaluation_status="completed",
        quality_score=4.5,
        quality_assessment={"summary": {"passed_sections": 3}},
        source_count=1,
        evidence_admissibility_status="passed",
        analyst_disposition=disposition,
    )

    assert state.review_status is ReviewStatus.REVIEWABLE
    assert (state.eligible_for_judgment, state.eligible_for_acceptance) == (True, True)
    assert state.eligible_for_handoff is handoff
    assert state.version == READER_STATE_VERSION


def test_failed_evidence_withholds_acceptance_and_handoff_even_when_accepted():
    state = derive_reader_state(
        report_status="completed",
        evaluation_status="completed",
        quality_score=4.9,
        quality_assessment={"summary": {"passed_sections": 3}},
        source_count=1,
        evidence_admissibility_status="blocked",
        analyst_disposition=AnalystDisposition.ACCEPTED,
    )

    assert state.review_status is ReviewStatus.NEEDS_ATTENTION
    assert (state.eligible_for_acceptance, state.eligible_for_handoff) == (False, False)


def test_revisions_are_an_ordered_append_only_sequence():
    assert [revision.version for revision in REVISIONS] == list(range(1, len(REVISIONS) + 1))
    assert SCHEMA_VERSION == REVISIONS[-1].version == 2
    # Applied SQL is frozen: the baseline checksum must never change.
    assert REVISIONS[0].checksum == (
        "ce8d3e907a8bd97b914b0e07df28d571aa5d8107b8e1c7b2463b3f1ac4d83a03"
    )
    for revision in REVISIONS:
        assert revision.statements(), revision.filename


def test_pending_revisions_require_an_exact_applied_prefix():
    expected = [(revision.version, revision.checksum) for revision in REVISIONS]

    assert _pending_revisions([]) == list(REVISIONS)
    assert _pending_revisions(expected[:1]) == list(REVISIONS[1:])
    assert _pending_revisions(expected) == []
    for applied in (
        [(1, "changed")],
        [expected[1]],
        [*expected, (3, "future")],
        [expected[0], (2, "changed")],
    ):
        with pytest.raises(RuntimeError):
            _pending_revisions(applied)


def test_revision_two_only_adds_objects():
    allowed = (
        "ALTER TABLE REPORTS ADD COLUMN IF NOT EXISTS",
        "CREATE TABLE IF NOT EXISTS",
        "CREATE INDEX IF NOT EXISTS",
    )
    for statement in REVISIONS[1].statements():
        code = " ".join(
            line for line in statement.splitlines() if not line.strip().startswith("--")
        ).strip()
        assert " ".join(code.upper().split()).startswith(allowed), code
