"""Flat profile relations: lossless round trip, stable identity, one classification."""

from copy import deepcopy
import json

import pytest

import src.core.evidence_admissibility as evidence_admissibility
from src.core.evidence_admissibility import classify_sources
from src.core.profile_tables import (
    CLAIM_FIELDS,
    flatten,
    render,
    write_back,
)
from src.core.source_ledger import CLAIM_CLASS_SELECTORS, derive_embedded_attribution
from src.core.threat_profile_generator import _materialize_and_validate_evidence
from tests.conftest import build_threat_profile_data

CAPTURED_TEXT = (
    "Remote access malware analysis. The threat drops example.exe and uses HTTPS callbacks. "
    "Process creation is logged. Unexpected service creation is a detection indicator. "
    "Monitor service creation and isolate affected host during incident response."
)
SOURCE_URL = "https://research.vendor-security.com/report"
OPERATIONAL_SOURCE = {
    "sourceId": "S1",
    "url": SOURCE_URL,
    "title": "Vendor threat analysis",
    "contentSnapshot": {
        "status": "captured",
        "capturedAt": "2026-08-15T12:00:00+00:00",
        "sha256": "a" * 64,
        "text": CAPTURED_TEXT,
    },
}


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _embedded(value: str, excerpt: str) -> dict:
    return {
        "value": value,
        "evidenceRole": "direct_evidence",
        "sourceIds": ["S1"],
        "supportingEvidence": [{"sourceId": "S1", "excerpt": excerpt}],
    }


def _generated_profile() -> dict:
    """The fixture in the generation input shape: embedded items, no claim map."""

    profile = build_threat_profile_data(SOURCE_URL)
    profile["webSearchSources"]["primarySources"][0]["domain"] = "research.vendor-security.com"
    profile.pop("claimAttribution")
    profile["threatIntelligence"]["riskAssessment"]["riskFactors"] = [
        _embedded("Remote access", "Remote access malware analysis.")
    ]
    profile["forensicArtifacts"]["fileSystemArtifacts"] = [
        _embedded("example.exe dropped", "The threat drops example.exe")
    ]
    profile["forensicArtifacts"]["networkArtifacts"] = [
        _embedded("HTTPS callbacks", "uses HTTPS callbacks")
    ]
    profile["detectionAndMitigation"]["iocs"]["filenames"] = [
        _embedded("example.exe", "drops example.exe"),
    ]
    profile["detectionAndMitigation"]["iocs"]["ips"] = [
        _embedded("See vendor report", "isolate affected host"),
    ]
    profile["detectionAndMitigation"]["behavioralIndicators"] = [
        _embedded("Unexpected service creation", "Unexpected service creation is a detection")
    ]
    profile["mitigationAndResponse"]["preventiveMeasures"] = [
        {
            "value": "Application control",
            "evidenceRole": "general_practice",
            "sourceIds": [],
            "supportingEvidence": [],
        }
    ]
    profile["mitigationAndResponse"]["detectionMethods"] = [
        _embedded("Monitor service creation", "Monitor service creation")
    ]
    profile["mitigationAndResponse"]["responseActions"] = [
        _embedded("Isolate affected host", "isolate affected host")
    ]
    profile["mitigationAndResponse"]["recoveryGuidance"] = []
    return profile


def _round_trip_fixtures() -> list[dict]:
    stored = build_threat_profile_data()
    legacy = deepcopy(stored)
    legacy.pop("claimAttribution")
    schema_two = deepcopy(stored)
    schema_two["claimAttribution"] = {
        "schemaVersion": "2",
        "claims": [{"claimClass": "threat_activity", "claim": "Remote", "sourceIds": ["S1"]}],
    }
    non_list_claims = deepcopy(stored)
    non_list_claims["claimAttribution"]["claims"] = "not a list"
    non_mapping_attribution = deepcopy(stored)
    non_mapping_attribution["claimAttribution"] = ["unexpected"]
    tampered = deepcopy(stored)
    tampered["claimAttribution"]["claims"].append("junk")
    tampered["claimAttribution"]["claims"][0]["claimIndex"] = 7
    tampered["forensicArtifacts"]["registryArtifacts"] = "not a list"
    partial = {"detectionAndMitigation": {"iocs": {"ips": ["10.0.0.1", None, 4]}}}
    with_assessment = deepcopy(stored)
    with_assessment["evidenceAdmissibility"] = {"status": "passed", "summary": {}}
    return [
        stored,
        _generated_profile(),
        legacy,
        schema_two,
        non_list_claims,
        non_mapping_attribution,
        tampered,
        partial,
        with_assessment,
        {},
    ]


@pytest.mark.parametrize("fixture", _round_trip_fixtures())
def test_render_of_flatten_reproduces_the_fixture_byte_for_byte(fixture):
    assert _canonical(render(flatten(fixture))) == _canonical(fixture)


def test_render_keeps_every_key_in_its_original_position():
    fixture = build_threat_profile_data()

    rendered = render(flatten(fixture))

    assert list(rendered) == list(fixture)
    assert list(rendered["threatIntelligence"]["riskAssessment"]) == list(
        fixture["threatIntelligence"]["riskAssessment"]
    )


def test_flatten_assigns_one_row_per_claim_item_and_links_attribution():
    tables = flatten(build_threat_profile_data())

    assert len(tables.claims) == 10
    assert len({row.claim_id for row in tables.claims}) == 10
    assert all(record.claim_id is not None for record in tables.attributions)
    linked = {record.claim_id for record in tables.attributions}
    assert linked == {row.claim_id for row in tables.claims}
    # Stored support belongs to the attribution record that cites it.
    assert {row.owner_id for row in tables.claim_support} == {
        record.attribution_id
        for record in tables.attributions
        if record.evidence_role == "direct_evidence"
    }


def test_claim_field_table_matches_the_published_selectors():
    assert {claim_class: dict(fields) for claim_class, fields in CLAIM_CLASS_SELECTORS.items()} == {
        claim_class: {
            claim_field: path
            for row_class, claim_field, path in CLAIM_FIELDS
            if row_class == claim_class
        }
        for claim_class in dict.fromkeys(row[0] for row in CLAIM_FIELDS)
    }


def test_claim_identity_survives_gating_and_ordinal_is_the_legacy_index():
    tables = flatten(_generated_profile(), classify_sources([OPERATIONAL_SOURCE]))
    ids_before = {
        (row.claim_field, row.ordinal): row.claim_id for row in tables.claims if row.embedded
    }

    gated, error = derive_embedded_attribution(tables, require_complete_classes=True)

    assert error is None
    for record in gated.attributions:
        claim = next(row for row in gated.claims if row.claim_id == record.claim_id)
        assert claim.ordinal == record.raw["claimIndex"]
        assert claim.claim_field == record.raw["claimField"]
        assert ids_before[(claim.claim_field, 0)] == claim.claim_id


def test_gate_pass_classifies_each_source_once(monkeypatch):
    calls: list[str] = []
    original = evidence_admissibility._classify_source

    def counting(source):
        calls.append(source.source_id)
        return original(source)

    monkeypatch.setattr(evidence_admissibility, "_classify_source", counting)
    profile = _generated_profile()
    second = dict(
        OPERATIONAL_SOURCE, sourceId="S2", url="https://training.vendor-security.com/tabletop/"
    )

    _materialize_and_validate_evidence(profile, [OPERATIONAL_SOURCE, second])

    assert sorted(calls) == ["S1", "S2"]
    assert profile["evidenceAdmissibility"]["status"] == "passed"
    assert profile["claimAttribution"]["schemaVersion"] == "5"


def test_write_back_keeps_nested_identity_for_existing_callers():
    profile = build_threat_profile_data()
    iocs = profile["detectionAndMitigation"]["iocs"]
    rendered = render(flatten(profile))
    rendered["detectionAndMitigation"]["iocs"]["filenames"] = []
    rendered.pop("lineage")

    write_back(profile, rendered)

    assert profile["detectionAndMitigation"]["iocs"] is iocs
    assert iocs["filenames"] == []
    assert "lineage" not in profile
