from copy import deepcopy

import pytest

from src.core.evidence_admissibility import (
    EvidenceDisposition,
    SourcePurpose,
    assess_profile_evidence,
    classify_research_sources,
    quarantine_rejected_indicator_items,
)
from src.core.generation_failures import (
    EvidenceAdmissibilityError,
    EvidenceCoverageError,
    build_generation_failure,
)
from src.domain.reports import GenerationStage

OPERATIONAL_SOURCE = {
    "sourceId": "S1",
    "url": "https://research.vendor-security.com/report",
    "title": "Vendor threat analysis",
    "contentSnapshot": {
        "status": "captured",
        "capturedAt": "2026-08-15T12:00:00+00:00",
        "sha256": "a" * 64,
        "text": "Captured support for observed threat behavior and mitigations.",
        "pageAge": "2026-08-14",
    },
}


def _append_claim(
    profile: dict,
    *,
    claim_field: str,
    claim_index: int,
    claim: str,
) -> None:
    profile["claimAttribution"]["claims"].append(
        {
            "claimClass": "detection_indicator",
            "claimField": claim_field,
            "claimIndex": claim_index,
            "claim": claim,
            "evidenceRole": "direct_evidence",
            "sourceIds": ["S1"],
            "supportingEvidence": [
                {
                    "sourceId": "S1",
                    "excerpt": "Captured support",
                    "snapshotSha256": "a" * 64,
                }
            ],
        }
    )


def test_source_purpose_names_training_and_special_use_context():
    sources = classify_research_sources(
        [
            {
                "sourceId": "S1",
                "url": "https://malwareandmonsters.com/im-handbook/resources/scenario-cards/noodle-rat/biotech-research/large-group/organizational-context.html",
                "title": "Noodle RAT scenario card",
            },
            {
                "sourceId": "S2",
                "url": "https://www.rfc-editor.org/rfc/rfc5737.html",
                "title": "IPv4 Address Blocks Reserved for Documentation",
            },
        ]
    )

    assert sources[0]["evidencePurpose"] == SourcePurpose.EXCLUDED_NON_OPERATIONAL.value
    assert sources[0]["evidenceRuleId"] == "source.training-scenario"
    assert sources[1]["evidencePurpose"] == SourcePurpose.CONTEXT_ONLY.value
    assert sources[1]["evidenceRuleId"] == "source.special-use-reference"


def test_source_without_captured_content_is_never_admitted_by_default():
    [source] = classify_research_sources(
        [
            {
                "sourceId": "S1",
                "url": "https://research.vendor-security.com/report",
                "title": "Vendor threat analysis",
            }
        ]
    )

    assert source["evidencePurpose"] == SourcePurpose.CONTEXT_ONLY.value
    assert source["evidenceDisposition"] == EvidenceDisposition.CONTEXT_REQUIRED.value
    assert source["evidenceRuleId"] == "source.intent-unverified"


def test_captured_content_without_operational_security_intent_stays_context_only():
    [source] = classify_research_sources(
        [
            {
                "sourceId": "S1",
                "url": "https://documents.vendor-security.com/notes",
                "title": "Project notes",
                "contentSnapshot": {
                    "status": "captured",
                    "capturedAt": "2026-08-15T12:00:00+00:00",
                    "sha256": "c" * 64,
                    "text": "A general project schedule and meeting notes.",
                },
            }
        ]
    )

    assert source["evidencePurpose"] == SourcePurpose.CONTEXT_ONLY.value
    assert source["evidenceRuleId"] == "source.intent-ambiguous"


def test_one_generic_security_word_does_not_establish_operational_intent():
    [source] = classify_research_sources(
        [
            {
                "sourceId": "S1",
                "url": "https://documents.vendor-security.com/overview",
                "title": "Security overview",
                "contentSnapshot": {
                    "status": "captured",
                    "capturedAt": "2026-08-15T12:00:00+00:00",
                    "sha256": "d" * 64,
                    "text": "This document discusses threat awareness for all employees.",
                },
            }
        ]
    )

    assert source["evidencePurpose"] == SourcePurpose.CONTEXT_ONLY.value
    assert source["evidenceRuleId"] == "source.intent-ambiguous"


def test_training_language_in_captured_content_excludes_a_neutral_github_url():
    [source] = classify_research_sources(
        [
            {
                "sourceId": "S8",
                "url": "https://github.com/example/security/blob/main/noodle-rat.qmd",
                "title": "Noodle RAT details",
                "contentSnapshot": {
                    "status": "captured",
                    "capturedAt": "2026-08-15T12:00:00+00:00",
                    "sha256": "b" * 64,
                    "text": "Advanced Noodle RAT training guide for game-based security education.",
                },
            }
        ]
    )

    assert source["evidencePurpose"] == SourcePurpose.EXCLUDED_NON_OPERATIONAL.value
    assert source["evidenceRuleId"] == "source.training-scenario"


def test_training_source_remains_named_when_not_used_operationally(threat_profile_data):
    assessment = assess_profile_evidence(
        deepcopy(threat_profile_data),
        [
            OPERATIONAL_SOURCE,
            {
                "sourceId": "S2",
                "url": "https://malwareandmonsters.com/resources/scenario-cards/noodle-rat",
                "title": "Incident-response training exercise",
            },
        ],
    )

    assert assessment["status"] == "passed"
    assert assessment["summary"]["excludedSources"] == 1
    excluded = assessment["sourceObservations"][1]
    assert excluded["sourceId"] == "S2"
    assert excluded["disposition"] == EvidenceDisposition.EXCLUDED.value


def test_test_net_indicator_fails_closed_even_with_a_source(threat_profile_data):
    profile = deepcopy(threat_profile_data)
    profile["detectionAndMitigation"]["iocs"]["ips"] = ["198.51.100.87"]
    _append_claim(
        profile,
        claim_field="ips",
        claim_index=0,
        claim="198.51.100.87",
    )

    with pytest.raises(EvidenceAdmissibilityError) as captured:
        assess_profile_evidence(profile, [OPERATIONAL_SOURCE])

    assessment = captured.value.assessment
    assert assessment["status"] == "blocked"
    assert assessment["summary"]["rejectedIndicators"] == 1
    ip_observation = next(
        item for item in assessment["indicatorObservations"] if item["claimField"] == "ips"
    )
    assert ip_observation["ruleId"] == "indicator.ip-documentation"


def test_test_net_infrastructure_outside_the_ioc_list_also_fails_closed(
    threat_profile_data,
):
    profile = deepcopy(threat_profile_data)
    profile["commandAndControl"][
        "communicationMethods"
    ] = "The implant beacons to 198.51.100.87 over HTTPS."

    with pytest.raises(EvidenceAdmissibilityError) as captured:
        assess_profile_evidence(profile, [OPERATIONAL_SOURCE])

    observation = next(
        item
        for item in captured.value.assessment["indicatorObservations"]
        if item["value"] == "198.51.100.87"
    )
    assert observation["claimField"] == "commandAndControl.communicationMethods"
    assert observation["ruleId"] == "indicator.ip-documentation"


def test_private_address_is_retained_with_context_flag(threat_profile_data):
    profile = deepcopy(threat_profile_data)
    profile["detectionAndMitigation"]["iocs"]["ips"] = ["10.20.30.40"]
    _append_claim(profile, claim_field="ips", claim_index=0, claim="10.20.30.40")

    assessment = assess_profile_evidence(profile, [OPERATIONAL_SOURCE])

    assert assessment["status"] == "passed"
    assert assessment["summary"]["contextIndicators"] == 1
    ip_observation = next(
        item for item in assessment["indicatorObservations"] if item["claimField"] == "ips"
    )
    assert ip_observation["ruleId"] == "indicator.ip-private-context"


@pytest.mark.parametrize(
    ("claim_field", "value", "rule_id"),
    [
        ("domains", "payload.example.com", "indicator.domain-reserved-example"),
        ("urls", "https://example.net/c2", "indicator.url-host-reserved-example"),
        ("hashes", "not-a-complete-hash", "indicator.hash-invalid"),
    ],
)
def test_reserved_or_malformed_indicators_fail_closed(
    threat_profile_data,
    claim_field,
    value,
    rule_id,
):
    profile = deepcopy(threat_profile_data)
    profile["detectionAndMitigation"]["iocs"][claim_field] = [value]
    _append_claim(profile, claim_field=claim_field, claim_index=0, claim=value)

    with pytest.raises(EvidenceAdmissibilityError) as captured:
        assess_profile_evidence(profile, [OPERATIONAL_SOURCE])

    observation = next(
        item
        for item in captured.value.assessment["indicatorObservations"]
        if item["claimField"] == claim_field
    )
    assert observation["ruleId"] == rule_id


def test_invalid_embedded_indicators_are_quarantined_before_operational_reuse():
    profile = {
        "detectionAndMitigation": {
            "iocs": {
                "hashes": [],
                "domains": [],
                "ips": [
                    {
                        "value": "See vendor report for current infrastructure",
                        "evidenceRole": "direct_evidence",
                        "sourceIds": ["S1"],
                        "supportingEvidence": [{"sourceId": "S1", "excerpt": "See vendor report"}],
                    },
                    {
                        "value": "10.20.30.40",
                        "evidenceRole": "direct_evidence",
                        "sourceIds": ["S1"],
                        "supportingEvidence": [{"sourceId": "S1", "excerpt": "10.20.30.40"}],
                    },
                ],
                "urls": [],
                "filenames": [],
            }
        }
    }

    observations = quarantine_rejected_indicator_items(profile)

    assert [item["value"] for item in profile["detectionAndMitigation"]["iocs"]["ips"]] == [
        "10.20.30.40"
    ]
    assert observations == [
        {
            "claimField": "ips",
            "claimIndex": 0,
            "value": "See vendor report for current infrastructure",
            "disposition": "excluded",
            "reason": (
                "Removed before operational reuse. "
                "Indicator is not a valid IP address or network."
            ),
            "ruleId": "indicator.ip-invalid",
        }
    ]


def test_schema_five_requires_every_high_risk_field_item(threat_profile_data):
    profile = deepcopy(threat_profile_data)
    profile["claimAttribution"]["claims"] = profile["claimAttribution"]["claims"][:-1]

    with pytest.raises(
        EvidenceCoverageError, match="incomplete high-risk claim coverage"
    ) as captured:
        assess_profile_evidence(profile, [OPERATIONAL_SOURCE])

    assert captured.value.assessment["status"] == "unassessed"
    assert captured.value.assessment["summary"]["safetyFindings"] == 0
    assert captured.value.assessment["summary"]["coverageFindings"] == 1


def test_typed_failure_keeps_the_application_owned_evidence_audit():
    assessment = {
        "schemaVersion": "1",
        "status": "blocked",
        "sourceObservations": [],
        "indicatorObservations": [],
        "blockingFindings": ["Documentation address was rejected."],
        "summary": {"rejectedIndicators": 1},
    }
    error = EvidenceAdmissibilityError(
        "unsafe evidence",
        findings=assessment["blockingFindings"],
        assessment=assessment,
    )

    failure = build_generation_failure(error, stage=GenerationStage.VALIDATING)

    assert failure["error_code"] == "evidence_inadmissible"
    assert failure["retryable"] is False
    assert failure["evidence_admissibility"] == assessment


def test_incomplete_coverage_has_its_own_retryable_failure_taxonomy():
    assessment = {
        "schemaVersion": "1",
        "status": "unassessed",
        "sourceObservations": [],
        "indicatorObservations": [],
        "blockingFindings": ["riskFactors[0] lacks direct source identity."],
        "summary": {"safetyFindings": 0, "coverageFindings": 1},
    }
    error = EvidenceCoverageError(
        "incomplete evidence",
        findings=assessment["blockingFindings"],
        assessment=assessment,
    )

    failure = build_generation_failure(error, stage=GenerationStage.VALIDATING)

    assert failure["error_code"] == "evidence_incomplete"
    assert failure["retryable"] is True
    assert failure["evidence_admissibility"] == assessment
