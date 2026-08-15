from typing import Any

from src.core.recommendation_integrity import validate_quality_recommendations


def _source(text: str, *, purpose: str = "operational") -> dict:
    return {
        "sourceId": "S1",
        "evidencePurpose": purpose,
        "contentSnapshot": {
            "status": "captured",
            "text": text,
            "sha256": "a" * 64,
        },
    }


def test_unsupported_ioc_population_recommendation_is_named_and_blocks_readiness():
    assessment: dict[str, Any] = {
        "recommendations": [
            "Populate ips, domains, and urls using C2 addresses mentioned in the source ledger."
        ],
        "needs_improvement": False,
    }

    validate_quality_recommendations(
        assessment,
        [_source("The report describes process injection but publishes no C2 infrastructure.")],
    )

    assert assessment["recommendations"] == []
    assert assessment["needs_improvement"] is True
    [unverified] = assessment["unverified_recommendations"]
    assert unverified["recommendation"].startswith("Populate ips")
    assert "does not name a concrete admitted source-backed" in unverified["reason"]


def test_ioc_recommendation_records_concrete_candidates_from_admitted_snapshots():
    assessment: dict[str, Any] = {
        "recommendations": ["Populate IP 8.8.8.8 from the captured source evidence."],
        "needs_improvement": False,
    }

    validate_quality_recommendations(
        assessment,
        [_source("Observed command infrastructure at 8.8.8.8 during the incident.")],
    )

    assert assessment["unverified_recommendations"] == []
    assert assessment["recommendations"] == [
        "Populate IP 8.8.8.8 from the captured source evidence."
    ]
    assert assessment["recommendation_evidence"][0]["candidateValues"]["ips"] == ["8.8.8.8"]


def test_excluded_source_cannot_verify_an_evaluator_recommendation():
    assessment: dict[str, Any] = {
        "recommendations": ["Populate IPs from the training scenario."],
        "needs_improvement": False,
    }

    validate_quality_recommendations(
        assessment,
        [_source("Scenario C2 is 8.8.8.8.", purpose="excluded_non_operational")],
    )

    assert assessment["needs_improvement"] is True
    assert len(assessment["unverified_recommendations"]) == 1
