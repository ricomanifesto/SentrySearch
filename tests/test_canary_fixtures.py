"""The canary replaces external responses, never evidence or scoring logic."""

from hashlib import sha256
import socket

import pytest

from src.core import report_evaluator, source_snapshot, threat_profile_generator
from src.core.generation_failures import EvidenceCoverageError, EvidenceUnavailableError
from src.core.openrouter_client import ModelClient
from src.core.source_ledger import assert_claim_attribution_consistent
from src.core.validation_criteria import SECTION_CRITERIA
from tests.canary_fixtures import (
    SOURCE_SHA256,
    SOURCE_TEXT,
    SOURCE_URL,
    install_worker_fixtures,
)


@pytest.fixture(autouse=True)
def refuse_live_network(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("The canary unit tests must never resolve or connect live")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


def test_real_generator_and_saved_evaluator_use_only_http_fixtures(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    original_dns = socket.getaddrinfo
    with install_worker_fixtures() as fixtures:
        generator = threat_profile_generator.ThreatProfileGenerator(
            enable_tracing=False, enable_metrics=False
        )
        assert isinstance(generator.client, ModelClient)
        assert socket.getaddrinfo is original_dns
        profile = generator.get_threat_intelligence("Example Threat")
        assert profile["evidenceAdmissibility"]["status"] == "passed"
        assert profile["evidenceAdmissibility"]["summary"]["operationalSources"] == 1
        assert profile["claimAttribution"]["schemaVersion"] == "5"
        assert_claim_attribution_consistent(profile)
        claims = profile["claimAttribution"]["claims"]
        assert len(claims) == 10
        for claim in claims:
            for support in claim["supportingEvidence"]:
                assert support["snapshotSha256"] == SOURCE_SHA256
                assert support["excerpt"] in SOURCE_TEXT
        source = profile["webSearchSources"]["primarySources"][0]
        assert source["url"] == SOURCE_URL
        assert source["evidenceSnapshotSha256"] == SOURCE_SHA256
        assert sha256(SOURCE_TEXT.encode()).hexdigest() == SOURCE_SHA256
        assert profile["_quality_assessment"]["overall_score"] == 4.5
        assert set(profile["_quality_assessment"]["section_validations"]) == set(SECTION_CRITERIA)
        evaluation = report_evaluator.evaluate_saved_report(profile)
        assert evaluation.succeeded
        assert evaluation.quality_assessment["overall_score"] == 4.5
        assert evaluation.quality_assessment["parallel_metrics"]["sections_processed"] == 7
        assert evaluation.evaluation_route["request_count"] == 8
        assert fixtures.request_counts == {
            "research": 3,
            "synthesis": 1,
            "section": 14,
            "consistency": 2,
        }
        assert len(fixtures.snapshots) == 1
        assert fixtures.snapshots[0]["sha256"] == SOURCE_SHA256
        assert fixtures.snapshots[0]["status"] == "captured"
    assert not list(tmp_path.iterdir())


def test_bad_model_excerpt_fails_real_claim_attestation(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    with install_worker_fixtures(bad_excerpt=True) as fixtures:
        generator = threat_profile_generator.ThreatProfileGenerator(
            enable_tracing=False, enable_metrics=False
        )
        with pytest.raises(EvidenceCoverageError) as rejected:
            generator.get_threat_intelligence("Example Threat")
        assert any("not verbatim" in finding for finding in rejected.value.findings)
        assert fixtures.snapshots[0]["sha256"] == SOURCE_SHA256
        assert fixtures.request_counts["synthesis"] == 2
        assert fixtures.request_counts.get("section", 0) == 0


def test_source_public_address_validation_stays_active():
    with install_worker_fixtures() as fixtures:
        fixtures.source_address = "127.0.0.1"
        captured = threat_profile_generator.capture_source_snapshots(
            [{"sourceId": "S1", "url": SOURCE_URL}]
        )[0]["contentSnapshot"]
        assert captured["status"] == "unavailable"
        assert "non-public infrastructure" in captured["reason"]
        assert fixtures.source_requests == 0


def test_fixture_rejects_unexpected_source_and_restores_boundaries():
    originals = (
        threat_profile_generator.create_model_client,
        report_evaluator.create_model_client,
        threat_profile_generator.capture_source_snapshots,
        source_snapshot.socket,
    )
    with install_worker_fixtures():
        captured = threat_profile_generator.capture_source_snapshots(
            [{"sourceId": "S1", "url": SOURCE_URL + "?unexpected=1"}]
        )[0]["contentSnapshot"]
        assert captured["status"] == "unavailable"
    assert originals == (
        threat_profile_generator.create_model_client,
        report_evaluator.create_model_client,
        threat_profile_generator.capture_source_snapshots,
        source_snapshot.socket,
    )


def test_real_source_classifier_rejects_non_operational_http_content(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "tests.canary_fixtures.SOURCE_TEXT",
        "This fictional scenario is a malware training exercise, not operational evidence.",
    )
    with install_worker_fixtures() as fixtures:
        generator = threat_profile_generator.ThreatProfileGenerator(
            enable_tracing=False, enable_metrics=False
        )
        with pytest.raises(EvidenceUnavailableError, match="no captured operational evidence"):
            generator.get_threat_intelligence("Example Threat")
        assert fixtures.snapshots[0]["status"] == "captured"
        assert fixtures.request_counts == {"research": 3}


def test_model_transport_rejects_an_unexpected_endpoint():
    with install_worker_fixtures() as fixtures:
        client = fixtures.create_client()
        client.base_url = "https://unexpected.invalid/api/v1"
        with pytest.raises(AssertionError, match="Unexpected model fixture request"):
            client.messages.create(messages=[{"role": "user", "content": "test"}])
