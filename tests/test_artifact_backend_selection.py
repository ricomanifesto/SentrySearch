"""Artifact backend selection preserves the S3 default and fails closed elsewhere."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from src.storage.artifacts import ArtifactConfigurationError, artifact_store_from_environment
from src.storage.r2_artifacts import R2ArtifactStore
from src.storage.report_service import ReportStorageService
from src.storage.s3_manager import s3_manager

R2 = {
    "ARTIFACT_BACKEND": "r2",
    "R2_ACCOUNT_ID": "0123456789abcdef0123456789abcdef",
    "R2_ARTIFACT_BUCKET": "sentry-staging-artifacts",
    "R2_ACCESS_KEY_ID": "fixture-access-key-id",
    "R2_SECRET_ACCESS_KEY": "fixture-secret-value-do-not-echo",
}


@pytest.mark.parametrize("environ", [{}, {"ARTIFACT_BACKEND": ""}, {"ARTIFACT_BACKEND": "s3"}])
def test_existing_entrypoints_keep_the_shared_s3_backend(environ):
    assert artifact_store_from_environment(environ) is s3_manager


def test_explicit_r2_selects_the_r2_backend_on_either_entrypoint():
    for environ in (R2, {**R2, "SENTRYSEARCH_PLATFORM": "cloudflare"}):
        store = artifact_store_from_environment(environ)
        assert isinstance(store, R2ArtifactStore)
        assert store.target.bucket == "sentry-staging-artifacts"
        assert store.target.jurisdiction is None
    eu = artifact_store_from_environment({**R2, "R2_JURISDICTION": "eu"})
    assert isinstance(eu, R2ArtifactStore) and eu.target.jurisdiction == "eu"
    # An empty R2_CA_BUNDLE means the default trust store, never an empty bundle.
    default_trust = artifact_store_from_environment({**R2, "R2_CA_BUNDLE": ""})
    assert isinstance(default_trust, R2ArtifactStore) and default_trust._ca_bundle is None


@pytest.mark.parametrize(
    "environ, message",
    [
        ({"SENTRYSEARCH_PLATFORM": "cloudflare"}, "requires ARTIFACT_BACKEND=r2"),
        ({"SENTRYSEARCH_PLATFORM": "cloudflare", "ARTIFACT_BACKEND": "s3"}, "requires"),
        ({"SENTRYSEARCH_PLATFORM": "cloudflare", "ARTIFACT_BACKEND": ""}, "requires"),
        ({"SENTRYSEARCH_PLATFORM": "aws"}, "SENTRYSEARCH_PLATFORM"),
        ({"ARTIFACT_BACKEND": "gcs"}, "ARTIFACT_BACKEND"),
        ({"ARTIFACT_BACKEND": "R2"}, "ARTIFACT_BACKEND"),
        ({**R2, "R2_ACCOUNT_ID": "not-an-account"}, "account_id"),
        ({**R2, "R2_ARTIFACT_BUCKET": "Bad_Bucket"}, "bucket"),
        ({**R2, "R2_JURISDICTION": "mars"}, "jurisdiction"),
        ({**R2, "R2_ACCESS_KEY_ID": ""}, "R2_ACCESS_KEY_ID"),
        ({**R2, "R2_SECRET_ACCESS_KEY": ""}, "R2_SECRET_ACCESS_KEY"),
        ({**R2, "R2_CA_BUNDLE": "/nonexistent/ca.pem"}, "R2_CA_BUNDLE"),
    ],
)
def test_contradictory_or_malformed_settings_fail_without_echoing_values(environ, message):
    with pytest.raises(ArtifactConfigurationError, match=message) as error:
        artifact_store_from_environment(environ)
    assert "fixture-secret-value" not in str(error.value)
    assert error.value.__cause__ is None


def test_report_service_uses_the_selected_store_under_both_names():
    store = Mock()
    service = ReportStorageService(artifacts=store)
    assert service.artifacts is store and service.s3_manager is store
    replacement = Mock()
    service.s3_manager = replacement
    assert service.artifacts is replacement


def test_report_service_default_is_selected_from_the_environment(monkeypatch):
    monkeypatch.delenv("ARTIFACT_BACKEND", raising=False)
    monkeypatch.delenv("SENTRYSEARCH_PLATFORM", raising=False)
    assert ReportStorageService().artifacts is s3_manager
    for name, value in R2.items():
        monkeypatch.setenv(name, value)
    assert isinstance(ReportStorageService().artifacts, R2ArtifactStore)
    monkeypatch.setenv("SENTRYSEARCH_PLATFORM", "cloudflare")
    monkeypatch.setenv("ARTIFACT_BACKEND", "s3")
    with pytest.raises(ArtifactConfigurationError):
        ReportStorageService()


def test_a_relative_ca_bundle_is_refused_even_when_it_exists(tmp_path, monkeypatch):
    (tmp_path / "ca.pem").write_text("placeholder")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ArtifactConfigurationError, match="absolute path"):
        artifact_store_from_environment({**R2, "R2_CA_BUNDLE": "ca.pem"})
    store = artifact_store_from_environment({**R2, "R2_CA_BUNDLE": str(tmp_path / "ca.pem")})
    assert isinstance(store, R2ArtifactStore)
