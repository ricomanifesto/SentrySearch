"""Offline guards for report inputs, local artifacts and storage cleanup."""

import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.core.threat_profile_generator import ThreatProfileGenerator, synthesis_prompt
from src.core.section_validator import SectionValidator
from src.domain.execution import GenerationLease, GenerationLeaseLost
from src.storage.s3_manager import S3StorageManager
from src.storage.report_service import ReportStorageService


def test_research_target_is_serialized_data_under_a_trusted_boundary(monkeypatch):
    generator = ThreatProfileGenerator.__new__(ThreatProfileGenerator)
    requests = []
    target = 'Example "Demo"\nEdition'

    def request(**kwargs):
        requests.append(kwargs)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text="Ordinary evidence")],
            web_search_sources=[{"url": "https://example.test/report"}],
            usage=SimpleNamespace(),
        )

    monkeypatch.setattr(generator, "_request_model", request)
    generator._research_evidence(target)
    assert len(requests) == 3
    for request in requests:
        assert "literal data" in request["system"]
        content = request["messages"][0]["content"]
        assert f"tool_name: {json.dumps(target)}" in content
        assert target not in content


def test_synthesis_template_encodes_target_as_json_data():
    target = 'Example "Demo"\nEdition'
    prompt = synthesis_prompt(
        target, research_text="Ordinary evidence", source_catalog="[]", withheld_source_count=0
    )
    start = prompt.index("following JSON format:\n\n") + len("following JSON format:\n\n")
    end = prompt.index("\n\nCRITICAL INSTRUCTIONS FOR OUTPUT:")
    skeleton = json.loads(prompt[start:end])
    assert skeleton["coreMetadata"]["name"] == target
    assert f"tool_name: {json.dumps(target)}" in prompt


@pytest.mark.parametrize("mode", ["web_search", "attested_evidence"])
def test_section_enhancement_keeps_target_data_under_the_same_boundary(monkeypatch, mode):
    validator = SectionValidator(client=SimpleNamespace())
    requests = []
    target = 'Example "Demo"\nEdition'

    def request(**kwargs):
        requests.append(kwargs)
        return SimpleNamespace(parsed=None, content=[])

    monkeypatch.setattr(validator, "_request_model", request)
    if mode == "web_search":
        validator._enhance_section_with_web_search("technicalDetails", {}, target)
    else:
        validator._enhance_section_from_attested_evidence(
            "technicalDetails", {}, target, "Ordinary evidence"
        )
    assert len(requests) == 1
    assert "literal data" in requests[0]["system"]
    prompt = requests[0]["messages"][0]["content"]
    assert f"tool_name: {json.dumps(target)}" in prompt
    assert target not in prompt


@pytest.mark.parametrize("name", ["Example / Edition", "Example \\ Edition", "...", ""])
def test_default_artifact_name_stays_in_output_directory(monkeypatch, tmp_path, name):
    monkeypatch.chdir(tmp_path)
    generator = ThreatProfileGenerator.__new__(ThreatProfileGenerator)
    data = {"coreMetadata": {"name": name}}
    filename = generator.save_to_file(data)
    assert Path(filename).name == filename
    assert Path(filename).resolve().parent == tmp_path.resolve()
    assert json.loads(Path(filename).read_text()) == data


def test_default_artifact_name_does_not_follow_an_existing_symlink(monkeypatch, tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    other = tmp_path / "other.json"
    other.write_text("original")
    (output / "example_threat_intel.json").symlink_to(other)
    monkeypatch.chdir(output)
    generator = ThreatProfileGenerator.__new__(ThreatProfileGenerator)
    with pytest.raises(ValueError, match="output directory"):
        generator.save_to_file({"coreMetadata": {"name": "Example"}})
    assert other.read_text() == "original"


def test_explicit_artifact_path_preserves_the_caller_contract(tmp_path):
    generator = ThreatProfileGenerator.__new__(ThreatProfileGenerator)
    filename = str(tmp_path / "chosen.json")
    assert generator.save_to_file({"coreMetadata": {"name": "Example"}}, filename) == filename
    assert (tmp_path / "chosen.json").is_file()


def storage_with_client(client):
    store = S3StorageManager()
    store._initialized = True
    store.s3_client = client
    return store


def test_storage_lists_every_report_page():
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = [
        {"Contents": [{"Key": "reports/example/first"}]},
        {},
        {"Contents": [{"Key": "reports/example/second"}]},
    ]
    client.list_objects_v2.return_value = {"Contents": [{"Key": "reports/example/first"}]}
    store = storage_with_client(client)
    assert store.list_report_files("example") == ["reports/example/first", "reports/example/second"]
    client.get_paginator.assert_called_once_with("list_objects_v2")
    client.get_paginator.return_value.paginate.assert_called_once_with(
        Bucket=store.bucket_name, Prefix="reports/example/"
    )


def test_storage_deletes_every_page_in_bounded_batches():
    client = Mock()
    keys = [f"reports/example/{index}" for index in range(1001)]
    client.get_paginator.return_value.paginate.return_value = [
        {"Contents": [{"Key": key} for key in keys[:1000]]},
        {"Contents": [{"Key": keys[-1]}]},
    ]
    client.list_objects_v2.return_value = {"Contents": [{"Key": key} for key in keys[:1000]]}
    client.delete_objects.return_value = {}
    storage_with_client(client).delete_report_files("example")
    calls = client.delete_objects.call_args_list
    assert [len(call.kwargs["Delete"]["Objects"]) for call in calls] == [1000, 1]
    assert [item["Key"] for call in calls for item in call.kwargs["Delete"]["Objects"]] == keys


def test_storage_surfaces_partial_delete_errors_for_retry():
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = [
        {"Contents": [{"Key": "reports/example/first"}]}
    ]
    client.list_objects_v2.return_value = {"Contents": [{"Key": "reports/example/first"}]}
    client.delete_objects.return_value = {
        "Errors": [{"Key": "reports/example/first", "Code": "AccessDenied"}]
    }
    with pytest.raises(RuntimeError, match="cleanup incomplete"):
        storage_with_client(client).delete_report_files("example")


def test_report_row_is_preserved_when_artifact_cleanup_fails():
    session = Mock()
    query = session.query.return_value
    query.filter.return_value = query
    query.with_for_update.return_value = query
    report = SimpleNamespace(id="example")
    query.first.return_value = report

    @contextmanager
    def get_session():
        yield session

    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = SimpleNamespace(get_session=get_session)
    service.s3_manager = Mock()
    service.s3_manager.delete_report_files.side_effect = [RuntimeError("cleanup incomplete"), None]
    with pytest.raises(RuntimeError, match="cleanup incomplete"):
        service.delete_report("example", owner_user_id="owner")
    session.delete.assert_not_called()
    session.commit.assert_not_called()
    assert service.delete_report("example", owner_user_id="owner")
    session.delete.assert_called_once_with(report)
    session.commit.assert_called_once()


def test_existing_report_intent_rejects_a_different_run_before_generation(monkeypatch):
    session = Mock()
    dispatch = SimpleNamespace(
        state="submitted",
        runtime_run_id="11111111-1111-1111-1111-111111111111",
        lease_version=1,
        lease_owner="worker",
    )

    @contextmanager
    def get_session():
        yield session

    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = SimpleNamespace(get_session=get_session)
    monkeypatch.setattr(service, "_locked_report", lambda *_: SimpleNamespace(status="generating"))
    monkeypatch.setattr(service, "_locked_dispatch", lambda *_: dispatch)
    with pytest.raises(GenerationLeaseLost, match="does not match"):
        service.begin_runtime_attempt(
            "example", GenerationLease("22222222-2222-2222-2222-222222222222", "worker", 2)
        )
    session.commit.assert_not_called()
    assert dispatch.lease_version == 1
