"""Metrics, traces, and route provenance are projections of one call log.

Each test drives the historical stateful observer API and the new after-the-run
projection over the same fixed fixture, then diffs their outputs.
"""

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from typing import Any

import pytest

import src.core.performance_metrics as performance_metrics
import src.core.trace_exporter as trace_exporter
from src.core.generation_run import GenerationRun, StageSpan
from src.core.performance_metrics import PerformanceTracker, project_metrics
from src.core.trace_exporter import TraceExporter, project_trace
from src.domain.model_calls import ModelCall, route_provenance, usage_totals
from src.domain.model_routes import ModelRouteAttemptOutcome, ModelRoutePurpose

SUCCEEDED = ModelRouteAttemptOutcome.SUCCEEDED
FAILED = ModelRouteAttemptOutcome.FAILED


def _call(purpose, outcome=SUCCEEDED, **fields: Any) -> ModelCall:
    defaults: dict[str, Any] = {
        "requested_model": "google/gemini-2.5-flash",
        "selected_model": "google/gemini-2.5-flash",
        "actual_model": "google/gemini-2.5-flash" if outcome is SUCCEEDED else "",
        "provider": "Google AI Studio",
        "requested_providers": ("google-ai-studio",),
        "started_at": 1.0,
        "ended_at": 2.0,
    }
    defaults.update(fields)
    return ModelCall(purpose=purpose, outcome=outcome, **defaults)


CALLS = [
    _call(ModelRoutePurpose.RESEARCH, input_tokens=1_000, output_tokens=200, web_search_calls=2),
    _call(ModelRoutePurpose.RESEARCH, input_tokens=1_100, output_tokens=210, web_search_calls=3),
    _call(
        ModelRoutePurpose.RESEARCH,
        FAILED,
        error_code="provider_rate_limited",
        retryable=True,
        provider="google-ai-studio",
    ),
    _call(ModelRoutePurpose.RESEARCH, input_tokens=900, output_tokens=190, web_search_calls=1),
    _call(
        ModelRoutePurpose.SYNTHESIS,
        input_tokens=40_000,
        output_tokens=9_000,
        cached_tokens=12_000,
        cache_write_tokens=3_000,
        reasoning_tokens=500,
        total_tokens=49_000,
    ),
    _call(
        ModelRoutePurpose.EVALUATION,
        requested_model="google/gemma-4-31b-it:free",
        selected_model="google/gemma-4-31b-it",
        actual_model="google/gemma-4-31b-it",
        input_tokens=7_777,
    ),
]


def _clock(monkeypatch, module, values):
    ticks = iter(values)
    monkeypatch.setattr(module.time, "time", lambda: next(ticks))


def test_usage_totals_count_successful_generation_calls_only():
    totals = usage_totals(CALLS, (ModelRoutePurpose.RESEARCH, ModelRoutePurpose.SYNTHESIS))

    assert totals["input_tokens"] == 43_000
    assert totals["web_search_calls"] == 6
    assert totals["cached_tokens"] == 12_000


def test_route_provenance_projection_keeps_failed_attempts_and_fallback():
    evaluation = route_provenance(
        CALLS,
        ModelRoutePurpose.EVALUATION,
        requested_model="google/gemma-4-31b-it:free",
    ).to_dict()
    research_route = route_provenance(
        CALLS,
        ModelRoutePurpose.RESEARCH,
        requested_model="google/gemini-2.5-flash",
        requested_providers=("google-ai-studio",),
    )
    research = research_route.to_dict()
    empty = route_provenance([], ModelRoutePurpose.EVALUATION, requested_model="m").to_dict()

    assert evaluation["used_fallback"] is True
    assert evaluation["request_count"] == 1
    assert research["request_count"] == 3
    assert [attempt.outcome.value for attempt in research_route.attempts] == [
        "succeeded",
        "succeeded",
        "failed",
        "succeeded",
    ]
    assert research_route.attempts[2].error_code == "provider_rate_limited"
    assert empty["request_count"] == 0 and empty["attempts"] == []


def _stateful_metrics(monkeypatch, tmp_path, *, error: str | None = None):
    tracker = PerformanceTracker(str(tmp_path / "old.jsonl"))
    _clock(monkeypatch, performance_metrics, [1_000.0, 1_012.5, 1_020.0])
    tracker.start_request(
        query="Example Threat",
        model="google/gemini-2.5-flash",
        prompt_type="threat_intel_main",
        cache_enabled=True,
    )
    tracker.record_prompt_details("x" * 4_321, cache_enabled=True)
    totals = usage_totals(CALLS, (ModelRoutePurpose.RESEARCH, ModelRoutePurpose.SYNTHESIS))
    response = SimpleNamespace(
        usage=SimpleNamespace(**totals),
        tool_events=[],
        web_search_sources=[{"url": "https://one.example"}, {"url": "https://two.example"}],
    )
    tracker.record_api_response(response, time_to_first_token=1_012.5 - 999.0)
    tracker.record_contract_result(schema_valid=True, source_attested=True)
    if error:
        tracker.record_error(RuntimeError(error))
    metrics = tracker.finish_request()
    assert metrics is not None
    return metrics


def _run_from(old) -> GenerationRun:
    return GenerationRun(
        tool_name="Example Threat",
        model="google/gemini-2.5-flash",
        metrics_request_id=old.request_id,
        metrics_timestamp=old.timestamp,
        metrics_started_clock=old.start_time,
        api_started_clock=999.0,
        api_ended_clock=1_012.5,
        prompt_size_chars=4_321,
        source_count=2,
        contract_valid=True,
    )


def test_projected_metrics_record_matches_the_stateful_tracker(monkeypatch, tmp_path):
    old = _stateful_metrics(monkeypatch, tmp_path)

    new = project_metrics(_run_from(old), CALLS)

    assert asdict(new) == asdict(old)
    assert set(asdict(new)) == set(asdict(old))


def test_projected_metrics_record_matches_on_failure(monkeypatch, tmp_path):
    old = _stateful_metrics(monkeypatch, tmp_path, error="synthesis failed")
    run = _run_from(old)
    run.error = "synthesis failed"
    run.error_clock = 1_020.0

    assert asdict(project_metrics(run, CALLS)) == asdict(old)


def test_projected_metrics_line_is_written_with_the_same_jsonl_shape(tmp_path):
    tracker = PerformanceTracker(str(tmp_path / "metrics.jsonl"))
    run = GenerationRun(tool_name="Example Threat", model="google/gemini-2.5-flash")
    run.start_metrics()

    tracker.write(project_metrics(run, CALLS))

    [line] = (tmp_path / "metrics.jsonl").read_text().splitlines()
    assert set(json.loads(line)) == set(performance_metrics.APIMetrics.__dataclass_fields__)


BASE = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
MOMENTS = [BASE + timedelta(seconds=offset) for offset in (0, 1, 2, 3, 40, 41, 70, 75)]
EVENTS = [{"type": "web_search_call", "status": "completed"}]
QUALITY = {"overall_score": 4.2, "sections": {}}
CORE = {"name": "Example Threat", "category": "RAT"}
VALIDATOR_SOURCES = [{"url": "https://one.example", "stage": "initial_research"}]
GUIDANCE = "Guidance " * 20


class _FixedDatetime(datetime):
    moments: list = []

    @classmethod
    def now(cls, tz=None):  # noqa: D401 - test clock
        value = cls.moments.pop(0)
        return cls.fromtimestamp(value.timestamp(), tz=value.tzinfo)


def _stateful_trace(monkeypatch, export_dir, *, failed: bool) -> dict:
    exporter = TraceExporter(str(export_dir))
    with monkeypatch.context() as patch:
        _FixedDatetime.moments = list(MOMENTS)
        patch.setattr(trace_exporter, "datetime", _FixedDatetime)
        patch.setattr(trace_exporter.uuid, "uuid4", lambda: "trace-1")
        exporter.start_trace("Example Threat")
        exporter.log_stage_start("initialization")
        exporter.log_stage_end("initialization")
        exporter.log_stage_start("web_search")
        if failed:
            _FixedDatetime.moments = [MOMENTS[4], MOMENTS[7]]
            exporter.log_error("synthesis failed", "main_process")
            path = exporter.complete_trace()
        else:
            exporter.log_model_tool_events(EVENTS)
            exporter.log_stage_end(
                "web_search", source_count=2, tool_event_count=1, response_id="r1", model="m"
            )
            exporter.log_stage_start("quality_validation")
            exporter.log_quality_metrics(QUALITY)
            exporter.log_stage_end("quality_validation")
            exporter.log_threat_characteristics(CORE)
            exporter.log_final_guidance(GUIDANCE)
            exporter.log_web_search_sources(VALIDATOR_SOURCES)
            path = exporter.complete_trace({"coreMetadata": CORE})
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def _projected_trace(export_dir, *, failed: bool) -> dict:
    run = GenerationRun(
        tool_name="Example Threat",
        model="m",
        run_id="trace-1",
        started_at=MOMENTS[0],
        stages={
            "initialization": StageSpan(MOMENTS[1], MOMENTS[2]),
            "web_search": StageSpan(started_at=MOMENTS[3]),
        },
    )
    if failed:
        run.error = "synthesis failed"
        run.error_at = MOMENTS[4]
        run.completed_at = MOMENTS[7]
    else:
        run.stages["web_search"] = StageSpan(
            MOMENTS[3],
            MOMENTS[4],
            {"source_count": 2, "tool_event_count": 1, "response_id": "r1", "model": "m"},
        )
        run.stages["quality_validation"] = StageSpan(MOMENTS[5], MOMENTS[6])
        run.tool_events = EVENTS
        run.quality_metrics = QUALITY
        run.core_metadata = CORE
        run.final_guidance = GUIDANCE
        run.validator_sources = VALIDATOR_SOURCES
        run.completed_at = MOMENTS[7]
        run.completed_profile = True
    path = TraceExporter(str(export_dir)).export(project_trace(run))
    with open(path, encoding="utf-8") as file:
        return json.load(file)


@pytest.mark.parametrize("failed", [False, True])
def test_projected_trace_file_matches_the_stateful_exporter(monkeypatch, tmp_path, failed):
    old = _stateful_trace(monkeypatch, tmp_path / "old", failed=failed)
    new = _projected_trace(tmp_path / "new", failed=failed)

    assert new == old


def test_each_run_owns_its_call_log_on_a_shared_client():
    from tests.test_openrouter_client import chat_response, model_client

    client = model_client([(200, chat_response("first"), {}), (200, chat_response("second"), {})])
    first_run = client.bind_call_log([])
    first = client.messages.create(
        route_purpose="research", messages=[{"role": "user", "content": "one"}]
    )
    second_run = client.bind_call_log([])
    second = client.messages.create(
        route_purpose="research", messages=[{"role": "user", "content": "two"}]
    )

    assert first_run == [first.model_call]
    assert second_run == [second.model_call]
    assert first.model_call.input_tokens == 10 and first.model_call.output_tokens == 20
    assert first.model_call.ended_at >= first.model_call.started_at
    provenance = client.route_provenance("research", requested_model="google/gemma-4-26b-a4b-it")
    assert provenance.request_count == 1
