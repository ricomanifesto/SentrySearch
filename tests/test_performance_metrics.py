from types import SimpleNamespace

import pytest

from src.core.performance_metrics import PerformanceTracker


def test_performance_tracker_measures_contract_tools_usage_and_cost(tmp_path):
    tracker = PerformanceTracker(str(tmp_path / "metrics.jsonl"))
    tracker.start_request("Example Threat")
    response = SimpleNamespace(
        usage=SimpleNamespace(
            input_tokens=1_000,
            output_tokens=100,
            cached_tokens=200,
            cache_write_tokens=300,
            reasoning_tokens=40,
            total_tokens=1_100,
            web_search_calls=2,
        ),
        tool_events=[],
        web_search_sources=[{"url": "https://one.example"}, {"url": "https://two.example"}],
    )

    tracker.record_api_response(response)
    tracker.record_contract_result(schema_valid=True, source_attested=True)
    metrics = tracker.finish_request()

    assert metrics is not None
    assert metrics.cached_tokens == 200
    assert metrics.cache_write_tokens == 300
    assert metrics.reasoning_tokens == 40
    assert metrics.cache_hit is True
    assert metrics.web_search_calls == 2
    assert metrics.source_count == 2
    assert metrics.schema_valid is True
    assert metrics.source_attested is True
    assert metrics.web_search_cost == pytest.approx(0.014)
    assert metrics.total_cost == pytest.approx(0.014132)

    summary = tracker.generate_evaluation_summary([metrics])
    assert summary["response_success_rate"] == 1.0
    assert summary["schema_success_rate"] == 1.0
    assert summary["source_attestation_rate"] == 1.0
    assert summary["avg_reasoning_tokens"] == 40
    assert summary["avg_source_count"] == 2
    assert summary["avg_web_search_calls"] == 2
