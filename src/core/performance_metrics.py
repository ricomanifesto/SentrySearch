"""
Performance metrics collection for prompt caching A/B testing
Tracks latency, costs, and token usage for baseline and cached comparisons
"""

import time
import json
import os
from contextvars import ContextVar
from datetime import datetime
import logging
from threading import Lock
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
import uuid

from src.core.openrouter_client import DEFAULT_MODEL

logger = logging.getLogger(__name__)


@dataclass
class APIMetrics:
    """Data class for storing API call metrics"""

    # Required fields
    request_id: str
    timestamp: str
    query: str
    model: str
    prompt_type: str
    start_time: float
    end_time: float
    latency_ms: int
    input_tokens: int
    output_tokens: int
    input_cost: float
    output_cost: float

    # Optional fields with defaults
    time_to_first_token_ms: Optional[int] = None
    cached_tokens: int = 0
    cache_write_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    web_search_calls: int = 0
    source_count: int = 0
    cache_write_cost: float = 0.0
    cache_read_cost: float = 0.0
    web_search_cost: float = 0.0
    total_cost: float = 0.0
    cache_enabled: bool = False
    cache_hit: bool = False
    prompt_size_chars: int = 0
    response_valid: bool = True
    json_parsed: bool = False
    schema_valid: bool = False
    source_attested: bool = False
    error_message: Optional[str] = None


class PerformanceTracker:
    """Tracks and logs performance metrics for prompt caching comparison"""

    # Current OpenRouter list pricing per 1M tokens and per 1K Exa tool calls.
    LONG_CONTEXT_THRESHOLD = 272_000
    PRICING = {
        "google/gemma-4-26b-a4b-it:free": {
            "input": 0.0,
            "output": 0.0,
            "cache_write": 0.0,
            "cache_read": 0.0,
            "long_input": 0.0,
            "long_output": 0.0,
            "long_cache_write": 0.0,
            "long_cache_read": 0.0,
            "web_search_per_1k_calls": 7.0,
        },
        "google/gemini-2.5-flash": {
            "input": 0.30,
            "output": 2.50,
            "cache_write": 0.383333,
            "cache_read": 0.03,
            "long_input": 0.30,
            "long_output": 2.50,
            "long_cache_write": 0.383333,
            "long_cache_read": 0.03,
            "web_search_per_1k_calls": 7.0,
        },
        "meta-llama/llama-3.3-70b-instruct": {
            "input": 0.10,
            "output": 0.32,
            "cache_write": 0.10,
            "cache_read": 0.10,
            "long_input": 0.10,
            "long_output": 0.32,
            "long_cache_write": 0.10,
            "long_cache_read": 0.10,
            "web_search_per_1k_calls": 7.0,
        },
    }

    def __init__(self, log_file: str = "performance_metrics.jsonl"):
        """Initialize the performance tracker

        Args:
            log_file: Path to JSONL file for storing metrics
        """
        self.log_file = log_file
        self._current_request_id: ContextVar[Optional[str]] = ContextVar(
            f"performance_request_id_{id(self)}", default=None
        )
        self._current_metrics: ContextVar[Optional[APIMetrics]] = ContextVar(
            f"performance_metrics_{id(self)}", default=None
        )
        self._write_lock = Lock()

        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)

        logger.debug("Performance metrics will be written to %s", log_file)

    @property
    def current_request_id(self) -> Optional[str]:
        return self._current_request_id.get()

    @current_request_id.setter
    def current_request_id(self, value: Optional[str]) -> None:
        self._current_request_id.set(value)

    @property
    def current_metrics(self) -> Optional[APIMetrics]:
        return self._current_metrics.get()

    @current_metrics.setter
    def current_metrics(self, value: Optional[APIMetrics]) -> None:
        self._current_metrics.set(value)

    def start_request(
        self,
        query: str,
        model: str = DEFAULT_MODEL,
        prompt_type: str = "threat_intel",
        cache_enabled: bool = False,
    ) -> str:
        """Start tracking a new API request

        Args:
            query: The query being executed
            model: model model being used
            prompt_type: Type of prompt (e.g., "threat_intel", "validation")
            cache_enabled: Whether prompt caching is enabled

        Returns:
            Request ID for tracking
        """
        request_id = f"{prompt_type}_{uuid.uuid4().hex}"
        start_time = time.time()

        self.current_request_id = request_id
        self.current_metrics = APIMetrics(
            request_id=request_id,
            timestamp=datetime.now().isoformat(),
            query=query,
            model=model,
            prompt_type=prompt_type,
            start_time=start_time,
            end_time=0.0,
            latency_ms=0,
            input_tokens=0,
            output_tokens=0,
            input_cost=0.0,
            output_cost=0.0,
            cache_enabled=cache_enabled,
        )

        logger.debug("Started metrics request %s", request_id)
        return request_id

    def record_prompt_details(self, prompt_content: str, cache_enabled: bool = False):
        """Record details about the prompt being sent

        Args:
            prompt_content: The actual prompt content
            cache_enabled: Whether caching is enabled for this prompt
        """
        if not self.current_metrics:
            logger.warning("No active request is available for prompt metrics")
            return

        self.current_metrics.prompt_size_chars = len(prompt_content)
        self.current_metrics.cache_enabled = cache_enabled

        logger.debug(
            "Recorded prompt metrics: size=%d cache_enabled=%s",
            len(prompt_content),
            cache_enabled,
        )

    def record_api_response(
        self, response, cache_hit: bool = False, time_to_first_token: Optional[float] = None
    ):
        """Record API response metrics

        Args:
            response: model API response object
            cache_hit: Whether this was a cache hit
            time_to_first_token: Time to first token in seconds
        """
        if not self.current_metrics:
            logger.warning("No active request is available for response metrics")
            return

        end_time = time.time()
        self.current_metrics.end_time = end_time
        self.current_metrics.latency_ms = int((end_time - self.current_metrics.start_time) * 1000)
        self.current_metrics.cache_hit = cache_hit

        if time_to_first_token:
            self.current_metrics.time_to_first_token_ms = int(time_to_first_token * 1000)

        # Extract token usage from response
        if hasattr(response, "usage"):
            usage = response.usage
            self.current_metrics.input_tokens = getattr(usage, "input_tokens", 0)
            self.current_metrics.output_tokens = getattr(usage, "output_tokens", 0)
            self.current_metrics.cached_tokens = getattr(usage, "cached_tokens", 0)
            self.current_metrics.cache_write_tokens = getattr(usage, "cache_write_tokens", 0)
            self.current_metrics.reasoning_tokens = getattr(usage, "reasoning_tokens", 0)
            self.current_metrics.total_tokens = getattr(
                usage,
                "total_tokens",
                self.current_metrics.input_tokens + self.current_metrics.output_tokens,
            )

            # Keep old response shapes readable while metrics files roll forward.
            self.current_metrics.cache_write_tokens = getattr(
                usage,
                "cache_creation_input_tokens",
                self.current_metrics.cache_write_tokens,
            )
            self.current_metrics.cached_tokens = getattr(
                usage,
                "cache_read_input_tokens",
                self.current_metrics.cached_tokens,
            )
            self.current_metrics.cache_hit = bool(
                self.current_metrics.cache_hit or self.current_metrics.cached_tokens
            )

        tool_events = getattr(response, "tool_events", []) or []
        reported_web_search_calls = getattr(
            getattr(response, "usage", None), "web_search_calls", None
        )
        self.current_metrics.web_search_calls = (
            int(reported_web_search_calls)
            if reported_web_search_calls is not None
            else sum(1 for event in tool_events if event.get("type") == "web_search_call")
        )
        self.current_metrics.source_count = len(getattr(response, "web_search_sources", []) or [])

        # Calculate costs
        self._calculate_costs()

        logger.debug(
            "Recorded model response: latency_ms=%d input_tokens=%d output_tokens=%d "
            "web_search_calls=%d source_count=%d cache_hit=%s",
            self.current_metrics.latency_ms,
            self.current_metrics.input_tokens,
            self.current_metrics.output_tokens,
            self.current_metrics.web_search_calls,
            self.current_metrics.source_count,
            self.current_metrics.cache_hit,
        )

    def record_error(self, error: Exception):
        """Record an error that occurred during the request

        Args:
            error: The exception that occurred
        """
        if not self.current_metrics:
            logger.warning("No active request is available for error metrics")
            return

        self.current_metrics.end_time = time.time()
        self.current_metrics.latency_ms = int(
            (self.current_metrics.end_time - self.current_metrics.start_time) * 1000
        )
        self.current_metrics.response_valid = False
        self.current_metrics.error_message = str(error)

        logger.debug("Recorded error for request %s: %s", self.current_request_id, error)

    def record_parsing_result(self, success: bool, error: Optional[str] = None):
        """Record JSON parsing success/failure

        Args:
            success: Whether JSON parsing succeeded
            error: Error message if parsing failed
        """
        if not self.current_metrics:
            return

        self.current_metrics.json_parsed = success
        self.current_metrics.schema_valid = success
        if not success and error:
            self.current_metrics.error_message = error

    def record_contract_result(
        self,
        *,
        schema_valid: bool,
        source_attested: bool,
        error: Optional[str] = None,
    ) -> None:
        """Record the structured-output and source-attestation result."""
        if not self.current_metrics:
            return

        self.current_metrics.json_parsed = schema_valid
        self.current_metrics.schema_valid = schema_valid
        self.current_metrics.source_attested = source_attested
        if error:
            self.current_metrics.error_message = error

    def finish_request(self) -> Optional[APIMetrics]:
        """Finish tracking the current request and save metrics

        Returns:
            The completed metrics object
        """
        if not self.current_metrics:
            logger.warning("No active metrics request to finish")
            return None

        # Ensure end time is set
        if self.current_metrics.end_time == 0.0:
            self.current_metrics.end_time = time.time()
            self.current_metrics.latency_ms = int(
                (self.current_metrics.end_time - self.current_metrics.start_time) * 1000
            )

        # Final cost calculation
        self._calculate_costs()

        # Save to log file
        self._save_metrics(self.current_metrics)

        metrics = self.current_metrics
        self.current_metrics = None
        self.current_request_id = None

        logger.debug("Finished metrics request %s", metrics.request_id)
        return metrics

    def _calculate_costs(self):
        """Calculate costs based on token usage and pricing"""
        if not self.current_metrics:
            return

        model = self.current_metrics.model
        pricing = self.PRICING.get(
            model,
            self.PRICING[DEFAULT_MODEL],
        )

        long_context = self.current_metrics.input_tokens > self.LONG_CONTEXT_THRESHOLD
        input_rate = pricing["long_input"] if long_context else pricing["input"]
        output_rate = pricing["long_output"] if long_context else pricing["output"]
        cache_write_rate = pricing["long_cache_write"] if long_context else pricing["cache_write"]
        cache_read_rate = pricing["long_cache_read"] if long_context else pricing["cache_read"]
        uncached_input_tokens = max(
            0,
            self.current_metrics.input_tokens
            - self.current_metrics.cached_tokens
            - self.current_metrics.cache_write_tokens,
        )

        self.current_metrics.input_cost = (uncached_input_tokens / 1_000_000) * input_rate
        self.current_metrics.output_cost = (
            self.current_metrics.output_tokens / 1_000_000
        ) * output_rate
        self.current_metrics.cache_read_cost = (
            self.current_metrics.cached_tokens / 1_000_000
        ) * cache_read_rate
        self.current_metrics.cache_write_cost = (
            self.current_metrics.cache_write_tokens / 1_000_000
        ) * cache_write_rate
        self.current_metrics.web_search_cost = (
            self.current_metrics.web_search_calls / 1_000
        ) * pricing["web_search_per_1k_calls"]

        # Total cost
        self.current_metrics.total_cost = (
            self.current_metrics.input_cost
            + self.current_metrics.output_cost
            + self.current_metrics.cache_write_cost
            + self.current_metrics.cache_read_cost
            + self.current_metrics.web_search_cost
        )

    def _save_metrics(self, metrics: APIMetrics):
        """Save metrics to the log file"""
        try:
            record = json.dumps(asdict(metrics), separators=(",", ":")) + "\n"
            with self._write_lock, open(self.log_file, "a", encoding="utf-8") as file:
                file.write(record)
        except Exception as e:
            logger.warning("Failed to save performance metrics: %s", e)

    def load_metrics(self) -> list[APIMetrics]:
        """Load all metrics from the log file

        Returns:
            List of APIMetrics objects
        """
        metrics = []
        if not os.path.exists(self.log_file):
            return metrics

        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line.strip())
                        metrics.append(APIMetrics(**data))
        except Exception as e:
            logger.warning("Failed to load performance metrics: %s", e)

        return metrics

    def generate_comparison_report(
        self, baseline_metrics: list[APIMetrics], cached_metrics: list[APIMetrics]
    ) -> Dict[str, Any]:
        """Generate a comparison report between baseline and cached metrics

        Args:
            baseline_metrics: Metrics from baseline (no caching) runs
            cached_metrics: Metrics from cached runs

        Returns:
            Comparison report dictionary
        """

        def calc_stats(metrics_list):
            if not metrics_list:
                return {}

            valid_metrics = [m for m in metrics_list if m.response_valid]
            if not valid_metrics:
                return {}

            latencies = [m.latency_ms for m in valid_metrics]
            costs = [m.total_cost for m in valid_metrics]
            input_tokens = [m.input_tokens for m in valid_metrics]

            return {
                "count": len(valid_metrics),
                "avg_latency_ms": sum(latencies) / len(latencies),
                "avg_cost_usd": sum(costs) / len(costs),
                "avg_input_tokens": sum(input_tokens) / len(input_tokens),
                "schema_success_rate": sum(m.schema_valid for m in valid_metrics)
                / len(valid_metrics),
                "source_attestation_rate": sum(m.source_attested for m in valid_metrics)
                / len(valid_metrics),
                "avg_source_count": sum(m.source_count for m in valid_metrics) / len(valid_metrics),
                "avg_web_search_calls": sum(m.web_search_calls for m in valid_metrics)
                / len(valid_metrics),
                "total_cost_usd": sum(costs),
            }

        baseline_stats = calc_stats(baseline_metrics)
        cached_stats = calc_stats(cached_metrics)

        if not baseline_stats or not cached_stats:
            return {"error": "Insufficient data for comparison"}

        # Calculate improvements
        latency_improvement = (
            (baseline_stats["avg_latency_ms"] - cached_stats["avg_latency_ms"])
            / baseline_stats["avg_latency_ms"]
        ) * 100

        cost_improvement = (
            (baseline_stats["avg_cost_usd"] - cached_stats["avg_cost_usd"])
            / baseline_stats["avg_cost_usd"]
        ) * 100

        return {
            "baseline": baseline_stats,
            "cached": cached_stats,
            "improvements": {
                "latency_reduction_percent": latency_improvement,
                "cost_reduction_percent": cost_improvement,
                "latency_reduction_ms": baseline_stats["avg_latency_ms"]
                - cached_stats["avg_latency_ms"],
            },
            "summary": {
                "baseline_avg_latency": f"{baseline_stats['avg_latency_ms']:.0f}ms",
                "cached_avg_latency": f"{cached_stats['avg_latency_ms']:.0f}ms",
                "improvement": f"{latency_improvement:.1f}% faster",
                "cost_reduction": f"{cost_improvement:.1f}% cheaper",
            },
        }

    def generate_evaluation_summary(self, metrics: list[APIMetrics]) -> Dict[str, Any]:
        """Summarize the quality, latency, usage, and cost of representative runs."""
        if not metrics:
            return {"error": "No evaluation data"}

        count = len(metrics)
        return {
            "count": count,
            "response_success_rate": sum(m.response_valid for m in metrics) / count,
            "schema_success_rate": sum(m.schema_valid for m in metrics) / count,
            "source_attestation_rate": sum(m.source_attested for m in metrics) / count,
            "avg_latency_ms": sum(m.latency_ms for m in metrics) / count,
            "avg_cost_usd": sum(m.total_cost for m in metrics) / count,
            "total_cost_usd": sum(m.total_cost for m in metrics),
            "avg_reasoning_tokens": sum(m.reasoning_tokens for m in metrics) / count,
            "avg_source_count": sum(m.source_count for m in metrics) / count,
            "avg_web_search_calls": sum(m.web_search_calls for m in metrics) / count,
        }
