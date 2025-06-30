"""
Performance metrics collection for prompt caching A/B testing
Tracks latency, costs, and token usage for baseline and cached comparisons
"""
import time
import json
import os
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


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
    cache_write_cost: float = 0.0
    cache_read_cost: float = 0.0
    total_cost: float = 0.0
    cache_enabled: bool = False
    cache_hit: bool = False
    prompt_size_chars: int = 0
    response_valid: bool = True
    json_parsed: bool = True
    error_message: Optional[str] = None


class PerformanceTracker:
    """Tracks and logs performance metrics for prompt caching comparison"""
    
    # Anthropic pricing per 1M tokens (as of Dec 2024)
    PRICING = {
        'claude-sonnet-4-20250514': {
            'input': 3.00,
            'output': 15.00,
            'cache_write': 3.75,
            'cache_read': 0.30
        }
    }
    
    def __init__(self, log_file: str = "performance_metrics.jsonl"):
        """Initialize the performance tracker
        
        Args:
            log_file: Path to JSONL file for storing metrics
        """
        self.log_file = log_file
        self.current_request_id = None
        self.current_metrics = None
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
        
        print(f"DEBUG: Performance tracker initialized, logging to {log_file}")
    
    def start_request(self, query: str, model: str = "claude-sonnet-4-20250514", 
                     prompt_type: str = "threat_intel", cache_enabled: bool = False) -> str:
        """Start tracking a new API request
        
        Args:
            query: The query being executed
            model: Claude model being used
            prompt_type: Type of prompt (e.g., "threat_intel", "validation")
            cache_enabled: Whether prompt caching is enabled
            
        Returns:
            Request ID for tracking
        """
        request_id = f"{prompt_type}_{int(time.time() * 1000)}"
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
            cache_enabled=cache_enabled
        )
        
        print(f"DEBUG: Started tracking request {request_id} for query: {query[:50]}...")
        return request_id
    
    def record_prompt_details(self, prompt_content: str, cache_enabled: bool = False):
        """Record details about the prompt being sent
        
        Args:
            prompt_content: The actual prompt content
            cache_enabled: Whether caching is enabled for this prompt
        """
        if not self.current_metrics:
            print("DEBUG: Warning - No active request to record prompt for")
            return
        
        self.current_metrics.prompt_size_chars = len(prompt_content)
        self.current_metrics.cache_enabled = cache_enabled
        
        print(f"DEBUG: Recorded prompt details - size: {len(prompt_content)} chars, caching: {cache_enabled}")
    
    def record_api_response(self, response, cache_hit: bool = False, 
                           time_to_first_token: Optional[float] = None):
        """Record API response metrics
        
        Args:
            response: Anthropic API response object
            cache_hit: Whether this was a cache hit
            time_to_first_token: Time to first token in seconds
        """
        if not self.current_metrics:
            print("DEBUG: Warning - No active request to record response for")
            return
        
        end_time = time.time()
        self.current_metrics.end_time = end_time
        self.current_metrics.latency_ms = int((end_time - self.current_metrics.start_time) * 1000)
        self.current_metrics.cache_hit = cache_hit
        
        if time_to_first_token:
            self.current_metrics.time_to_first_token_ms = int(time_to_first_token * 1000)
        
        # Extract token usage from response
        if hasattr(response, 'usage'):
            usage = response.usage
            self.current_metrics.input_tokens = getattr(usage, 'input_tokens', 0)
            self.current_metrics.output_tokens = getattr(usage, 'output_tokens', 0)
            
            # Check for cache-specific token counts
            if hasattr(usage, 'cache_creation_input_tokens'):
                # For cache writes
                cache_write_tokens = getattr(usage, 'cache_creation_input_tokens', 0)
                self.current_metrics.cached_tokens = cache_write_tokens
            elif hasattr(usage, 'cache_read_input_tokens'):
                # For cache reads
                cache_read_tokens = getattr(usage, 'cache_read_input_tokens', 0)
                self.current_metrics.cached_tokens = cache_read_tokens
        
        # Calculate costs
        self._calculate_costs()
        
        print(f"DEBUG: Recorded API response - latency: {self.current_metrics.latency_ms}ms, "
              f"tokens: {self.current_metrics.input_tokens}+{self.current_metrics.output_tokens}, "
              f"cache_hit: {cache_hit}")
    
    def record_error(self, error: Exception):
        """Record an error that occurred during the request
        
        Args:
            error: The exception that occurred
        """
        if not self.current_metrics:
            print("DEBUG: Warning - No active request to record error for")
            return
        
        self.current_metrics.end_time = time.time()
        self.current_metrics.latency_ms = int((self.current_metrics.end_time - self.current_metrics.start_time) * 1000)
        self.current_metrics.response_valid = False
        self.current_metrics.error_message = str(error)
        
        print(f"DEBUG: Recorded error for request {self.current_request_id}: {error}")
    
    def record_parsing_result(self, success: bool, error: Optional[str] = None):
        """Record JSON parsing success/failure
        
        Args:
            success: Whether JSON parsing succeeded
            error: Error message if parsing failed
        """
        if not self.current_metrics:
            return
        
        self.current_metrics.json_parsed = success
        if not success and error:
            self.current_metrics.error_message = error
    
    def finish_request(self) -> Optional[APIMetrics]:
        """Finish tracking the current request and save metrics
        
        Returns:
            The completed metrics object
        """
        if not self.current_metrics:
            print("DEBUG: Warning - No active request to finish")
            return None
        
        # Ensure end time is set
        if self.current_metrics.end_time == 0.0:
            self.current_metrics.end_time = time.time()
            self.current_metrics.latency_ms = int((self.current_metrics.end_time - self.current_metrics.start_time) * 1000)
        
        # Final cost calculation
        self._calculate_costs()
        
        # Save to log file
        self._save_metrics(self.current_metrics)
        
        metrics = self.current_metrics
        self.current_metrics = None
        self.current_request_id = None
        
        print(f"DEBUG: Finished tracking request {metrics.request_id}")
        return metrics
    
    def _calculate_costs(self):
        """Calculate costs based on token usage and pricing"""
        if not self.current_metrics:
            return
        
        model = self.current_metrics.model
        pricing = self.PRICING.get(model, self.PRICING['claude-sonnet-4-20250514'])
        
        # Base costs
        self.current_metrics.input_cost = (self.current_metrics.input_tokens / 1_000_000) * pricing['input']
        self.current_metrics.output_cost = (self.current_metrics.output_tokens / 1_000_000) * pricing['output']
        
        # Cache costs
        if self.current_metrics.cache_enabled and self.current_metrics.cached_tokens > 0:
            if self.current_metrics.cache_hit:
                # Cache read cost
                self.current_metrics.cache_read_cost = (self.current_metrics.cached_tokens / 1_000_000) * pricing['cache_read']
            else:
                # Cache write cost
                self.current_metrics.cache_write_cost = (self.current_metrics.cached_tokens / 1_000_000) * pricing['cache_write']
        
        # Total cost
        self.current_metrics.total_cost = (
            self.current_metrics.input_cost + 
            self.current_metrics.output_cost + 
            self.current_metrics.cache_write_cost + 
            self.current_metrics.cache_read_cost
        )
    
    def _save_metrics(self, metrics: APIMetrics):
        """Save metrics to the log file"""
        try:
            with open(self.log_file, 'a') as f:
                json.dump(asdict(metrics), f)
                f.write('\n')
        except Exception as e:
            print(f"DEBUG: Failed to save metrics: {e}")
    
    def load_metrics(self) -> list[APIMetrics]:
        """Load all metrics from the log file
        
        Returns:
            List of APIMetrics objects
        """
        metrics = []
        if not os.path.exists(self.log_file):
            return metrics
        
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line.strip())
                        metrics.append(APIMetrics(**data))
        except Exception as e:
            print(f"DEBUG: Failed to load metrics: {e}")
        
        return metrics
    
    def generate_comparison_report(self, baseline_metrics: list[APIMetrics], 
                                 cached_metrics: list[APIMetrics]) -> Dict[str, Any]:
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
                'count': len(valid_metrics),
                'avg_latency_ms': sum(latencies) / len(latencies),
                'avg_cost_usd': sum(costs) / len(costs),
                'avg_input_tokens': sum(input_tokens) / len(input_tokens),
                'total_cost_usd': sum(costs)
            }
        
        baseline_stats = calc_stats(baseline_metrics)
        cached_stats = calc_stats(cached_metrics)
        
        if not baseline_stats or not cached_stats:
            return {'error': 'Insufficient data for comparison'}
        
        # Calculate improvements
        latency_improvement = ((baseline_stats['avg_latency_ms'] - cached_stats['avg_latency_ms']) / 
                             baseline_stats['avg_latency_ms']) * 100
        
        cost_improvement = ((baseline_stats['avg_cost_usd'] - cached_stats['avg_cost_usd']) / 
                          baseline_stats['avg_cost_usd']) * 100
        
        return {
            'baseline': baseline_stats,
            'cached': cached_stats,
            'improvements': {
                'latency_reduction_percent': latency_improvement,
                'cost_reduction_percent': cost_improvement,
                'latency_reduction_ms': baseline_stats['avg_latency_ms'] - cached_stats['avg_latency_ms']
            },
            'summary': {
                'baseline_avg_latency': f"{baseline_stats['avg_latency_ms']:.0f}ms",
                'cached_avg_latency': f"{cached_stats['avg_latency_ms']:.0f}ms",
                'improvement': f"{latency_improvement:.1f}% faster",
                'cost_reduction': f"{cost_improvement:.1f}% cheaper"
            }
        }