"""
Trace Exporter for SentrySearch-Annotator Integration

Captures detailed traces of the threat intelligence generation process including:
- Quality validation steps
- Web search sources and metadata

Exports traces in the format expected by SentrySearch-Annotator tool.
"""

import json
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


class TraceExporter:
    """Exports SentrySearch execution traces for annotator tool integration"""

    def __init__(self, export_dir: str = "./traces"):
        """Initialize trace exporter

        Args:
            export_dir: Directory to export trace files
        """
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)
        self._current_trace: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
            f"trace_{id(self)}", default=None
        )

    @property
    def current_trace(self) -> Optional[Dict[str, Any]]:
        return self._current_trace.get()

    @current_trace.setter
    def current_trace(self, value: Optional[Dict[str, Any]]) -> None:
        self._current_trace.set(value)

    def start_trace(self, tool_name: str) -> str:
        """Start a new trace for threat intelligence generation

        Args:
            tool_name: Name of the threat/tool being analyzed

        Returns:
            Trace ID for this execution
        """
        trace_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)

        self.current_trace = {
            "trace_id": trace_id,
            "timestamp": timestamp.isoformat(),
            "tool_name": tool_name,
            "start_time": timestamp,
            "pipeline_version": "1.0.0",
            "knowledge_base_version": "2024-06",
            # Processing stages
            "stages": {
                "initialization": {"start_time": timestamp},
                "web_search": {},
                "quality_validation": {},
                "completion": {},
            },
            # Results storage
            "threat_characteristics": None,
            "final_guidance": "",
            "web_search_sources": [],
            "model_tool_events": [],
            "quality_metrics": {},
            "processing_times": {},
            "errors": [],
            "warnings": [],
        }

        logger.debug("Started trace %s for %s", trace_id, tool_name)
        return trace_id

    def log_stage_start(self, stage_name: str):
        """Log the start of a processing stage"""
        if self.current_trace and stage_name in self.current_trace["stages"]:
            self.current_trace["stages"][stage_name]["start_time"] = datetime.now(timezone.utc)

    def log_stage_end(self, stage_name: str, **kwargs):
        """Log the end of a processing stage with optional metadata"""
        if self.current_trace and stage_name in self.current_trace["stages"]:
            stage_data = self.current_trace["stages"][stage_name]
            stage_data["end_time"] = datetime.now(timezone.utc)

            if "start_time" in stage_data:
                duration = (stage_data["end_time"] - stage_data["start_time"]).total_seconds()
                stage_data["duration_ms"] = int(duration * 1000)

            # Add any additional metadata
            stage_data.update(kwargs)

    def log_threat_characteristics(self, characteristics: Dict[str, Any]):
        """Log extracted threat characteristics"""
        if self.current_trace:
            self.current_trace["threat_characteristics"] = {
                "threat_name": characteristics.get("threat_name", self.current_trace["tool_name"]),
                "threat_type": self._infer_threat_type(characteristics),
                "attack_vectors": characteristics.get("attack_vectors", []),
                "target_assets": characteristics.get("target_assets", []),
                "behavior_patterns": characteristics.get("behavior_patterns", []),
                "time_characteristics": characteristics.get("time_characteristics", "persistent"),
            }

    def log_web_search_sources(self, sources: List[Dict]):
        """Log web search sources used"""
        if self.current_trace:
            self.current_trace["web_search_sources"] = sources

    def log_model_tool_events(self, events: List[Dict]):
        """Log sanitized hosted-tool execution metadata from the model response."""
        if self.current_trace:
            self.current_trace["model_tool_events"] = events

    def log_final_guidance(self, guidance: str):
        """Log final threat intelligence guidance"""
        if self.current_trace:
            self.current_trace["final_guidance"] = guidance

    def log_quality_metrics(self, metrics: Dict):
        """Log quality validation metrics"""
        if self.current_trace:
            self.current_trace["quality_metrics"] = metrics

    def log_error(self, error: str, stage: str | None = None):
        """Log an error during processing"""
        if self.current_trace:
            error_entry = {
                "error": error,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stage": stage,
            }
            self.current_trace["errors"].append(error_entry)

    def log_warning(self, warning: str, stage: str | None = None):
        """Log a warning during processing"""
        if self.current_trace:
            warning_entry = {
                "warning": warning,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stage": stage,
            }
            self.current_trace["warnings"].append(warning_entry)

    def complete_trace(self, final_profile: Optional[Dict] = None) -> str:
        """Complete the current trace and export to file

        Args:
            final_profile: Complete threat intelligence profile (optional)

        Returns:
            Path to exported trace file
        """
        trace = self.current_trace
        if not trace:
            raise ValueError("No active trace to complete")

        # Finalize trace
        trace["stages"]["completion"]["end_time"] = datetime.now(timezone.utc)
        total_duration = (
            trace["stages"]["completion"]["end_time"] - trace["start_time"]
        ).total_seconds()
        trace["processing_time_ms"] = int(total_duration * 1000)

        # Auto-flag problematic traces
        is_flagged, flag_reasons = self._check_for_flags(trace)
        trace["is_flagged"] = is_flagged
        trace["flag_reasons"] = flag_reasons

        # Clean up internal fields
        trace_for_export = trace.copy()
        trace_for_export.pop("start_time", None)

        # Convert datetime objects to ISO strings
        self._serialize_datetimes(trace_for_export)

        # Export to file
        filename = f"trace_{trace['trace_id']}.json"
        filepath = self.export_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(trace_for_export, f, indent=2, default=str)

        logger.debug("Exported trace to %s", filepath)

        # Reset current trace
        self.current_trace = None

        return str(filepath)

    def _infer_threat_type(self, characteristics: Dict) -> str:
        """Infer threat type from characteristics"""
        category = characteristics.get("category", "").lower()

        threat_type_mapping = {
            "rat": "malware",
            "backdoor": "malware",
            "trojan": "malware",
            "ransomware": "ransomware",
            "botnet": "bot",
            "apt": "apt",
            "phishing": "phishing",
        }

        return threat_type_mapping.get(category, "malware")

    def _serialize_datetimes(self, obj):
        """Recursively serialize datetime objects to ISO strings"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, datetime):
                    obj[key] = value.isoformat() + "Z"
                elif isinstance(value, (dict, list)):
                    self._serialize_datetimes(value)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, datetime):
                    obj[i] = item.isoformat() + "Z"
                elif isinstance(item, (dict, list)):
                    self._serialize_datetimes(item)

    def _check_for_flags(self, trace: Dict[str, Any]) -> tuple:
        """Check if trace should be flagged for review"""
        flags = []

        # Check for processing errors
        if trace.get("errors"):
            flags.append("processing_errors")

        # Check for insufficient guidance
        final_guidance = trace.get("final_guidance", "").strip()
        if not final_guidance or len(final_guidance) < 100:
            flags.append("insufficient_guidance")

        return len(flags) > 0, flags


def get_trace_exporter(export_dir: str = "./traces") -> TraceExporter:
    """Create an exporter whose lifecycle is owned by one generator instance."""

    return TraceExporter(export_dir)
