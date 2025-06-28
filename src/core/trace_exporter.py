"""
Trace Exporter for SentrySearch-Annotator Integration

Captures detailed traces of the threat intelligence generation process including:
- Hybrid retrieval results (vector, BM25, fusion)
- ML guidance generation
- Quality validation steps
- Web search sources and metadata

Exports traces in the format expected by SentrySearch-Annotator tool.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import os


@dataclass
class ThreatCharacteristics:
    """Threat characteristics for ML guidance generation"""
    threat_name: str
    threat_type: str
    attack_vectors: List[str]
    target_assets: List[str]
    behavior_patterns: List[str]
    time_characteristics: str


@dataclass
class RetrievalResult:
    """Individual retrieval result from vector or BM25"""
    content: str
    metadata: Dict[str, Any]
    score: float
    method: str  # "vector", "bm25", "hybrid"
    matched_terms: Optional[List[str]] = None
    source_company: Optional[str] = None
    ml_techniques: List[str] = None
    
    def __post_init__(self):
        if self.ml_techniques is None:
            self.ml_techniques = []


@dataclass
class HybridScoring:
    """Hybrid scoring breakdown for analysis"""
    vector_score: float
    bm25_score: float
    hybrid_score: float
    applicability_score: float
    fusion_method: str = "reciprocal_rank_fusion"
    rrf_k: int = 60


@dataclass
class QueryOptimization:
    """Query optimization trace"""
    original_query: str
    optimized_queries: List[str]
    ml_focus_areas: List[str]
    reasoning: str
    source_selection: Dict[str, List[str]]


@dataclass
class MLTechnique:
    """ML technique recommendation with metadata"""
    name: str
    category: str
    complexity: str  # "Low", "Medium", "High"
    company_source: str
    implementation_details: str
    applicability_score: float


class TraceExporter:
    """Exports SentrySearch execution traces for annotator tool integration"""
    
    def __init__(self, export_dir: str = "./traces"):
        """Initialize trace exporter
        
        Args:
            export_dir: Directory to export trace files
        """
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(exist_ok=True)
        self.current_trace = None
    
    def start_trace(self, tool_name: str) -> str:
        """Start a new trace for threat intelligence generation
        
        Args:
            tool_name: Name of the threat/tool being analyzed
            
        Returns:
            Trace ID for this execution
        """
        trace_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        self.current_trace = {
            "trace_id": trace_id,
            "timestamp": timestamp.isoformat() + "Z",
            "tool_name": tool_name,
            "start_time": timestamp,
            "pipeline_version": "1.0.0",
            "knowledge_base_version": "2024-06",
            
            # Processing stages
            "stages": {
                "initialization": {"start_time": timestamp},
                "web_search": {},
                "query_optimization": {},
                "vector_retrieval": {},
                "bm25_retrieval": {},
                "hybrid_fusion": {},
                "ml_guidance": {},
                "quality_validation": {},
                "completion": {}
            },
            
            # Results storage
            "threat_characteristics": None,
            "query_optimization": None,
            "vector_results": [],
            "bm25_results": [],
            "hybrid_results": [],
            "hybrid_scoring": None,
            "ml_techniques": [],
            "final_guidance": "",
            "web_search_sources": [],
            "quality_metrics": {},
            "processing_times": {},
            "errors": [],
            "warnings": []
        }
        
        print(f"Started trace {trace_id} for {tool_name}")
        return trace_id
    
    def log_stage_start(self, stage_name: str):
        """Log the start of a processing stage"""
        if self.current_trace and stage_name in self.current_trace["stages"]:
            self.current_trace["stages"][stage_name]["start_time"] = datetime.utcnow()
    
    def log_stage_end(self, stage_name: str, **kwargs):
        """Log the end of a processing stage with optional metadata"""
        if self.current_trace and stage_name in self.current_trace["stages"]:
            stage_data = self.current_trace["stages"][stage_name]
            stage_data["end_time"] = datetime.utcnow()
            
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
                "time_characteristics": characteristics.get("time_characteristics", "persistent")
            }
    
    def log_query_optimization(self, original_query: str, optimized_queries: List[str], 
                             reasoning: str, ml_focus_areas: List[str] = None):
        """Log query optimization details"""
        if self.current_trace:
            self.current_trace["query_optimization"] = {
                "original_query": original_query,
                "optimized_queries": optimized_queries,
                "ml_focus_areas": ml_focus_areas or [],
                "reasoning": reasoning,
                "source_selection": {
                    "companies": ["Netflix", "LinkedIn", "Cloudflare", "Meta", "Uber"],
                    "techniques": ["anomaly_detection", "behavioral_analysis", "graph_analysis"]
                }
            }
    
    def log_retrieval_results(self, results: List[Dict], method: str):
        """Log retrieval results from vector, BM25, or hybrid search
        
        Args:
            results: List of retrieval results
            method: "vector", "bm25", or "hybrid"
        """
        if not self.current_trace:
            return
        
        processed_results = []
        for result in results:
            processed_result = {
                "content": result.get("content", ""),
                "metadata": result.get("metadata", {}),
                "score": float(result.get("score", 0.0)),
                "method": method,
                "matched_terms": result.get("matched_terms"),
                "source_company": self._extract_company(result),
                "ml_techniques": self._extract_ml_techniques(result)
            }
            processed_results.append(processed_result)
        
        if method == "vector":
            self.current_trace["vector_results"] = processed_results
        elif method == "bm25":
            self.current_trace["bm25_results"] = processed_results
        elif method == "hybrid":
            self.current_trace["hybrid_results"] = processed_results
    
    def log_hybrid_scoring(self, vector_score: float, bm25_score: float, 
                          hybrid_score: float, applicability_score: float):
        """Log hybrid scoring breakdown"""
        if self.current_trace:
            self.current_trace["hybrid_scoring"] = {
                "vector_score": vector_score,
                "bm25_score": bm25_score,
                "hybrid_score": hybrid_score,
                "applicability_score": applicability_score,
                "fusion_method": "reciprocal_rank_fusion",
                "rrf_k": 60
            }
    
    def log_ml_techniques(self, techniques: List[Dict]):
        """Log ML technique recommendations"""
        if not self.current_trace:
            return
        
        processed_techniques = []
        for tech in techniques:
            processed_tech = {
                "name": tech.get("name", ""),
                "category": tech.get("category", ""),
                "complexity": tech.get("complexity", "Medium"),
                "company_source": tech.get("company_source", "Unknown"),
                "implementation_details": tech.get("implementation_details", ""),
                "applicability_score": float(tech.get("applicability_score", 0.0))
            }
            processed_techniques.append(processed_tech)
        
        self.current_trace["ml_techniques"] = processed_techniques
    
    def log_web_search_sources(self, sources: List[Dict]):
        """Log web search sources used"""
        if self.current_trace:
            self.current_trace["web_search_sources"] = sources
    
    def log_final_guidance(self, guidance: str):
        """Log final threat intelligence guidance"""
        if self.current_trace:
            self.current_trace["final_guidance"] = guidance
    
    def log_quality_metrics(self, metrics: Dict):
        """Log quality validation metrics"""
        if self.current_trace:
            self.current_trace["quality_metrics"] = metrics
    
    def log_error(self, error: str, stage: str = None):
        """Log an error during processing"""
        if self.current_trace:
            error_entry = {
                "error": error,
                "timestamp": datetime.utcnow().isoformat(),
                "stage": stage
            }
            self.current_trace["errors"].append(error_entry)
    
    def log_warning(self, warning: str, stage: str = None):
        """Log a warning during processing"""
        if self.current_trace:
            warning_entry = {
                "warning": warning,
                "timestamp": datetime.utcnow().isoformat(),
                "stage": stage
            }
            self.current_trace["warnings"].append(warning_entry)
    
    def complete_trace(self, final_profile: Dict = None) -> str:
        """Complete the current trace and export to file
        
        Args:
            final_profile: Complete threat intelligence profile (optional)
            
        Returns:
            Path to exported trace file
        """
        if not self.current_trace:
            raise ValueError("No active trace to complete")
        
        # Finalize trace
        self.current_trace["stages"]["completion"]["end_time"] = datetime.utcnow()
        total_duration = (
            self.current_trace["stages"]["completion"]["end_time"] - 
            self.current_trace["start_time"]
        ).total_seconds()
        self.current_trace["processing_time_ms"] = int(total_duration * 1000)
        
        # Auto-flag problematic traces
        is_flagged, flag_reasons = self._check_for_flags()
        self.current_trace["is_flagged"] = is_flagged
        self.current_trace["flag_reasons"] = flag_reasons
        
        # Clean up internal fields
        trace_for_export = self.current_trace.copy()
        trace_for_export.pop("start_time", None)
        
        # Convert datetime objects to ISO strings
        self._serialize_datetimes(trace_for_export)
        
        # Export to file
        filename = f"trace_{self.current_trace['trace_id']}.json"
        filepath = self.export_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(trace_for_export, f, indent=2, default=str)
        
        print(f"Exported trace to {filepath}")
        
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
            "phishing": "phishing"
        }
        
        return threat_type_mapping.get(category, "malware")
    
    def _extract_company(self, result: Dict) -> Optional[str]:
        """Extract company source from retrieval result"""
        metadata = result.get("metadata", {})
        
        # Check various metadata fields for company information
        for field in ["company", "source", "organization", "vendor"]:
            if field in metadata:
                return str(metadata[field])
        
        # Check content for company mentions
        content = result.get("content", "").lower()
        companies = ["netflix", "linkedin", "cloudflare", "meta", "uber", "google", "microsoft"]
        
        for company in companies:
            if company in content:
                return company.title()
        
        return None
    
    def _extract_ml_techniques(self, result: Dict) -> List[str]:
        """Extract ML techniques mentioned in retrieval result"""
        content = result.get("content", "").lower()
        techniques = []
        
        ml_keywords = {
            "isolation forest": "isolation_forest",
            "anomaly detection": "anomaly_detection",
            "lstm": "lstm",
            "autoencoder": "autoencoder",
            "random forest": "random_forest",
            "svm": "svm",
            "clustering": "clustering",
            "graph analysis": "graph_analysis",
            "behavioral analysis": "behavioral_analysis"
        }
        
        for keyword, technique in ml_keywords.items():
            if keyword in content:
                techniques.append(technique)
        
        return techniques
    
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
    
    def _check_for_flags(self) -> tuple:
        """Check if trace should be flagged for review"""
        flags = []
        
        # Check for low hybrid scores
        hybrid_scoring = self.current_trace.get("hybrid_scoring", {})
        hybrid_score = hybrid_scoring.get("hybrid_score", 0)
        
        if hybrid_score < 0.3:
            flags.append("low_hybrid_score")
        
        # Check for missing ML techniques
        ml_techniques = self.current_trace.get("ml_techniques", [])
        if not ml_techniques:
            flags.append("no_ml_techniques")
        
        # Check for processing errors
        if self.current_trace.get("errors"):
            flags.append("processing_errors")
        
        # Check for insufficient guidance
        final_guidance = self.current_trace.get("final_guidance", "").strip()
        if not final_guidance or len(final_guidance) < 100:
            flags.append("insufficient_guidance")
        
        # Check for empty retrieval results
        if (not self.current_trace.get("vector_results") and 
            not self.current_trace.get("bm25_results") and 
            not self.current_trace.get("hybrid_results")):
            flags.append("no_retrieval_results")
        
        return len(flags) > 0, flags


# Global trace exporter instance
_trace_exporter = None

def get_trace_exporter(export_dir: str = "./traces") -> TraceExporter:
    """Get global trace exporter instance"""
    global _trace_exporter
    if _trace_exporter is None:
        _trace_exporter = TraceExporter(export_dir)
    return _trace_exporter