"""
Threat profile generator backed by OpenRouter through the OpenAI SDK.
Enhanced with ML-based anomaly detection guidance and trace export for annotator integration.
"""

import os
import json
import logging
from src.core.openai_client import (
    create_model_client,
    resolve_model_name,
)
from src.core.model_retry import RetryingModelRequests
from typing import Dict, Any, Optional
from datetime import datetime
import time
from src.core.section_validator import SectionValidator
from src.core.ml_guidance_generator import MLGuidanceGenerator, ThreatCharacteristics
from src.core.trace_exporter import get_trace_exporter
from src.core.performance_metrics import PerformanceTracker
from src.core.threat_profile_schema import (
    ThreatProfile,
    attest_profile_sources,
    parse_threat_profile_response,
)

logger = logging.getLogger(__name__)


class ThreatProfileGenerator(RetryingModelRequests):
    def __init__(
        self,
        enable_tracing=True,
        trace_export_dir="./traces",
        enable_metrics=True,
        metrics_file="performance_metrics.jsonl",
    ):
        """Initialize the configured model client."""
        self.client = create_model_client()
        self.validator = SectionValidator(self.client)
        self.enable_quality_control = True

        # Initialize performance metrics tracking
        self.enable_metrics = enable_metrics
        if self.enable_metrics:
            self.performance_tracker = PerformanceTracker(metrics_file)
            logger.debug(f"Performance metrics enabled, logging to {metrics_file}")
        else:
            self.performance_tracker = None

        # Initialize trace exporter
        self.enable_tracing = enable_tracing
        if self.enable_tracing:
            self.trace_exporter = get_trace_exporter(trace_export_dir)
            logger.debug(f"Trace exporter initialized, export directory: {trace_export_dir}")
        else:
            self.trace_exporter = None

        # Initialize ML guidance generator
        try:
            self.ml_guidance_generator: MLGuidanceGenerator | None = MLGuidanceGenerator(
                self.client
            )
            self.enable_ml_guidance = True
            logger.debug("ML guidance generator initialized successfully")
        except Exception as e:
            logger.info("ML guidance is unavailable: %s", e)
            self.ml_guidance_generator = None
            self.enable_ml_guidance = False

    def get_threat_intelligence(self, tool_name: str, progress_callback=None):
        """
        Generate comprehensive threat intelligence profile using the configured model.

        Args:
            tool_name: Name of the tool/threat to analyze
            progress_callback: Optional callback for progress updates

        Returns:
            dict: Threat intelligence data with quality assessment
        """
        # Start trace
        trace_id = None
        if self.enable_tracing and self.trace_exporter:
            trace_id = self.trace_exporter.start_trace(tool_name)
            self.trace_exporter.log_stage_start("initialization")

        try:
            if progress_callback:
                progress_callback(0.1, "Initializing research...")

            logger.debug(f"Starting threat intelligence generation for: {tool_name}")

            if self.enable_tracing and self.trace_exporter:
                self.trace_exporter.log_stage_end("initialization")

            # Start performance tracking
            if self.enable_metrics and self.performance_tracker:
                self.performance_tracker.start_request(
                    query=tool_name,
                    model=resolve_model_name(),
                    prompt_type="threat_intel_main",
                    cache_enabled=False,  # Baseline measurement
                )

            # ENHANCED PROMPT - Triggers model's research mode with comprehensive web search
            prompt = f"""Conduct comprehensive research and deep dive analysis to generate a detailed threat intelligence profile for: {tool_name}

Today's date is {datetime.now().strftime('%B %d, %Y')}.

CRITICAL: You MUST use the web search tool extensively to find the most current, verified information. Do NOT hallucinate or invent URLs, sources, or information. All sources must be real and accessible through your web search tool.

Please perform a thorough deep dive research using the web search tool to find comprehensive information about {tool_name}, including:
- Recent vulnerabilities and exploits (search for CVEs, security advisories)
- Technical details and architecture (search for technical analyses, documentation)
- Indicators of compromise (IOCs) (search for threat intelligence reports, IOC feeds)
- Threat actor associations (search for attribution reports, campaign analyses)
- Detection methods and mitigations (search for security vendor reports, YARA rules)
- Recent security advisories or reports (search across security vendor sites, MITRE, NIST)

SEARCH STRATEGY: Use multiple specific search queries to gather comprehensive intelligence:
1. "{tool_name} malware analysis"
2. "{tool_name} threat intelligence report"
3. "{tool_name} IOCs indicators compromise"
4. "{tool_name} detection signatures YARA"
5. "{tool_name} vulnerability CVE"
6. "{tool_name} security advisory"

Focus on finding information from the most recent 24 months when possible, but include relevant historical context.

Based on your comprehensive research findings, create a detailed profile in the following JSON format:

{{
  "coreMetadata": {{
    "name": "{tool_name}",
    "version": "Latest known version from research",
    "category": "Tool category (RAT/Backdoor/Trojan/etc)",
    "profileId": "TI_{tool_name.upper().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}",
    "profileAuthor": "OpenRouter model pipeline",
    "createdDate": "{datetime.now().strftime('%Y-%m-%d')}",
    "lastUpdated": "{datetime.now().strftime('%Y-%m-%d')}",
    "profileVersion": "1.0",
    "tlpClassification": "TLP:AMBER",
    "trustScore": "Based on source quality"
  }},
  "webSearchSources": {{
    "searchQueriesUsed": ["REQUIRED: List the actual search queries you executed"],
    "primarySources": [
      {{
        "url": "REQUIRED: Real, accessible URL from your web search tool results - NO hallucinated URLs",
        "title": "REQUIRED: Actual title from the web search tool results",
        "domain": "REQUIRED: Actual domain name from web search tool results",
        "accessDate": "{datetime.now().strftime('%Y-%m-%d')}",
        "relevanceScore": "High/Medium/Low based on content relevance",
        "contentType": "Report/Article/Advisory/Blog/Database/Documentation",
        "keyFindings": "REQUIRED: Specific information extracted from this real source"
      }}
    ],
    "searchStrategy": "REQUIRED: Describe your actual web search tool approach and methodology",
    "dataFreshness": "REQUIRED: How recent the web search tool information is",
    "sourceReliability": "REQUIRED: Assessment based on actual domain authority and content quality from web search tool"
  }},
  "toolOverview": {{
    "description": "Comprehensive description based on findings",
    "primaryPurpose": "Main purpose of the tool",
    "targetAudience": "Who typically uses it (legitimate and malicious)",
    "knownAliases": ["Alternative names found"],
    "firstSeen": "First discovery/release date",
    "lastUpdated": "Most recent activity",
    "currentStatus": "Active/Inactive/Unknown"
  }},
  "technicalDetails": {{
    "architecture": "Technical architecture details",
    "operatingSystems": ["Supported operating systems"],
    "dependencies": ["Required dependencies"],
    "encryption": "Encryption methods used",
    "obfuscation": "Obfuscation techniques",
    "persistence": ["Persistence mechanisms"],
    "capabilities": ["Key capabilities and features"]
  }},
  "commandAndControl": {{
    "communicationMethods": "C2 communication methods",
    "commandProtocols": [
      {{
        "protocolName": "Protocol name",
        "encoding": "Encoding method",
        "encryption": "Encryption used",
        "detectionNotes": "Detection guidance"
      }}
    ],
    "beaconingPatterns": [
      {{
        "pattern": "Pattern description",
        "frequency": "Beacon frequency",
        "indicators": ["Network indicators"]
      }}
    ],
    "commonCommands": ["Common commands used"]
  }},
  "threatIntelligence": {{
    "entities": {{
      "threatActors": [
        {{
          "name": "Threat actor name",
          "attribution": "Attribution confidence",
          "activityTimeframe": "When active"
        }}
      ],
      "campaigns": [
        {{
          "name": "Campaign name",
          "timeframe": "Campaign timeframe",
          "targetSectors": ["Targeted sectors"],
          "geographicFocus": "Geographic targets"
        }}
      ]
    }},
    "riskAssessment": {{
      "overallRisk": "High/Medium/Low",
      "impactRating": "Impact assessment",
      "likelihoodRating": "Likelihood assessment",
      "riskFactors": ["Key risk factors"]
    }}
  }},
  "forensicArtifacts": {{
    "fileSystemArtifacts": ["File paths and names"],
    "registryArtifacts": ["Registry keys"],
    "networkArtifacts": ["Network artifacts"],
    "memoryArtifacts": ["Memory artifacts"],
    "logArtifacts": ["Log patterns"]
  }},
  "detectionAndMitigation": {{
    "iocs": {{
      "hashes": ["File hashes"],
      "domains": ["Malicious domains"],
      "ips": ["Malicious IP addresses"],
      "urls": ["Malicious URLs"],
      "filenames": ["Malicious filenames"]
    }},
    "behavioralIndicators": ["Behavioral patterns for detection"]
  }},
  "mitigationAndResponse": {{
    "preventiveMeasures": ["Prevention recommendations"],
    "detectionMethods": ["Detection methods"],
    "responseActions": ["Incident response actions"],
    "recoveryGuidance": ["Recovery steps"]
  }},
  "referencesAndIntelligenceSharing": {{
    "sources": [
      {{
        "title": "Source title",
        "url": "URL from web search tool results",
        "date": "Publication date",
        "relevanceScore": "High/Medium/Low"
      }}
    ],
    "mitreAttackMapping": "MITRE ATT&CK techniques",
    "cveReferences": "Related CVEs",
    "additionalReferences": ["Other relevant sources"]
  }},
  "integration": {{
    "siemIntegration": "SIEM integration guidance",
    "threatHuntingQueries": ["Threat hunting queries"],
    "automatedResponse": "Automation recommendations"
  }},
  "lineage": {{
    "variants": ["Known variants"],
    "evolution": "Evolution of the tool",
    "relationships": ["Related tools"]
  }},
  "contextualAnalysis": {{
    "usageContexts": {{
      "legitimateUse": "Legitimate use cases",
      "maliciousUse": "Malicious applications",
      "dualUseConsiderations": "Dual-use considerations"
    }},
    "trendAnalysis": {{
      "industryImpact": "Industry impact",
      "futureOutlook": "Future outlook",
      "adoptionTrend": "Adoption trends"
    }}
  }},
  "operationalGuidance": {{
    "validationCriteria": ["Validation criteria"],
    "communityResources": [
      {{
        "resourceType": "Type of resource",
        "name": "Resource name",
        "url": "URL from web search tool",
        "focus": "Resource focus"
      }}
    ]
  }}
}}

CRITICAL INSTRUCTIONS FOR OUTPUT:
1. Return ONLY the JSON object populated with verified information from your web search tool results
2. NEVER invent, hallucinate, or fabricate URLs, sources, or technical details
3. If you cannot find information for certain sections through the web search tool, explicitly state "No verified information found through web search tool" rather than making up content
4. All URLs in webSearchSources and referencesAndIntelligenceSharing MUST be real URLs from your actual web search tool results
5. Cross-reference claims across multiple sources when possible using the web search tool
6. If web search tool results are limited, acknowledge this limitation in the relevant sections

Remember: Accuracy and source verification through the web search tool are more important than completeness. Real, verified information from web search is infinitely more valuable than hallucinated content."""

            # Record prompt details for metrics
            if self.enable_metrics and self.performance_tracker:
                self.performance_tracker.record_prompt_details(prompt, cache_enabled=False)

            if progress_callback:
                progress_callback(0.2, "Researching with web search...")

            logger.debug("Sending request to model API with web search tool enabled...")
            logger.debug(f"Prompt size: {len(prompt)} characters")

            # Log web search stage
            if self.enable_tracing and self.trace_exporter:
                self.trace_exporter.log_stage_start("web_search")

            # Generate threat intelligence using model with retry logic
            api_start_time = time.time()
            response = self._request_model(
                model=resolve_model_name(),
                # The full profile is returned as a single JSON object; cap output at
                # the model's ceiling so a large profile isn't truncated mid-JSON
                # (which leaves the object unparseable and fails the whole report).
                max_tokens=16384,
                temperature=0.3,
                messages=[{"role": "user", "content": prompt}],
                tools=[{"type": "web_search"}],
                response_format=ThreatProfile,
            )

            # Record API response metrics
            if self.enable_metrics and self.performance_tracker:
                api_end_time = time.time()
                time_to_first_token = api_end_time - api_start_time  # Approximate
                self.performance_tracker.record_api_response(
                    response,
                    cache_hit=False,  # Baseline - no caching
                    time_to_first_token=time_to_first_token,
                )

            # Extract initial web search sources from the main response
            initial_sources = self.validator._extract_web_search_sources_from_response(
                response, "initial_research", tool_name
            )
            self.validator.web_search_sources.extend(initial_sources)
            logger.debug(f"Captured {len(initial_sources)} initial web search sources")

            if progress_callback:
                progress_callback(0.7, "Processing response...")
            if progress_callback:
                progress_callback(0.75, "Validating structured response...")

            json_data = parse_threat_profile_response(response)
            attest_profile_sources(json_data, response.web_search_sources)

            if self.enable_metrics and self.performance_tracker:
                self.performance_tracker.record_contract_result(
                    schema_valid=True,
                    source_attested=True,
                )

            if self.enable_tracing and self.trace_exporter:
                self.trace_exporter.log_model_tool_events(response.tool_events)
                self.trace_exporter.log_stage_end(
                    "web_search",
                    source_count=len(response.web_search_sources),
                    tool_event_count=len(response.tool_events),
                    response_id=response.response_id,
                    model=response.model,
                )

            logger.debug(
                "Structured generation successful. "
                f"Profile contains {len(json_data)} top-level sections and "
                f"{len(response.web_search_sources)} attested sources"
            )

            # Generate ML guidance BEFORE quality control to leverage all context
            if self.enable_ml_guidance and self.ml_guidance_generator:
                if progress_callback:
                    progress_callback(0.75, "Generating ML detection guidance...")

                if self.enable_tracing and self.trace_exporter:
                    self.trace_exporter.log_stage_start("ml_guidance")

                try:
                    ml_guidance = self._generate_ml_guidance(json_data, tool_name)
                    if ml_guidance:
                        json_data["mlGuidance"] = ml_guidance
                        logger.debug("ML guidance generated successfully")

                        # Log ML guidance for tracing
                        if self.enable_tracing and self.trace_exporter:
                            # Extract ML techniques from the guidance
                            ml_techniques = []
                            if isinstance(ml_guidance, dict) and "content" in ml_guidance:
                                # This would need to be enhanced to extract structured ML techniques
                                # For now, log basic info
                                pass
                            self.trace_exporter.log_stage_end("ml_guidance", success=True)
                    else:
                        logger.debug("No ML guidance generated")
                        if self.enable_tracing and self.trace_exporter:
                            self.trace_exporter.log_stage_end("ml_guidance", success=False)
                except Exception as e:
                    logger.warning("ML guidance generation failed: %s", e)
                    if self.enable_tracing and self.trace_exporter:
                        self.trace_exporter.log_error(str(e), "ml_guidance")
                        self.trace_exporter.log_stage_end(
                            "ml_guidance", success=False, error=str(e)
                        )
                    # Continue without ML guidance - don't fail the entire process

            # Quality control phase - now includes ML guidance validation
            if self.enable_quality_control:
                if progress_callback:
                    progress_callback(0.8, "Running quality validation...")

                if self.enable_tracing and self.trace_exporter:
                    self.trace_exporter.log_stage_start("quality_validation")

                # Validate the complete profile including ML guidance
                validation_results = self.validator.validate_complete_profile(
                    json_data, progress_callback, tool_name
                )

                if self.enable_tracing and self.trace_exporter:
                    self.trace_exporter.log_quality_metrics(validation_results)
                    self.trace_exporter.log_stage_end("quality_validation")

                # The validator owns iterative enhancement and returns its final
                # assessment, so no second improvement pass is needed here.
                json_data["_quality_assessment"] = validation_results

                logger.debug(
                    f"Quality control complete. Overall score: {validation_results['overall_score']}"
                )

                # Add comprehensive web search sources section to the main profile if available
                if (
                    hasattr(self.validator, "web_search_sources")
                    and self.validator.web_search_sources
                ):
                    comprehensive_sources = self.validator.generate_comprehensive_sources_section()
                    json_data["comprehensiveWebSearchSources"] = comprehensive_sources
                    logger.debug(
                        f"Added comprehensive sources section to main profile with {len(self.validator.web_search_sources)} sources"
                    )

            if progress_callback:
                progress_callback(1.0, "Analysis complete!")

            # Complete performance tracking
            if self.enable_metrics and self.performance_tracker:
                metrics = self.performance_tracker.finish_request()
                if metrics:
                    logger.debug(
                        f"Request completed - Latency: {metrics.latency_ms}ms, Cost: ${metrics.total_cost:.4f}"
                    )

            # Complete trace and export
            if self.enable_tracing and self.trace_exporter:
                try:
                    # Log comprehensive trace data
                    self.trace_exporter.log_threat_characteristics(
                        json_data.get("coreMetadata", {})
                    )
                    self.trace_exporter.log_final_guidance(json_data.get("final_guidance", ""))

                    # Log web search sources if available
                    if (
                        hasattr(self.validator, "web_search_sources")
                        and self.validator.web_search_sources
                    ):
                        self.trace_exporter.log_web_search_sources(
                            self.validator.web_search_sources
                        )

                    # Complete and export trace
                    trace_file = self.trace_exporter.complete_trace(json_data)
                    logger.debug(f"Trace exported to {trace_file}")

                    # Add trace metadata to response
                    json_data["_trace_metadata"] = {
                        "trace_id": trace_id,
                        "trace_file": trace_file,
                        "export_enabled": True,
                    }
                except Exception as trace_error:
                    logger.warning("Trace export failed: %s", trace_error)
                    # Don't fail the main process for trace export errors

            return json_data

        except Exception as e:
            logger.exception("Threat profile generation failed: %s", e)

            # Record error in performance metrics
            if self.enable_metrics and self.performance_tracker:
                self.performance_tracker.record_error(e)
                self.performance_tracker.finish_request()

            # Log error to trace if available
            if self.enable_tracing and self.trace_exporter:
                try:
                    self.trace_exporter.log_error(str(e), "main_process")
                    # Try to complete trace even on error
                    error_trace_file = self.trace_exporter.complete_trace()
                    logger.debug(f"Error trace exported to {error_trace_file}")
                except Exception as trace_error:
                    logger.warning("Failed to export error trace: %s", trace_error)

            if progress_callback:
                progress_callback(1.0, "Analysis failed")
            raise

    def _generate_ml_guidance(self, threat_data: Dict, tool_name: str) -> Optional[Dict]:
        """
        Generate comprehensive ML-based anomaly detection guidance leveraging all threat context

        Args:
            threat_data: Complete threat intelligence profile with all sections
            tool_name: Name of the threat/tool

        Returns:
            ML guidance data or None if generation fails
        """
        try:
            guidance_generator = self.ml_guidance_generator
            if guidance_generator is None:
                return None

            # Extract enhanced threat characteristics from the COMPLETE profile
            threat_characteristics = self._extract_enhanced_threat_characteristics(
                threat_data, tool_name
            )

            # Generate ML guidance using full context
            ml_guidance_markdown = guidance_generator.generate_enhanced_ml_guidance_section(
                threat_characteristics,
                threat_data,
                trace_exporter=self.trace_exporter if self.enable_tracing else None,
            )

            if ml_guidance_markdown:
                return {
                    "enabled": True,
                    "content": ml_guidance_markdown,
                    "threatCharacteristics": {
                        "name": threat_characteristics.threat_name,
                        "type": threat_characteristics.threat_type,
                        "attackVectors": threat_characteristics.attack_vectors,
                        "behaviorPatterns": threat_characteristics.behavior_patterns,
                        "timeCharacteristics": threat_characteristics.time_characteristics,
                    },
                    "contextUsed": {
                        "technicalDetails": bool(threat_data.get("technicalDetails")),
                        "commandAndControl": bool(threat_data.get("commandAndControl")),
                        "detectionAndMitigation": bool(threat_data.get("detectionAndMitigation")),
                        "threatIntelligence": bool(threat_data.get("threatIntelligence")),
                        "forensicArtifacts": bool(threat_data.get("forensicArtifacts")),
                    },
                    "generatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "generator": "Agentic RAG with Full Context",
                    "qualityScore": 0.0,  # Will be filled by validator
                }
            else:
                return None

        except Exception as e:
            logger.exception("ML guidance generation failed: %s", e)
            return {
                "enabled": False,
                "error": "ML guidance unavailable",
                "fallbackGuidance": "Consider implementing statistical anomaly detection and behavioral analysis for this threat type.",
                "qualityScore": 0.0,
            }

    def _extract_enhanced_threat_characteristics(
        self, threat_data: Dict, tool_name: str
    ) -> ThreatCharacteristics:
        """
        Extract enhanced threat characteristics from the COMPLETE threat intelligence profile

        Args:
            threat_data: Complete threat intelligence profile with all sections
            tool_name: Name of the threat/tool

        Returns:
            Enhanced ThreatCharacteristics with context from all sections
        """

        # Start with basic extraction
        characteristics = self._extract_threat_characteristics(threat_data, tool_name)

        # Enhance with additional context from completed sections
        if threat_data.get("technicalDetails"):
            tech_details = threat_data["technicalDetails"]
            # Add technical context to behavior patterns
            if tech_details.get("capabilities"):
                for capability in tech_details["capabilities"][:3]:  # Top 3 capabilities
                    if isinstance(capability, dict) and capability.get("name"):
                        characteristics.behavior_patterns.append(
                            capability["name"].lower().replace(" ", "_")
                        )
                    elif isinstance(capability, str):
                        characteristics.behavior_patterns.append(
                            capability.lower().replace(" ", "_")
                        )

        if threat_data.get("commandAndControl"):
            c2_data = threat_data["commandAndControl"]
            # Add C2 methods to attack vectors
            if c2_data.get("communicationMethods"):
                for method in c2_data["communicationMethods"][:2]:  # Top 2 methods
                    if isinstance(method, dict) and method.get("protocol"):
                        characteristics.attack_vectors.append(f"c2_{method['protocol'].lower()}")
                    elif isinstance(method, str):
                        characteristics.attack_vectors.append(f"c2_{method.lower()}")

        if threat_data.get("detectionAndMitigation"):
            detection_data = threat_data["detectionAndMitigation"]
            # Add behavioral indicators to behavior patterns
            if detection_data.get("behavioralIndicators"):
                for indicator in detection_data["behavioralIndicators"][:3]:  # Top 3 indicators
                    if isinstance(indicator, dict) and indicator.get("behavior"):
                        characteristics.behavior_patterns.append(
                            indicator["behavior"].lower().replace(" ", "_")
                        )
                    elif isinstance(indicator, str):
                        characteristics.behavior_patterns.append(
                            indicator.lower().replace(" ", "_")
                        )

        # Remove duplicates and clean up
        characteristics.attack_vectors = list(set(characteristics.attack_vectors))
        characteristics.behavior_patterns = list(set(characteristics.behavior_patterns))

        return characteristics

    def _extract_threat_characteristics(
        self, threat_data: Dict, tool_name: str
    ) -> ThreatCharacteristics:
        """
        Extract threat characteristics from the threat intelligence profile

        Args:
            threat_data: Complete threat intelligence profile
            tool_name: Name of the threat/tool

        Returns:
            ThreatCharacteristics object for ML guidance generation
        """
        # Extract metadata
        core_metadata = threat_data.get("coreMetadata", {})
        category = core_metadata.get("category", "malware").lower()

        # Map category to threat type
        threat_type_mapping = {
            "rat": "malware",
            "backdoor": "malware",
            "trojan": "malware",
            "ransomware": "malware",
            "botnet": "malware",
            "apt": "apt",
            "framework": "post_exploitation_framework",
            "tool": "attack_tool",
        }

        threat_type = threat_type_mapping.get(category, "malware")

        # Extract attack vectors from technical details
        technical_details = threat_data.get("technicalDetails", {})
        operating_systems = technical_details.get("operatingSystems", [])
        capabilities = technical_details.get("capabilities", [])

        attack_vectors = []
        if any("network" in str(cap).lower() for cap in capabilities):
            attack_vectors.append("network")
        if any("email" in str(cap).lower() for cap in capabilities):
            attack_vectors.append("email")
        if any("web" in str(cap).lower() for cap in capabilities):
            attack_vectors.append("web")
        if any(
            "memory" in str(cap).lower() or "injection" in str(cap).lower() for cap in capabilities
        ):
            attack_vectors.append("memory_injection")
        if any("lateral" in str(cap).lower() for cap in capabilities):
            attack_vectors.append("lateral_movement")

        # Add OS-specific attack vectors based on supported operating systems
        for os_name in operating_systems:
            os_lower = str(os_name).lower()
            if "windows" in os_lower:
                if "windows_specific" not in attack_vectors:
                    attack_vectors.append("windows_specific")
            elif "linux" in os_lower or "unix" in os_lower:
                if "unix_like" not in attack_vectors:
                    attack_vectors.append("unix_like")
            elif "mac" in os_lower or "darwin" in os_lower:
                if "macos_specific" not in attack_vectors:
                    attack_vectors.append("macos_specific")
            elif "android" in os_lower:
                if "mobile" not in attack_vectors:
                    attack_vectors.append("mobile")
            elif "ios" in os_lower:
                if "mobile" not in attack_vectors:
                    attack_vectors.append("mobile")

        # Default to network if no specific vectors found
        if not attack_vectors:
            attack_vectors = ["network"]

        # Extract target assets
        threat_intel = threat_data.get("threatIntelligence", {})
        campaigns = threat_intel.get("entities", {}).get("campaigns", [])
        target_assets = []

        for campaign in campaigns:
            sectors = campaign.get("targetSectors", [])
            for sector in sectors:
                if "financial" in str(sector).lower():
                    target_assets.append("financial_data")
                elif "healthcare" in str(sector).lower():
                    target_assets.append("healthcare_data")
                elif "government" in str(sector).lower():
                    target_assets.append("government_systems")
                elif "corporate" in str(sector).lower():
                    target_assets.append("corporate_networks")

        # Add OS-specific target assets if not already identified from campaigns
        if not target_assets:
            target_assets = ["corporate_networks", "endpoints"]

        # Enhance target assets based on operating systems
        for os_name in operating_systems:
            os_lower = str(os_name).lower()
            if "windows" in os_lower and "windows_endpoints" not in target_assets:
                target_assets.append("windows_endpoints")
            elif (
                "linux" in os_lower or "unix" in os_lower
            ) and "linux_servers" not in target_assets:
                target_assets.append("linux_servers")
            elif (
                "mac" in os_lower or "darwin" in os_lower
            ) and "macos_endpoints" not in target_assets:
                target_assets.append("macos_endpoints")
            elif (
                "android" in os_lower or "ios" in os_lower
            ) and "mobile_devices" not in target_assets:
                target_assets.append("mobile_devices")

        # Extract behavior patterns from capabilities and C2
        behavior_patterns = []
        persistence_mechanisms = technical_details.get("persistence", [])
        if persistence_mechanisms:
            behavior_patterns.append("persistence")

        c2_data = threat_data.get("commandAndControl", {})
        if c2_data.get("communicationMethods"):
            behavior_patterns.append("command_control")

        # Check for common behaviors in capabilities
        for cap in capabilities:
            cap_lower = str(cap).lower()
            if "exfiltrat" in cap_lower:
                behavior_patterns.append("data_exfiltration")
            elif "lateral" in cap_lower:
                behavior_patterns.append("lateral_movement")
            elif "credential" in cap_lower:
                behavior_patterns.append("credential_harvesting")

        if not behavior_patterns:
            behavior_patterns = ["persistence", "command_control"]

        # Determine time characteristics
        beaconing_patterns = c2_data.get("beaconingPatterns", [])
        if beaconing_patterns:
            # Check beacon frequency
            frequencies = [pattern.get("frequency", "") for pattern in beaconing_patterns]
            if any(
                "continuous" in str(freq).lower() or "persistent" in str(freq).lower()
                for freq in frequencies
            ):
                time_characteristics = "persistent"
            elif any(
                "periodic" in str(freq).lower() or "regular" in str(freq).lower()
                for freq in frequencies
            ):
                time_characteristics = "periodic"
            else:
                time_characteristics = "burst"
        else:
            time_characteristics = "persistent"  # Default assumption

        return ThreatCharacteristics(
            threat_name=tool_name,
            threat_type=threat_type,
            attack_vectors=attack_vectors,
            target_assets=target_assets,
            behavior_patterns=behavior_patterns,
            time_characteristics=time_characteristics,
        )

    def save_to_file(self, data: Dict[str, Any], filename: str | None = None) -> str:
        """Save the threat intelligence data to a JSON file."""
        if filename is None:
            tool_name = data.get("coreMetadata", {}).get("name", "threat_intel")
            filename = f"{tool_name.lower().replace(' ', '_')}_threat_intel.json"

        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

        return filename
