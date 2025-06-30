"""
Core Threat Intelligence Tool for generating threat profiles using Claude AI with web search
Enhanced with ML-based anomaly detection guidance and trace export for annotator integration
"""
import os
import json
import anthropic
from typing import Dict, Any, Optional, Callable
from datetime import datetime
import re
from pydantic import ValidationError
import time
import random
from src.core.section_validator import SectionValidator, SectionImprover
from src.core.ml_guidance_generator import MLGuidanceGenerator, ThreatCharacteristics
from src.core.trace_exporter import get_trace_exporter
from src.core.performance_metrics import PerformanceTracker


class ThreatIntelTool:
    def __init__(self, api_key, enable_tracing=True, trace_export_dir="./traces", enable_metrics=True, metrics_file="performance_metrics.jsonl"):
        """Initialize the Claude client with the provided API key"""
        self.client = anthropic.Anthropic(api_key=api_key)
        self.validator = SectionValidator(self.client)
        self.improver = SectionImprover(self.client)
        self.enable_quality_control = True
        
        # Initialize performance metrics tracking
        self.enable_metrics = enable_metrics
        if self.enable_metrics:
            self.performance_tracker = PerformanceTracker(metrics_file)
            print(f"DEBUG: Performance metrics enabled, logging to {metrics_file}")
        else:
            self.performance_tracker = None
        
        # Initialize trace exporter
        self.enable_tracing = enable_tracing
        if self.enable_tracing:
            self.trace_exporter = get_trace_exporter(trace_export_dir)
            print(f"DEBUG: Trace exporter initialized, export directory: {trace_export_dir}")
        else:
            self.trace_exporter = None
        
        # Initialize ML guidance generator
        try:
            self.ml_guidance_generator = MLGuidanceGenerator(self.client)
            self.enable_ml_guidance = True
            print("DEBUG: ML guidance generator initialized successfully")
        except Exception as e:
            print(f"DEBUG: ML guidance generator initialization failed: {e}")
            self.ml_guidance_generator = None
            self.enable_ml_guidance = False
    
    def get_threat_intelligence(self, tool_name: str, progress_callback=None):
        """
        Generate comprehensive threat intelligence profile using Claude with web search
        
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
                progress_callback(0.1, "🔍 Initializing research...")
            
            print(f"DEBUG: Starting threat intelligence generation for: {tool_name}")
            
            if self.enable_tracing and self.trace_exporter:
                self.trace_exporter.log_stage_end("initialization")
            
            # Start performance tracking
            if self.enable_metrics and self.performance_tracker:
                self.performance_tracker.start_request(
                    query=tool_name,
                    model="claude-sonnet-4-20250514",
                    prompt_type="threat_intel_main",
                    cache_enabled=False  # Baseline measurement
                )
            
            # ENHANCED PROMPT - Triggers Claude's research mode with comprehensive web search
            prompt = f"""Conduct comprehensive research and deep dive analysis to generate a detailed threat intelligence profile for: {tool_name}

Today's date is {datetime.now().strftime('%B %d, %Y')}.

CRITICAL: You MUST use the web_search_20250305 tool extensively to find the most current, verified information. Do NOT hallucinate or invent URLs, sources, or information. All sources must be real and accessible through your web_search_20250305 tool.

Please perform a thorough deep dive research using the web_search_20250305 tool to find comprehensive information about {tool_name}, including:
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

Focus on finding information from 2024-2025 when possible, but include relevant historical context.

Based on your comprehensive research findings, create a detailed profile in the following JSON format:

{{
  "coreMetadata": {{
    "name": "{tool_name}",
    "version": "Latest known version from research",
    "category": "Tool category (RAT/Backdoor/Trojan/etc)",
    "profileId": "TI_{tool_name.upper().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}",
    "profileAuthor": "Claude AI with Web Search",
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
        "url": "REQUIRED: Real, accessible URL from your web_search_20250305 tool results - NO hallucinated URLs",
        "title": "REQUIRED: Actual title from the web_search_20250305 tool results",
        "domain": "REQUIRED: Actual domain name from web_search_20250305 tool results",
        "accessDate": "{datetime.now().strftime('%Y-%m-%d')}",
        "relevanceScore": "High/Medium/Low based on content relevance",
        "contentType": "Report/Article/Advisory/Blog/Database/Documentation",
        "keyFindings": "REQUIRED: Specific information extracted from this real source"
      }}
    ],
    "searchStrategy": "REQUIRED: Describe your actual web_search_20250305 tool approach and methodology",
    "dataFreshness": "REQUIRED: How recent the web_search_20250305 tool information is",
    "sourceReliability": "REQUIRED: Assessment based on actual domain authority and content quality from web_search_20250305 tool"
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
        "url": "URL from web_search_20250305 tool results",
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
        "url": "URL from web_search_20250305 tool",
        "focus": "Resource focus"
      }}
    ]
  }}
}}

CRITICAL INSTRUCTIONS FOR OUTPUT:
1. Return ONLY the JSON object populated with verified information from your web_search_20250305 tool results
2. NEVER invent, hallucinate, or fabricate URLs, sources, or technical details
3. If you cannot find information for certain sections through the web_search_20250305 tool, explicitly state "No verified information found through web_search_20250305 tool" rather than making up content
4. All URLs in webSearchSources and referencesAndIntelligenceSharing MUST be real URLs from your actual web_search_20250305 tool results
5. Cross-reference claims across multiple sources when possible using the web_search_20250305 tool
6. If web_search_20250305 tool results are limited, acknowledge this limitation in the relevant sections

Remember: Accuracy and source verification through the web_search_20250305 tool are more important than completeness. Real, verified information from web_search_20250305 is infinitely more valuable than hallucinated content."""

            # Record prompt details for metrics
            if self.enable_metrics and self.performance_tracker:
                self.performance_tracker.record_prompt_details(prompt, cache_enabled=False)

            if progress_callback:
                progress_callback(0.2, "🤖 Researching with web search...")
            
            print("DEBUG: Sending request to Claude API with web search tool enabled...")
            print(f"DEBUG: Prompt size: {len(prompt)} characters")
            
            # Log web search stage
            if self.enable_tracing and self.trace_exporter:
                self.trace_exporter.log_stage_start("web_search")
            
            # Generate threat intelligence using Claude with retry logic
            api_start_time = time.time()
            response = self._api_call_with_retry(
                model="claude-sonnet-4-20250514",
                max_tokens=8192,
                temperature=0.3,
                messages=[{
                    "role": "user", 
                    "content": prompt
                }],
                tools=[{
                    "type": "web_search_20250305",
                    "name": "web_search"
                }]
            )
            
            # Record API response metrics
            if self.enable_metrics and self.performance_tracker:
                api_end_time = time.time()
                time_to_first_token = api_end_time - api_start_time  # Approximate
                self.performance_tracker.record_api_response(
                    response, 
                    cache_hit=False,  # Baseline - no caching
                    time_to_first_token=time_to_first_token
                )
            
            if self.enable_tracing and self.trace_exporter:
                self.trace_exporter.log_stage_end("web_search")
            
            # Extract initial web search sources from the main response
            initial_sources = self.validator._extract_web_search_sources_from_response(
                response, 'initial_research', tool_name
            )
            self.validator.web_search_sources.extend(initial_sources)
            print(f"DEBUG: Captured {len(initial_sources)} initial web search sources")
            
            # Extract response text (existing logic)
            response_text = ""
            if hasattr(response, 'content') and response.content:
                text_blocks = []
                found_tool_result = False
                
                for content in response.content:
                    if hasattr(content, 'type'):
                        if content.type == 'web_search_tool_result':
                            found_tool_result = True
                        elif content.type == 'text' and found_tool_result:
                            if hasattr(content, 'text'):
                                text_blocks.append(content.text)
                
                if text_blocks:
                    response_text = " ".join(text_blocks)
                else:
                    for content in response.content:
                        if hasattr(content, 'type') and content.type == 'text':
                            if hasattr(content, 'text'):
                                response_text += content.text + "\n"
            
            response_text = response_text.strip()
            
            print("DEBUG: Received response from Claude API")
            
            if progress_callback:
                progress_callback(0.7, "📊 Processing response...")
            print(f"DEBUG: Response length: {len(response_text)} characters")
            print(f"DEBUG: Response preview: {response_text[:200]}...")
            
            # Find the JSON content in the response using bracket matching
            json_text = None
            json_start = -1
            
            # Find the first opening brace
            start_pos = response_text.find('{')
            if start_pos == -1:
                print(f"DEBUG: No JSON found in response")
                raise ValueError(f"No JSON found in response. Response preview: {response_text[:1000]}")
            
            # Use bracket matching to find the complete JSON object
            brace_count = 0
            json_end = -1
            in_string = False
            escape_next = False
            
            for i in range(start_pos, len(response_text)):
                char = response_text[i]
                
                if escape_next:
                    escape_next = False
                    continue
                    
                if char == '\\' and in_string:
                    escape_next = True
                    continue
                    
                if char == '"' and not escape_next:
                    in_string = not in_string
                    continue
                    
                if not in_string:
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_end = i + 1
                            break
            
            if json_end == -1:
                print(f"DEBUG: No complete JSON object found in response")
                raise ValueError(f"No complete JSON object found in response. Response preview: {response_text[:1000]}")
            
            json_text = response_text[start_pos:json_end]
            json_start = start_pos
            
            print(f"DEBUG: JSON boundaries - start: {json_start}, end: {json_end}")
            print(f"DEBUG: Extracted JSON length: {len(json_text)} characters")
            
            if progress_callback:
                progress_callback(0.75, "🔍 Parsing JSON response...")
            
            try:
                json_data = json.loads(json_text)
                print("DEBUG: JSON parsing successful")
                
                # Record successful parsing
                if self.enable_metrics and self.performance_tracker:
                    self.performance_tracker.record_parsing_result(True)
                    
            except json.JSONDecodeError as e:
                print(f"DEBUG: JSON parsing failed: {e}")
                print(f"DEBUG: JSON text preview: {json_text[:500]}")
                
                # Record failed parsing
                if self.enable_metrics and self.performance_tracker:
                    self.performance_tracker.record_parsing_result(False, str(e))
                    
                raise ValueError(f"Invalid JSON in response: {str(e)}. JSON preview: {json_text[:500]}")
            
            if not json_data:
                raise ValueError("Empty JSON data received")
            
            # Validate that we have a dictionary with the expected structure
            if not isinstance(json_data, dict):
                raise ValueError(f"Invalid response format: Expected JSON object but got {type(json_data).__name__}")
            
            print(f"DEBUG: Initial generation successful. JSON contains {len(json_data)} top-level keys")
            
            # Generate ML guidance BEFORE quality control to leverage all context
            if self.enable_ml_guidance and self.ml_guidance_generator:
                if progress_callback:
                    progress_callback(0.75, "🤖 Generating ML detection guidance...")
                
                if self.enable_tracing and self.trace_exporter:
                    self.trace_exporter.log_stage_start("ml_guidance")
                
                try:
                    ml_guidance = self._generate_ml_guidance(json_data, tool_name)
                    if ml_guidance:
                        json_data['mlGuidance'] = ml_guidance
                        print("DEBUG: ML guidance generated successfully")
                        
                        # Log ML guidance for tracing
                        if self.enable_tracing and self.trace_exporter:
                            # Extract ML techniques from the guidance
                            ml_techniques = []
                            if isinstance(ml_guidance, dict) and 'content' in ml_guidance:
                                # This would need to be enhanced to extract structured ML techniques
                                # For now, log basic info
                                pass
                            self.trace_exporter.log_stage_end("ml_guidance", success=True)
                    else:
                        print("DEBUG: No ML guidance generated")
                        if self.enable_tracing and self.trace_exporter:
                            self.trace_exporter.log_stage_end("ml_guidance", success=False)
                except Exception as e:
                    print(f"DEBUG: ML guidance generation failed: {e}")
                    if self.enable_tracing and self.trace_exporter:
                        self.trace_exporter.log_error(str(e), "ml_guidance")
                        self.trace_exporter.log_stage_end("ml_guidance", success=False, error=str(e))
                    # Continue without ML guidance - don't fail the entire process
            
            # Quality control phase - now includes ML guidance validation
            if self.enable_quality_control:
                if progress_callback:
                    progress_callback(0.8, "🔍 Running quality validation...")
                
                if self.enable_tracing and self.trace_exporter:
                    self.trace_exporter.log_stage_start("quality_validation")
                
                # Validate the complete profile including ML guidance
                validation_results = self.validator.validate_complete_profile(
                    json_data, progress_callback, tool_name
                )
                
                if self.enable_tracing and self.trace_exporter:
                    self.trace_exporter.log_quality_metrics(validation_results)
                    self.trace_exporter.log_stage_end("quality_validation")
                
                # If improvement is needed, attempt to fix weak sections
                if validation_results['needs_improvement']:
                    if progress_callback:
                        progress_callback(0.9, "🔧 Improving weak sections...")
                    
                    json_data = self._improve_weak_sections(
                        json_data, validation_results, progress_callback
                    )
                    
                    # Re-validate after improvements
                    if progress_callback:
                        progress_callback(0.95, "✅ Final validation...")
                    
                    final_validation = self.validator.validate_complete_profile(json_data, None, tool_name)
                    json_data['_quality_assessment'] = final_validation
                else:
                    # Attach original validation results
                    json_data['_quality_assessment'] = validation_results
                
                print(f"DEBUG: Quality control complete. Overall score: {validation_results['overall_score']}")
                
                # Add comprehensive web search sources section to the main profile if available
                if hasattr(self.validator, 'web_search_sources') and self.validator.web_search_sources:
                    comprehensive_sources = self.validator.generate_comprehensive_sources_section()
                    json_data['comprehensiveWebSearchSources'] = comprehensive_sources
                    print(f"DEBUG: Added comprehensive sources section to main profile with {len(self.validator.web_search_sources)} sources")
            
            if progress_callback:
                progress_callback(1.0, "✅ Analysis complete!")
            
            # Complete performance tracking
            if self.enable_metrics and self.performance_tracker:
                metrics = self.performance_tracker.finish_request()
                if metrics:
                    print(f"DEBUG: Request completed - Latency: {metrics.latency_ms}ms, Cost: ${metrics.total_cost:.4f}")
            
            # Complete trace and export
            if self.enable_tracing and self.trace_exporter:
                try:
                    # Log comprehensive trace data
                    self.trace_exporter.log_threat_characteristics(json_data.get('coreMetadata', {}))
                    self.trace_exporter.log_final_guidance(json_data.get('final_guidance', ''))
                    
                    # Log web search sources if available
                    if hasattr(self.validator, 'web_search_sources') and self.validator.web_search_sources:
                        self.trace_exporter.log_web_search_sources(self.validator.web_search_sources)
                    
                    # Complete and export trace
                    trace_file = self.trace_exporter.complete_trace(json_data)
                    print(f"DEBUG: Trace exported to {trace_file}")
                    
                    # Add trace metadata to response
                    json_data['_trace_metadata'] = {
                        'trace_id': trace_id,
                        'trace_file': trace_file,
                        'export_enabled': True
                    }
                except Exception as trace_error:
                    print(f"DEBUG: Trace export failed: {trace_error}")
                    # Don't fail the main process for trace export errors
            
            return json_data
        
        except Exception as e:
            print(f"DEBUG: Exception occurred: {e}")
            print(f"DEBUG: Exception type: {type(e)}")
            import traceback
            traceback.print_exc()
            
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
                    print(f"DEBUG: Error trace exported to {error_trace_file}")
                except Exception as trace_error:
                    print(f"DEBUG: Failed to export error trace: {trace_error}")
            
            if progress_callback:
                progress_callback(1.0, f"❌ Error: {str(e)}")
            raise e
    
    def _improve_weak_sections(self, profile: dict, validation_results: dict, 
                              progress_callback: Optional[Callable] = None) -> dict:
        """
        Improve sections that failed validation (legacy method - now handled in validator)
        
        Args:
            profile: Current threat intelligence profile
            validation_results: Validation results indicating weak sections
            progress_callback: Optional progress callback
            
        Returns:
            Improved profile
        """
        # This method is now largely replaced by the iterative validation in SectionValidator
        # Keep minimal implementation for backward compatibility
        improved_profile = profile.copy()
        sections_to_improve = []
        
        # Identify only critical sections needing immediate improvement
        for section_name, validation in validation_results['section_validations'].items():
            if validation.get('recommendation') == 'RETRY' and validation.get('is_critical'):
                sections_to_improve.append((section_name, validation))
        
        # Improve only critical sections (web search enhancement handled in validator)
        for i, (section_name, validation) in enumerate(sections_to_improve[:2]):  # Limit to top 2 critical
            if progress_callback:
                progress = 0.9 + (0.05 * i / max(len(sections_to_improve), 1))
                progress_callback(progress, f"🔧 Critical fix for {section_name}...")
            
            current_content = improved_profile.get(section_name, {})
            
            # Improve section without caching
            improved_content = self.improver.improve_section(
                section_name, current_content, validation
            )
            
            if improved_content != current_content:
                improved_profile[section_name] = improved_content
                print(f"DEBUG: Critical improvement for section: {section_name}")
        
        return improved_profile
    
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
            # Extract enhanced threat characteristics from the COMPLETE profile
            threat_characteristics = self._extract_enhanced_threat_characteristics(threat_data, tool_name)
            
            # Generate ML guidance using full context
            ml_guidance_markdown = self.ml_guidance_generator.generate_enhanced_ml_guidance_section(
                threat_characteristics, threat_data, 
                trace_exporter=self.trace_exporter if self.enable_tracing else None
            )
            
            if ml_guidance_markdown:
                return {
                    'enabled': True,
                    'content': ml_guidance_markdown,
                    'threatCharacteristics': {
                        'name': threat_characteristics.threat_name,
                        'type': threat_characteristics.threat_type,
                        'attackVectors': threat_characteristics.attack_vectors,
                        'behaviorPatterns': threat_characteristics.behavior_patterns,
                        'timeCharacteristics': threat_characteristics.time_characteristics
                    },
                    'contextUsed': {
                        'technicalDetails': bool(threat_data.get('technicalDetails')),
                        'commandAndControl': bool(threat_data.get('commandAndControl')),
                        'detectionAndMitigation': bool(threat_data.get('detectionAndMitigation')),
                        'threatIntelligence': bool(threat_data.get('threatIntelligence')),
                        'forensicArtifacts': bool(threat_data.get('forensicArtifacts'))
                    },
                    'generatedAt': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'generator': 'Agentic RAG with Full Context',
                    'qualityScore': 0.0  # Will be filled by validator
                }
            else:
                return None
                
        except Exception as e:
            print(f"DEBUG: ML guidance generation error: {e}")
            return {
                'enabled': False,
                'error': str(e),
                'fallbackGuidance': 'Consider implementing statistical anomaly detection and behavioral analysis for this threat type.',
                'qualityScore': 0.0
            }
    
    def _extract_enhanced_threat_characteristics(self, threat_data: Dict, tool_name: str) -> ThreatCharacteristics:
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
        if threat_data.get('technicalDetails'):
            tech_details = threat_data['technicalDetails']
            # Add technical context to behavior patterns
            if tech_details.get('capabilities'):
                for capability in tech_details['capabilities'][:3]:  # Top 3 capabilities
                    if isinstance(capability, dict) and capability.get('name'):
                        characteristics.behavior_patterns.append(capability['name'].lower().replace(' ', '_'))
                    elif isinstance(capability, str):
                        characteristics.behavior_patterns.append(capability.lower().replace(' ', '_'))
        
        if threat_data.get('commandAndControl'):
            c2_data = threat_data['commandAndControl']
            # Add C2 methods to attack vectors
            if c2_data.get('communicationMethods'):
                for method in c2_data['communicationMethods'][:2]:  # Top 2 methods
                    if isinstance(method, dict) and method.get('protocol'):
                        characteristics.attack_vectors.append(f"c2_{method['protocol'].lower()}")
                    elif isinstance(method, str):
                        characteristics.attack_vectors.append(f"c2_{method.lower()}")
        
        if threat_data.get('detectionAndMitigation'):
            detection_data = threat_data['detectionAndMitigation']
            # Add behavioral indicators to behavior patterns
            if detection_data.get('behavioralIndicators'):
                for indicator in detection_data['behavioralIndicators'][:3]:  # Top 3 indicators
                    if isinstance(indicator, dict) and indicator.get('behavior'):
                        characteristics.behavior_patterns.append(indicator['behavior'].lower().replace(' ', '_'))
                    elif isinstance(indicator, str):
                        characteristics.behavior_patterns.append(indicator.lower().replace(' ', '_'))
        
        # Remove duplicates and clean up
        characteristics.attack_vectors = list(set(characteristics.attack_vectors))
        characteristics.behavior_patterns = list(set(characteristics.behavior_patterns))
        
        return characteristics
    
    def _extract_threat_characteristics(self, threat_data: Dict, tool_name: str) -> ThreatCharacteristics:
        """
        Extract threat characteristics from the threat intelligence profile
        
        Args:
            threat_data: Complete threat intelligence profile
            tool_name: Name of the threat/tool
            
        Returns:
            ThreatCharacteristics object for ML guidance generation
        """
        # Extract metadata
        core_metadata = threat_data.get('coreMetadata', {})
        category = core_metadata.get('category', 'malware').lower()
        
        # Map category to threat type
        threat_type_mapping = {
            'rat': 'malware',
            'backdoor': 'malware', 
            'trojan': 'malware',
            'ransomware': 'malware',
            'botnet': 'malware',
            'apt': 'apt',
            'framework': 'post_exploitation_framework',
            'tool': 'attack_tool'
        }
        
        threat_type = threat_type_mapping.get(category, 'malware')
        
        # Extract attack vectors from technical details
        technical_details = threat_data.get('technicalDetails', {})
        operating_systems = technical_details.get('operatingSystems', [])
        capabilities = technical_details.get('capabilities', [])
        
        attack_vectors = []
        if any('network' in str(cap).lower() for cap in capabilities):
            attack_vectors.append('network')
        if any('email' in str(cap).lower() for cap in capabilities):
            attack_vectors.append('email')
        if any('web' in str(cap).lower() for cap in capabilities):
            attack_vectors.append('web')
        if any('memory' in str(cap).lower() or 'injection' in str(cap).lower() for cap in capabilities):
            attack_vectors.append('memory_injection')
        if any('lateral' in str(cap).lower() for cap in capabilities):
            attack_vectors.append('lateral_movement')
        
        # Add OS-specific attack vectors based on supported operating systems
        for os_name in operating_systems:
            os_lower = str(os_name).lower()
            if 'windows' in os_lower:
                if 'windows_specific' not in attack_vectors:
                    attack_vectors.append('windows_specific')
            elif 'linux' in os_lower or 'unix' in os_lower:
                if 'unix_like' not in attack_vectors:
                    attack_vectors.append('unix_like')
            elif 'mac' in os_lower or 'darwin' in os_lower:
                if 'macos_specific' not in attack_vectors:
                    attack_vectors.append('macos_specific')
            elif 'android' in os_lower:
                if 'mobile' not in attack_vectors:
                    attack_vectors.append('mobile')
            elif 'ios' in os_lower:
                if 'mobile' not in attack_vectors:
                    attack_vectors.append('mobile')
        
        # Default to network if no specific vectors found
        if not attack_vectors:
            attack_vectors = ['network']
        
        # Extract target assets
        threat_intel = threat_data.get('threatIntelligence', {})
        campaigns = threat_intel.get('entities', {}).get('campaigns', [])
        target_assets = []
        
        for campaign in campaigns:
            sectors = campaign.get('targetSectors', [])
            for sector in sectors:
                if 'financial' in str(sector).lower():
                    target_assets.append('financial_data')
                elif 'healthcare' in str(sector).lower():
                    target_assets.append('healthcare_data')
                elif 'government' in str(sector).lower():
                    target_assets.append('government_systems')
                elif 'corporate' in str(sector).lower():
                    target_assets.append('corporate_networks')
        
        # Add OS-specific target assets if not already identified from campaigns
        if not target_assets:
            target_assets = ['corporate_networks', 'endpoints']
            
        # Enhance target assets based on operating systems
        for os_name in operating_systems:
            os_lower = str(os_name).lower()
            if 'windows' in os_lower and 'windows_endpoints' not in target_assets:
                target_assets.append('windows_endpoints')
            elif ('linux' in os_lower or 'unix' in os_lower) and 'linux_servers' not in target_assets:
                target_assets.append('linux_servers')
            elif ('mac' in os_lower or 'darwin' in os_lower) and 'macos_endpoints' not in target_assets:
                target_assets.append('macos_endpoints')
            elif ('android' in os_lower or 'ios' in os_lower) and 'mobile_devices' not in target_assets:
                target_assets.append('mobile_devices')
        
        # Extract behavior patterns from capabilities and C2
        behavior_patterns = []
        persistence_mechanisms = technical_details.get('persistence', [])
        if persistence_mechanisms:
            behavior_patterns.append('persistence')
        
        c2_data = threat_data.get('commandAndControl', {})
        if c2_data.get('communicationMethods'):
            behavior_patterns.append('command_control')
        
        # Check for common behaviors in capabilities
        for cap in capabilities:
            cap_lower = str(cap).lower()
            if 'exfiltrat' in cap_lower:
                behavior_patterns.append('data_exfiltration')
            elif 'lateral' in cap_lower:
                behavior_patterns.append('lateral_movement')
            elif 'credential' in cap_lower:
                behavior_patterns.append('credential_harvesting')
        
        if not behavior_patterns:
            behavior_patterns = ['persistence', 'command_control']
        
        # Determine time characteristics
        beaconing_patterns = c2_data.get('beaconingPatterns', [])
        if beaconing_patterns:
            # Check beacon frequency
            frequencies = [pattern.get('frequency', '') for pattern in beaconing_patterns]
            if any('continuous' in str(freq).lower() or 'persistent' in str(freq).lower() for freq in frequencies):
                time_characteristics = 'persistent'
            elif any('periodic' in str(freq).lower() or 'regular' in str(freq).lower() for freq in frequencies):
                time_characteristics = 'periodic'
            else:
                time_characteristics = 'burst'
        else:
            time_characteristics = 'persistent'  # Default assumption
        
        return ThreatCharacteristics(
            threat_name=tool_name,
            threat_type=threat_type,
            attack_vectors=attack_vectors,
            target_assets=target_assets,
            behavior_patterns=behavior_patterns,
            time_characteristics=time_characteristics
        )
    
    
    def _api_call_with_retry(self, **kwargs):
        """Make API call with intelligent retry logic using retry-after header"""
        max_retries = 3  # Reduced since we're using smarter delays
        base_delay = 5   # Minimum delay between retries
        
        for attempt in range(max_retries):
            try:
                print(f"DEBUG: Making API call attempt {attempt + 1}/{max_retries}")
                return self.client.messages.create(**kwargs)
                
            except anthropic.RateLimitError as e:
                if attempt == max_retries - 1:  # Last attempt
                    print(f"DEBUG: Rate limit exceeded after {max_retries} attempts")
                    raise e
                
                # Check if the error response has retry-after information
                retry_after = None
                if hasattr(e, 'response') and e.response:
                    retry_after_header = e.response.headers.get('retry-after')
                    if retry_after_header:
                        try:
                            retry_after = float(retry_after_header)
                            print(f"DEBUG: API provided retry-after: {retry_after} seconds")
                        except (ValueError, TypeError):
                            pass
                
                # Use retry-after if available, otherwise exponential backoff
                if retry_after:
                    delay = retry_after + random.uniform(1, 3)  # Add small jitter
                else:
                    # Fallback: exponential backoff with reasonable delays
                    delay = base_delay * (2 ** attempt) + random.uniform(1, 5)
                    # Cap at 2 minutes since token bucket refills continuously
                    delay = min(delay, 120)
                
                print(f"DEBUG: Rate limit hit. Waiting {delay:.1f} seconds before retry {attempt + 2}")
                time.sleep(delay)
                
            except Exception as e:
                # For non-rate-limit errors, fail immediately
                print(f"DEBUG: Non-rate-limit error: {e}")
                raise e

    def save_to_file(self, data: Dict[str, Any], filename: str = None) -> str:
        """Save the threat intelligence data to a JSON file."""
        if filename is None:
            tool_name = data.get("coreMetadata", {}).get("name", "threat_intel")
            filename = f"{tool_name.lower().replace(' ', '_')}_threat_intel.json"
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filename