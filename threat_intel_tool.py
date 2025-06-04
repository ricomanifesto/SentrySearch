"""
Core Threat Intelligence Tool for generating threat profiles using Claude AI with web search
"""
import os
import json
import anthropic
from typing import Dict, Any, Optional, Callable
from datetime import datetime
import re
from pydantic import ValidationError
from section_validator import SectionValidator, SectionImprover


class ThreatIntelTool:
    def __init__(self, api_key):
        """Initialize the Claude client with the provided API key"""
        self.client = anthropic.Anthropic(api_key=api_key)
        self.validator = SectionValidator(self.client)
        self.improver = SectionImprover(self.client)
        self.enable_quality_control = True
    
    def get_threat_intelligence(self, tool_name: str, progress_callback=None):
        """
        Generate comprehensive threat intelligence profile using Claude with web search
        
        Args:
            tool_name: Name of the tool/threat to analyze
            progress_callback: Optional callback for progress updates
            
        Returns:
            dict: Threat intelligence data with quality assessment
        """
        try:
            if progress_callback:
                progress_callback(0.1, "🔍 Initializing research...")
            
            print(f"DEBUG: Starting threat intelligence generation for: {tool_name}")
            
            # UPDATED PROMPT - Works with web search tool
            prompt = f"""Generate a comprehensive threat intelligence profile for: {tool_name}

Today's date is {datetime.now().strftime('%B %d, %Y')}.

Please use web search to find the most current information about {tool_name}, including:
- Recent vulnerabilities and exploits
- Technical details and architecture
- Indicators of compromise (IOCs)
- Threat actor associations
- Detection methods and mitigations
- Recent security advisories or reports

Focus on finding information from 2024-2025 when possible.

Based on your research, create a comprehensive profile in the following JSON format:

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
    "searchQueriesUsed": ["List the search queries you used"],
    "primarySources": [
      {{
        "url": "Actual URL from search results",
        "title": "Actual title from search results",
        "domain": "Domain name",
        "accessDate": "{datetime.now().strftime('%Y-%m-%d')}",
        "relevanceScore": "High/Medium/Low",
        "contentType": "Report/Article/Advisory/Blog/Database",
        "keyFindings": "Key information this source provided"
      }}
    ],
    "searchStrategy": "Brief description of your search approach",
    "dataFreshness": "How recent the information is",
    "sourceReliability": "Assessment of source credibility"
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
        "url": "URL from search results",
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
        "url": "URL from search",
        "focus": "Resource focus"
      }}
    ]
  }}
}}

Return ONLY the JSON object with the information you found. If you cannot find information for certain sections, indicate that clearly in the content rather than making up information."""

            if progress_callback:
                progress_callback(0.2, "🤖 Researching with web search...")
            
            print("DEBUG: Sending request to Claude API with web search tool enabled...")
            
            # Generate threat intelligence using Claude with ACTUAL web search tool
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=8192,
                temperature=0.3,
                messages=[{
                    "role": "user", 
                    "content": prompt
                }],
                # Enable the web search tool
                tools=[
                    {
                        "type": "web_search_20250305",
                        "name": "web_search"
                    }
                ]
            )
            
            print("DEBUG: Received response from Claude API")
            
            if progress_callback:
                progress_callback(0.7, "📊 Processing response...")
            
            # Extract the final text response from the content blocks
            response_text = ""
            
            # According to the docs, the response will have multiple content blocks
            # We need to find the final text blocks that contain our JSON
            if hasattr(response, 'content') and response.content:
                # Look for text blocks after tool use
                text_blocks = []
                found_tool_result = False
                
                for content in response.content:
                    # Track when we've seen tool results
                    if hasattr(content, 'type'):
                        if content.type == 'web_search_tool_result':
                            found_tool_result = True
                        # Collect text blocks that come after tool results
                        elif content.type == 'text' and found_tool_result:
                            if hasattr(content, 'text'):
                                text_blocks.append(content.text)
                
                # If we found text after tool results, use that
                if text_blocks:
                    response_text = " ".join(text_blocks)
                else:
                    # Fallback: collect all text blocks
                    for content in response.content:
                        if hasattr(content, 'type') and content.type == 'text':
                            if hasattr(content, 'text'):
                                response_text += content.text + "\n"
            
            response_text = response_text.strip()
            print(f"DEBUG: Response length: {len(response_text)} characters")
            print(f"DEBUG: Response preview: {response_text[:200]}...")
            
            # Find the JSON content in the response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            print(f"DEBUG: JSON boundaries - start: {json_start}, end: {json_end}")
            
            if json_start == -1 or json_end == 0:
                print(f"DEBUG: No JSON found in response")
                raise ValueError(f"No JSON found in response. Response preview: {response_text[:1000]}")
            
            json_text = response_text[json_start:json_end]
            print(f"DEBUG: Extracted JSON length: {len(json_text)} characters")
            
            if progress_callback:
                progress_callback(0.75, "🔍 Parsing JSON response...")
            
            try:
                json_data = json.loads(json_text)
                print("DEBUG: JSON parsing successful")
            except json.JSONDecodeError as e:
                print(f"DEBUG: JSON parsing failed: {e}")
                print(f"DEBUG: JSON text preview: {json_text[:500]}")
                raise ValueError(f"Invalid JSON in response: {str(e)}. JSON preview: {json_text[:500]}")
            
            if not json_data:
                raise ValueError("Empty JSON data received")
            
            # Validate that we have a dictionary with the expected structure
            if not isinstance(json_data, dict):
                raise ValueError(f"Invalid response format: Expected JSON object but got {type(json_data).__name__}")
            
            print(f"DEBUG: Initial generation successful. JSON contains {len(json_data)} top-level keys")
            
            # Quality control phase
            if self.enable_quality_control:
                if progress_callback:
                    progress_callback(0.8, "🔍 Running quality validation...")
                
                # Validate the complete profile
                validation_results = self.validator.validate_complete_profile(
                    json_data, progress_callback
                )
                
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
                    
                    final_validation = self.validator.validate_complete_profile(json_data)
                    json_data['_quality_assessment'] = final_validation
                else:
                    # Attach original validation results
                    json_data['_quality_assessment'] = validation_results
                
                print(f"DEBUG: Quality control complete. Overall score: {validation_results['overall_score']}")
            
            if progress_callback:
                progress_callback(1.0, "✅ Analysis complete!")
            
            return json_data
        
        except Exception as e:
            print(f"DEBUG: Exception occurred: {e}")
            print(f"DEBUG: Exception type: {type(e)}")
            import traceback
            traceback.print_exc()
            
            if progress_callback:
                progress_callback(1.0, f"❌ Error: {str(e)}")
            raise e
    
    def _improve_weak_sections(self, profile: dict, validation_results: dict, 
                              progress_callback: Optional[Callable] = None) -> dict:
        """
        Improve sections that failed validation
        
        Args:
            profile: Current threat intelligence profile
            validation_results: Validation results indicating weak sections
            progress_callback: Optional progress callback
            
        Returns:
            Improved profile
        """
        improved_profile = profile.copy()
        sections_to_improve = []
        
        # Identify sections needing improvement
        for section_name, validation in validation_results['section_validations'].items():
            if validation.get('recommendation') in ['RETRY', 'ENHANCE']:
                if validation.get('is_critical') or validation.get('scores', {}).get('overall', 0) < 3.0:
                    sections_to_improve.append((section_name, validation))
        
        # Improve each weak section
        for i, (section_name, validation) in enumerate(sections_to_improve[:3]):  # Limit to top 3
            if progress_callback:
                progress = 0.9 + (0.05 * i / len(sections_to_improve))
                progress_callback(progress, f"🔧 Improving {section_name}...")
            
            current_content = improved_profile.get(section_name, {})
            improved_content = self.improver.improve_section(
                section_name, current_content, validation
            )
            
            if improved_content != current_content:
                improved_profile[section_name] = improved_content
                print(f"DEBUG: Improved section: {section_name}")
        
        return improved_profile

    def save_to_file(self, data: Dict[str, Any], filename: str = None) -> str:
        """Save the threat intelligence data to a JSON file."""
        if filename is None:
            tool_name = data.get("coreMetadata", {}).get("name", "threat_intel")
            filename = f"{tool_name.lower().replace(' ', '_')}_threat_intel.json"
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filename