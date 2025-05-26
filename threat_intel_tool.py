"""
Core Threat Intelligence Tool for generating threat profiles using Claude AI with web search
"""
import os
import json
import anthropic
from typing import Dict, Any, Optional, Callable
from datetime import datetime
from models import ThreatProfile
import re
from threat_intel_schema import ThreatIntelligenceProfile
from pydantic import ValidationError


class ThreatIntelTool:
    def __init__(self, api_key):
        """Initialize the Claude client with the provided API key"""
        self.client = anthropic.Anthropic(api_key=api_key)
    
    def get_threat_intelligence(self, tool_name: str, progress_callback=None):
        """
        Generate comprehensive threat intelligence profile using Claude with web search
        
        Args:
            tool_name: Name of the tool/threat to analyze
            progress_callback: Optional callback for progress updates
            
        Returns:
            dict: Threat intelligence data
        """
        try:
            if progress_callback:
                progress_callback(0.1, "🔍 Initializing research...")
            
            print(f"DEBUG: Starting threat intelligence generation for: {tool_name}")
            
            prompt = f"""Generate a comprehensive threat intelligence profile for: {tool_name}

Use web search to gather current information. Return ONLY a complete JSON object with all sections below:

{{
  "coreMetadata": {{
    "name": "{tool_name}",
    "version": "Latest known version",
    "category": "Tool category (RAT/Backdoor/RMM/etc)",
    "profileId": "TI_{tool_name.upper().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}",
    "profileAuthor": "Claude AI",
    "createdDate": "{datetime.now().strftime('%Y-%m-%d')}",
    "lastUpdated": "{datetime.now().strftime('%Y-%m-%d')}",
    "profileVersion": "1.0",
    "tlpClassification": "TLP:AMBER",
    "trustScore": "Assessment based on source reliability"
  }},
  "webSearchSources": {{
    "searchQueriesUsed": ["search terms used"],
    "primarySources": [{{
      "url": "https://source-url.com",
      "title": "Source title",
      "domain": "domain.com",
      "accessDate": "{datetime.now().strftime('%Y-%m-%d')}",
      "relevanceScore": "High/Medium/Low",
      "contentType": "Report/Article/Database",
      "keyFindings": "Key information from source"
    }}],
    "searchStrategy": "How you approached the research",
    "dataFreshness": "Currency of information found",
    "sourceReliability": "Source trustworthiness assessment"
  }},
  "toolOverview": {{
    "description": "Tool description from research",
    "primaryPurpose": "Main purpose",
    "targetAudience": "Typical users",
    "knownAliases": ["aliases found"],
    "firstSeen": "Discovery/release date",
    "lastUpdated": "Recent activity",
    "currentStatus": "Current status"
  }},
  "technicalDetails": {{
    "architecture": "Technical architecture",
    "operatingSystems": ["supported OS"],
    "dependencies": ["dependencies"],
    "encryption": "Encryption methods",
    "obfuscation": "Obfuscation techniques",
    "persistence": ["persistence methods"],
    "capabilities": ["key capabilities"]
  }},
  "commandAndControl": {{
    "communicationMethods": "C2 communication",
    "commandProtocols": [{{
      "protocolName": "Protocol",
      "encoding": "Encoding method",
      "encryption": "Encryption used",
      "detectionNotes": "Detection guidance"
    }}],
    "beaconingPatterns": [{{
      "pattern": "Pattern description",
      "frequency": "Frequency details",
      "indicators": ["indicators"]
    }}],
    "commonCommands": ["commands"]
  }},
  "threatIntelligence": {{
    "entities": {{
      "threatActors": [{{
        "name": "Actor name",
        "attribution": "Attribution level",
        "activityTimeframe": "Activity period"
      }}],
      "campaigns": [{{
        "name": "Campaign name",
        "timeframe": "Campaign period",
        "targetSectors": ["sectors"],
        "geographicFocus": "Geography"
      }}]
    }},
    "riskAssessment": {{
      "overallRisk": "Risk level",
      "impactRating": "Impact assessment",
      "likelihoodRating": "Likelihood assessment",
      "riskFactors": ["risk factors"]
    }}
  }},
  "forensicArtifacts": {{
    "fileSystemArtifacts": ["file artifacts"],
    "registryArtifacts": ["registry keys"],
    "networkArtifacts": ["network indicators"],
    "memoryArtifacts": ["memory patterns"],
    "logArtifacts": ["log patterns"]
  }},
  "detectionAndMitigation": {{
    "yaraRules": ["YARA rules"],
    "sigmaRules": ["Sigma rules"],
    "iocs": {{
      "hashes": ["file hashes"],
      "domains": ["malicious domains"],
      "ips": ["malicious IPs"],
      "urls": ["malicious URLs"],
      "filenames": ["malicious files"]
    }},
    "behavioralIndicators": ["behaviors"]
  }},
  "mitigationAndResponse": {{
    "preventiveMeasures": ["prevention steps"],
    "detectionMethods": ["detection methods"],
    "responseActions": ["response actions"],
    "recoveryGuidance": ["recovery steps"]
  }},
  "referencesAndIntelligenceSharing": {{
    "sources": [{{
      "title": "Reference title",
      "url": "https://reference.url",
      "date": "2024-01-01",
      "relevanceScore": "High"
    }}],
    "mitreAttackMapping": "MITRE techniques",
    "cveReferences": "Related CVEs",
    "additionalReferences": ["references"]
  }},
  "integration": {{
    "siemIntegration": "SIEM guidance",
    "threatHuntingQueries": ["hunting queries"],
    "automatedResponse": "Automation guidance"
  }},
  "lineage": {{
    "variants": ["variants"],
    "evolution": "Evolution description",
    "relationships": ["related tools"]
  }},
  "contextualAnalysis": {{
    "usageContexts": {{
      "legitimateUse": "Legitimate uses",
      "maliciousUse": "Malicious uses",
      "dualUseConsiderations": "Dual-use notes"
    }},
    "trendAnalysis": {{
      "industryImpact": "Industry impact",
      "futureOutlook": "Future trends",
      "adoptionTrend": "Adoption patterns"
    }}
  }},
  "operationalGuidance": {{
    "validationCriteria": ["validation criteria"],
    "communityResources": [{{
      "resourceType": "Type",
      "name": "Resource name",
      "url": "https://resource.url",
      "focus": "Focus area"
    }}]
  }}
}}

Use web search extensively. Populate with real current data about {tool_name}."""

            if progress_callback:
                progress_callback(0.2, "🤖 Sending request to Claude...")
            
            print("DEBUG: Sending request to Claude API...")
            print("DEBUG: Using max_tokens = 8192")
            
            # Generate the threat intelligence using Claude with CORRECT token limit
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=8192,  # EXPLICITLY set to 8192 - the maximum allowed
                temperature=0.3,
                messages=[{
                    "role": "user", 
                    "content": prompt
                }]
            )
            
            print("DEBUG: Received response from Claude API")
            
            if progress_callback:
                progress_callback(0.7, "📊 Processing response...")
            
            response_text = response.content[0].text.strip()
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
                progress_callback(0.9, "🔍 Parsing JSON response...")
            
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
            
            print(f"DEBUG: Validation successful. JSON contains {len(json_data)} top-level keys")
            print(f"DEBUG: Keys present: {list(json_data.keys())}")
            
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

    def save_to_file(self, data: Dict[str, Any], filename: str = None) -> str:
        """Save the threat intelligence data to a JSON file."""
        if filename is None:
            tool_name = data.get("coreMetadata", {}).get("name", "threat_intel")
            filename = f"{tool_name.lower().replace(' ', '_')}_threat_intel.json"
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filename