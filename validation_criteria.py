"""
Validation criteria and prompts for each section type in threat intelligence profiles
"""

SECTION_CRITERIA = {
    "webSearchSources": {
        "required_fields": ["searchQueriesUsed", "primarySources", "searchStrategy"],
        "quality_checks": [
            "Search queries should be specific and varied",
            "Primary sources should include authoritative domains",
            "Each source should have URL, title, and key findings",
            "Sources should be recent (check accessDate)",
            "Multiple source types (reports, advisories, analysis)"
        ],
        "min_score": 3.5,
        "critical": True
    },
    "technicalDetails": {
        "required_fields": ["architecture", "operatingSystems", "capabilities", "dependencies"],
        "quality_checks": [
            "Architecture description should be technical, not generic",
            "Operating systems should include version information where known",
            "Capabilities should be specific and actionable",
            "Dependencies should include version numbers",
            "Should describe technical implementation details"
        ],
        "min_score": 4.0,
        "critical": True
    },
    "commandAndControl": {
        "required_fields": ["communicationMethods", "commonCommands"],
        "quality_checks": [
            "C2 methods should include technical details (ports, protocols)",
            "Command protocols should specify encoding/encryption if known",
            "Beaconing patterns should include frequency/timing",
            "Should include detection guidance for C2 traffic",
            "Common commands should use proper syntax/format"
        ],
        "min_score": 3.5,
        "critical": True
    },
    "detectionAndMitigation": {
        "required_fields": ["yaraRules", "sigmaRules", "iocs", "behavioralIndicators"],
        "quality_checks": [
            "IOCs should be properly formatted and valid",
            "YARA rules should follow correct syntax",
            "Sigma rules should be actionable",
            "Should include both network and host-based indicators",
            "Behavioral indicators should be specific, not generic",
            "IOCs should include context (why they're indicators)"
        ],
        "min_score": 4.0,
        "critical": True
    },
    "threatIntelligence": {
        "required_fields": ["entities", "riskAssessment"],
        "quality_checks": [
            "Threat actors should have attribution confidence levels",
            "Campaigns should include timeframes",
            "Risk assessment should justify ratings",
            "Should link to known TTPs when possible"
        ],
        "min_score": 3.0,
        "critical": False
    },
    "forensicArtifacts": {
        "required_fields": ["fileSystemArtifacts", "registryArtifacts", "networkArtifacts"],
        "quality_checks": [
            "Artifacts should be specific file paths/registry keys",
            "Should indicate what each artifact reveals",
            "Should cover multiple artifact types",
            "Memory artifacts should include patterns to search"
        ],
        "min_score": 3.5,
        "critical": False
    },
    "mitigationAndResponse": {
        "required_fields": ["preventiveMeasures", "detectionMethods", "responseActions"],
        "quality_checks": [
            "Measures should be actionable and specific",
            "Should prioritize mitigations by effectiveness",
            "Response actions should follow incident response best practices",
            "Should include both technical and procedural measures"
        ],
        "min_score": 3.5,
        "critical": True
    }
}

VALIDATION_PROMPTS = {
    "section_validation": """You are a cybersecurity expert evaluating a section of a threat intelligence profile.

Section Name: {section_name}
Section Content: {content}

Evaluate this section on the following dimensions (score 0-5, where 5 is excellent):

1. **Completeness** (0-5): Are all expected fields populated with meaningful content?
   - Required fields: {required_fields}
   
2. **Technical Accuracy** (0-5): Is the technical information accurate and properly detailed?
   - Quality checks: {quality_checks}
   
3. **Source Quality** (0-5): Are claims supported by credible sources and properly cited?
   - For technical claims, are sources provided?
   - Are sources authoritative for this type of information?
   
4. **Actionability** (0-5): Can a security team act on this information?
   - Are indicators specific enough to implement?
   - Is guidance clear and practical?
   
5. **Relevance** (0-5): Is all content directly relevant to understanding this threat?
   - No generic filler content
   - Specific to this threat/tool

Additionally, identify:
- Missing critical information that should be included
- Weak or generic content that needs improvement  
- Any technical inconsistencies or errors
- Specific recommendations for improvement

Return your evaluation as JSON:
{{
    "scores": {{
        "completeness": <0-5>,
        "technical_accuracy": <0-5>,
        "source_quality": <0-5>,
        "actionability": <0-5>,
        "relevance": <0-5>,
        "overall": <average of above scores>
    }},
    "missing_information": ["list of missing critical details"],
    "weak_areas": ["list of areas needing improvement"],
    "technical_issues": ["list of technical problems"],
    "specific_improvements": ["concrete suggestions for improvement"],
    "recommendation": "PASS/RETRY/ENHANCE",
    "reasoning": "Brief explanation of the evaluation"
}}

Recommendation guidelines:
- PASS: All scores >= {min_score}, no critical issues
- ENHANCE: Some scores < {min_score} but content is usable
- RETRY: Critical information missing or major technical issues""",

    "consistency_check": """Analyze the consistency across different sections of this threat intelligence profile.

Profile sections: {sections}

Check for:
1. **Technical Consistency**: Do technical details align across sections?
2. **Temporal Consistency**: Do timelines and dates make sense?
3. **Source Consistency**: Are sources used appropriately across sections?
4. **Terminology Consistency**: Are terms used consistently?

Return as JSON:
{{
    "consistency_score": <0-5>,
    "inconsistencies": ["list of found inconsistencies"],
    "recommendations": ["how to fix inconsistencies"]
}}""",

    "improvement_prompt": """Given this section that needs improvement, generate an enhanced version.

Section Name: {section_name}
Current Content: {content}
Issues Identified: {issues}
Specific Improvements Needed: {improvements}

Generate an improved version that addresses all identified issues. Ensure the improved content:
1. Addresses all missing information
2. Replaces generic content with specific details
3. Fixes any technical inaccuracies
4. Maintains the same JSON structure

Return ONLY the improved JSON content for this section."""
}