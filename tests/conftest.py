import pytest


def build_threat_profile_data(source_url: str = "https://example.com/report") -> dict:
    return {
        "coreMetadata": {
            "name": "Example Threat",
            "version": "1.0",
            "category": "Backdoor",
            "profileId": "TI_EXAMPLE_THREAT_20260811",
            "profileAuthor": "OpenAI model pipeline",
            "createdDate": "2026-08-11",
            "lastUpdated": "2026-08-11",
            "profileVersion": "1.0",
            "tlpClassification": "TLP:AMBER",
            "trustScore": "High",
        },
        "webSearchSources": {
            "searchQueriesUsed": ["Example Threat analysis"],
            "primarySources": [
                {
                    "url": source_url,
                    "title": "Example report",
                    "domain": "example.com",
                    "accessDate": "2026-08-11",
                    "relevanceScore": "High",
                    "contentType": "Report",
                    "keyFindings": "Observed behavior and mitigations.",
                }
            ],
            "searchStrategy": "Searched primary sources.",
            "dataFreshness": "Current as of 2026-08-11.",
            "sourceReliability": "Primary source.",
        },
        "toolOverview": {
            "description": "Example threat description.",
            "primaryPurpose": "Remote access.",
            "targetAudience": "Threat analysts.",
            "knownAliases": [],
            "firstSeen": "2026",
            "lastUpdated": "2026-08-11",
            "currentStatus": "Active",
        },
        "technicalDetails": {
            "architecture": "Client-server.",
            "operatingSystems": ["Windows"],
            "dependencies": [],
            "encryption": "TLS",
            "obfuscation": "Unknown",
            "persistence": ["Service"],
            "capabilities": ["Remote access"],
        },
        "commandAndControl": {
            "communicationMethods": "HTTPS",
            "commandProtocols": [
                {
                    "protocolName": "HTTPS",
                    "encoding": "JSON",
                    "encryption": "TLS",
                    "detectionNotes": "Inspect anomalous destinations.",
                }
            ],
            "beaconingPatterns": [
                {
                    "pattern": "Periodic callbacks",
                    "frequency": "Unknown",
                    "indicators": ["Repeated outbound HTTPS"],
                }
            ],
            "commonCommands": ["execute"],
        },
        "threatIntelligence": {
            "entities": {
                "threatActors": [
                    {
                        "name": "Unknown",
                        "attribution": "Unconfirmed",
                        "activityTimeframe": "2026",
                    }
                ],
                "campaigns": [
                    {
                        "name": "Unknown",
                        "timeframe": "2026",
                        "targetSectors": ["Unknown"],
                        "geographicFocus": "Unknown",
                    }
                ],
            },
            "riskAssessment": {
                "overallRisk": "High",
                "impactRating": "High",
                "likelihoodRating": "Medium",
                "riskFactors": ["Remote access"],
            },
        },
        "forensicArtifacts": {
            "fileSystemArtifacts": ["example.exe"],
            "registryArtifacts": [],
            "networkArtifacts": ["HTTPS callbacks"],
            "memoryArtifacts": [],
            "logArtifacts": ["Process creation"],
        },
        "detectionAndMitigation": {
            "iocs": {
                "hashes": [],
                "domains": [],
                "ips": [],
                "urls": [],
                "filenames": ["example.exe"],
            },
            "behavioralIndicators": ["Unexpected service creation"],
        },
        "mitigationAndResponse": {
            "preventiveMeasures": ["Application control"],
            "detectionMethods": ["Monitor service creation"],
            "responseActions": ["Isolate affected host"],
            "recoveryGuidance": ["Rebuild compromised systems"],
        },
        "referencesAndIntelligenceSharing": {
            "sources": [
                {
                    "title": "Example report",
                    "url": source_url,
                    "date": "2026-08-11",
                    "relevanceScore": "High",
                }
            ],
            "mitreAttackMapping": "T1543",
            "cveReferences": "None verified",
            "additionalReferences": [],
        },
        "integration": {
            "siemIntegration": "Ingest endpoint telemetry.",
            "threatHuntingQueries": ["Search for example.exe"],
            "automatedResponse": "Isolate confirmed hosts.",
        },
        "lineage": {
            "variants": [],
            "evolution": "Unknown",
            "relationships": [],
        },
        "contextualAnalysis": {
            "usageContexts": {
                "legitimateUse": "None verified",
                "maliciousUse": "Remote access",
                "dualUseConsiderations": "Validate context before blocking.",
            },
            "trendAnalysis": {
                "industryImpact": "Potential endpoint compromise.",
                "futureOutlook": "Continued monitoring required.",
                "adoptionTrend": "Unknown",
            },
        },
        "operationalGuidance": {
            "validationCriteria": ["Confirm indicators in local telemetry"],
            "communityResources": [
                {
                    "resourceType": "Report",
                    "name": "Example report",
                    "url": source_url,
                    "focus": "Threat behavior",
                }
            ],
        },
    }


@pytest.fixture
def threat_profile_data() -> dict:
    return build_threat_profile_data()
