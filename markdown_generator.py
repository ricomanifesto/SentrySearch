"""
Markdown generator for converting threat intelligence JSON to readable format
"""
from typing import Dict, Any, List
from datetime import datetime


def format_date(date_str: str) -> str:
    """Format date strings consistently"""
    if not date_str:
        return "Unknown"
    
    try:
        # Try to parse and reformat the date
        date_obj = datetime.strptime(date_str, "%Y-%m-%d")
        return date_obj.strftime("%B %d, %Y")
    except ValueError:
        # If parsing fails, return the original string
        return date_str


def generate_markdown(data):
    """Generate markdown report from threat intelligence data"""
    
    if not data or not isinstance(data, dict):
        return "# ❌ Error\n\nNo valid threat intelligence data provided."
    
    md = []
    
    try:
        # Header with core metadata
        print("MARKDOWN DEBUG: Starting header section...")
        core = data.get("coreMetadata", {})
        
        md.append(f"# 🛡️ Threat Intelligence Profile: {core.get('name', 'Unknown Tool')}")
        md.append("")
        md.append("---")
        md.append("")
        
        # Metadata table
        md.append("## 📋 Profile Metadata")
        md.append("")
        md.append("| Field | Value |")
        md.append("|-------|-------|")
        md.append(f"| **Tool Name** | {core.get('name', 'Unknown')} |")
        md.append(f"| **Version** | {core.get('version', 'Unknown')} |")
        md.append(f"| **Category** | {core.get('category', 'Unknown')} |")
        md.append(f"| **Profile ID** | {core.get('profileId', 'Unknown')} |")
        md.append(f"| **Profile Author** | {core.get('profileAuthor', 'Unknown')} |")
        md.append(f"| **Created Date** | {core.get('createdDate', 'Unknown')} |")
        md.append(f"| **Last Updated** | {core.get('lastUpdated', 'Unknown')} |")
        md.append(f"| **Profile Version** | {core.get('profileVersion', 'Unknown')} |")
        md.append(f"| **TLP Classification** | {core.get('tlpClassification', 'Unknown')} |")
        md.append(f"| **Trust Score** | {core.get('trustScore', 'Unknown')} |")
        md.append("")
        
        # Web Search Sources (NEW SECTION)
        print("MARKDOWN DEBUG: Starting web search sources section...")
        web_sources = data.get("webSearchSources", {})
        if isinstance(web_sources, dict):
            md.append("## 🌐 Web Search Sources & Research Methodology")
            md.append("")
            
            # Search Strategy
            strategy = web_sources.get("searchStrategy", "")
            if strategy:
                md.append(f"**Search Strategy**: {strategy}")
                md.append("")
            
            # Search Queries Used
            queries = web_sources.get("searchQueriesUsed", [])
            if queries and isinstance(queries, list):
                md.append("### 🔍 Search Queries Used")
                md.append("")
                for query in queries:
                    md.append(f"- `{query}`")
                md.append("")
            
            # Primary Sources
            primary_sources = web_sources.get("primarySources", [])
            if primary_sources and isinstance(primary_sources, list):
                md.append("### 📚 Primary Sources")
                md.append("")
                for source in primary_sources:
                    if isinstance(source, dict):
                        title = source.get('title', 'Unknown Source')
                        url = source.get('url', '')
                        domain = source.get('domain', 'Unknown Domain')
                        relevance = source.get('relevanceScore', 'Unknown')
                        content_type = source.get('contentType', 'Unknown')
                        findings = source.get('keyFindings', 'No findings listed')
                        access_date = source.get('accessDate', 'Unknown')
                        
                        md.append(f"**{title}**")
                        if url:
                            md.append(f"- **URL**: [{url}]({url})")
                        md.append(f"- **Domain**: {domain}")
                        md.append(f"- **Content Type**: {content_type}")
                        md.append(f"- **Relevance**: {relevance}")
                        md.append(f"- **Access Date**: {access_date}")
                        md.append(f"- **Key Findings**: {findings}")
                        md.append("")
            
            # Additional Resources
            additional = web_sources.get("additionalResources", [])
            if additional and isinstance(additional, list):
                md.append("### 🔗 Additional Resources")
                md.append("")
                for resource in additional:
                    if isinstance(resource, dict):
                        title = resource.get('title', 'Unknown Resource')
                        url = resource.get('url', '')
                        description = resource.get('description', 'No description')
                        
                        if url:
                            md.append(f"- **[{title}]({url})**: {description}")
                        else:
                            md.append(f"- **{title}**: {description}")
                md.append("")
            
            # Data Quality Assessment
            freshness = web_sources.get("dataFreshness", "")
            reliability = web_sources.get("sourceReliability", "")
            if freshness or reliability:
                md.append("### 📊 Data Quality Assessment")
                md.append("")
                if freshness:
                    md.append(f"**Data Freshness**: {freshness}")
                if reliability:
                    md.append(f"**Source Reliability**: {reliability}")
                md.append("")

        # Tool Overview
        print("MARKDOWN DEBUG: Starting tool overview section...")
        overview = data.get("toolOverview", {})
        if isinstance(overview, dict):
            md.append("## 🔍 Tool Overview")
            md.append("")
            md.append(f"**Description**: {overview.get('description', 'No description available')}")
            md.append("")
            md.append(f"**Primary Purpose**: {overview.get('primaryPurpose', 'Unknown')}")
            md.append("")
            md.append(f"**Target Audience**: {overview.get('targetAudience', 'Unknown')}")
            md.append("")
            
            # Known aliases
            aliases = overview.get("knownAliases", [])
            if aliases and isinstance(aliases, list):
                md.append("**Known Aliases**:")
                for alias in aliases:
                    md.append(f"- {alias}")
            md.append("")
            
            md.append(f"**First Seen**: {overview.get('firstSeen', 'Unknown')}")
            md.append("")
            md.append(f"**Last Updated**: {overview.get('lastUpdated', 'Unknown')}")
            md.append("")
            md.append(f"**Current Status**: {overview.get('currentStatus', 'Unknown')}")
            md.append("")

        # Technical Details
        print("MARKDOWN DEBUG: Starting technical details section...")
        technical = data.get("technicalDetails", {})
        if isinstance(technical, dict):
            md.append("## ⚙️ Technical Details")
            md.append("")
            md.append(f"**Architecture**: {technical.get('architecture', 'Unknown')}")
            md.append("")
            
            # Operating Systems
            os_list = technical.get("operatingSystems", [])
            if os_list and isinstance(os_list, list):
                md.append("**Supported Operating Systems**:")
                for os in os_list:
                    md.append(f"- {os}")
            md.append("")
            
            # Dependencies
            deps = technical.get("dependencies", [])
            if deps and isinstance(deps, list):
                md.append("**Dependencies**:")
                for dep in deps:
                    md.append(f"- {dep}")
            md.append("")
            
            md.append(f"**Encryption**: {technical.get('encryption', 'Unknown')}")
            md.append("")
            md.append(f"**Obfuscation**: {technical.get('obfuscation', 'Unknown')}")
            md.append("")
            
            # Persistence mechanisms
            persistence = technical.get("persistence", [])
            if persistence and isinstance(persistence, list):
                md.append("**Persistence Mechanisms**:")
                for method in persistence:
                    md.append(f"- {method}")
            md.append("")
            
            # Capabilities
            capabilities = technical.get("capabilities", [])
            if capabilities and isinstance(capabilities, list):
                md.append("**Key Capabilities**:")
                for capability in capabilities:
                    md.append(f"- {capability}")
            md.append("")
        
        # Command and Control
        print("MARKDOWN DEBUG: Starting C2 section...")
        c2 = data.get("commandAndControl", {})
        if isinstance(c2, dict):
            md.append("## 🎛️ Command and Control")
            md.append("")
            
            # Common Commands
            commands = c2.get("commonCommands", [])
            if commands and isinstance(commands, list):
                md.append("**Common Commands**:")
                for cmd in commands:
                    md.append(f"- `{cmd}`")
                md.append("")
            
            # Command Protocols
            protocols = c2.get("commandProtocols", [])
            if protocols and isinstance(protocols, list):
                md.append("**Command Protocols**:")
                md.append("")
                for protocol in protocols:
                    if isinstance(protocol, dict):
                        md.append(f"**{protocol.get('protocolName', 'Unknown Protocol')}**")
                        md.append(f"- **Encoding**: {protocol.get('encoding', 'Unknown')}")
                        md.append(f"- **Encryption**: {protocol.get('encryption', 'Unknown')}")
                        md.append(f"- **Detection Notes**: {protocol.get('detectionNotes', 'None')}")
                        md.append("")
            
            # Beaconing Patterns
            patterns = c2.get("beaconingPatterns", [])
            if patterns and isinstance(patterns, list):
                md.append("**Beaconing Patterns**:")
                md.append("")
                for pattern in patterns:
                    if isinstance(pattern, dict):
                        md.append(f"**Pattern**: {pattern.get('pattern', 'Unknown')}")
                        md.append(f"- **Frequency**: {pattern.get('frequency', 'Unknown')}")
                        indicators = pattern.get('indicators', [])
                        if indicators:
                            md.append(f"- **Indicators**: {', '.join(indicators)}")
                        md.append("")
        
        # Threat Intelligence
        print("MARKDOWN DEBUG: Starting threat intelligence section...")
        threat_intel = data.get("threatIntelligence", {})
        if isinstance(threat_intel, dict):
            md.append("## 🎯 Threat Intelligence")
            md.append("")
            
            # Risk Assessment
            risk = threat_intel.get("riskAssessment", {})
            if isinstance(risk, dict):
                md.append("### Risk Assessment")
                md.append("")
                md.append(f"**Overall Risk**: {risk.get('overallRisk', 'Unknown')}")
                md.append("")
                md.append(f"**Impact Rating**: {risk.get('impactRating', 'Unknown')}")
                md.append("")
                md.append(f"**Likelihood Rating**: {risk.get('likelihoodRating', 'Unknown')}")
                md.append("")
            
            # Entities
            entities = threat_intel.get("entities", {})
            if isinstance(entities, dict):
                # Threat Actors
                actors = entities.get("threatActors", [])
                if actors and isinstance(actors, list):
                    md.append("### Associated Threat Actors")
                    md.append("")
                    for actor in actors:
                        if isinstance(actor, dict):
                            md.append(f"**{actor.get('name', 'Unknown Actor')}**")
                            md.append(f"- **Attribution**: {actor.get('attribution', 'Unknown')}")
                            md.append(f"- **Activity Timeframe**: {actor.get('activityTimeframe', 'Unknown')}")
                            md.append("")
                
                # Campaigns
                campaigns = entities.get("campaigns", [])
                if campaigns and isinstance(campaigns, list):
                    md.append("### Related Campaigns")
                    md.append("")
                    for campaign in campaigns:
                        if isinstance(campaign, dict):
                            md.append(f"**{campaign.get('name', 'Unknown Campaign')}**")
                            md.append(f"- **Timeframe**: {campaign.get('timeframe', 'Unknown')}")
                            sectors = campaign.get('targetSectors', [])
                            if sectors:
                                md.append(f"- **Target Sectors**: {', '.join(sectors)}")
                            md.append(f"- **Geographic Focus**: {campaign.get('geographicFocus', 'Unknown')}")
                            md.append("")
        
        # Forensic Artifacts
        print("MARKDOWN DEBUG: Starting forensic artifacts section...")
        forensics = data.get("forensicArtifacts", {})
        if isinstance(forensics, dict):
            md.append("## 🔍 Forensic Artifacts")
            md.append("")
            
            artifact_types = [
                ("fileSystemArtifacts", "File System Artifacts"),
                ("registryArtifacts", "Registry Artifacts"),
                ("networkArtifacts", "Network Artifacts"),
                ("memoryArtifacts", "Memory Artifacts"),
                ("logArtifacts", "Log Artifacts")
            ]
            
            for key, title in artifact_types:
                artifacts = forensics.get(key, [])
                if artifacts and isinstance(artifacts, list):
                    md.append(f"### {title}")
                    md.append("")
                    for artifact in artifacts:
                        md.append(f"- `{artifact}`")
                    md.append("")
        
        # Detection and Mitigation
        print("MARKDOWN DEBUG: Starting detection section...")
        detection = data.get("detectionAndMitigation", {})
        if isinstance(detection, dict):
            md.append("## 🛡️ Detection and Mitigation")
            md.append("")
            
            # YARA Rules
            yara = detection.get("yaraRules", [])
            if yara and isinstance(yara, list):
                md.append("### YARA Rules")
                md.append("")
                for rule in yara:
                    md.append(f"- {rule}")
                md.append("")
            
            # Sigma Rules
            sigma = detection.get("sigmaRules", [])
            if sigma and isinstance(sigma, list):
                md.append("### Sigma Rules")
                md.append("")
                for rule in sigma:
                    md.append(f"- {rule}")
                md.append("")
            
            # IOCs
            iocs = detection.get("iocs", {})
            if isinstance(iocs, dict):
                md.append("### Indicators of Compromise (IOCs)")
                md.append("")
                
                ioc_types = [
                    ("hashes", "File Hashes"),
                    ("domains", "Malicious Domains"),
                    ("ips", "Malicious IP Addresses"),
                    ("urls", "Malicious URLs"),
                    ("filenames", "Malicious Filenames")
                ]
                
                for key, title in ioc_types:
                    ioc_list = iocs.get(key, [])
                    if ioc_list and isinstance(ioc_list, list):
                        md.append(f"**{title}**:")
                        for ioc in ioc_list:
                            md.append(f"- `{ioc}`")
                        md.append("")
            
            # Behavioral Indicators
            behavioral = detection.get("behavioralIndicators", [])
            if behavioral and isinstance(behavioral, list):
                md.append("### Behavioral Indicators")
                md.append("")
                for indicator in behavioral:
                    md.append(f"- {indicator}")
                md.append("")
        
        # Continue with remaining sections...
        print("MARKDOWN DEBUG: Processing remaining sections...")
        
        # Mitigation and Response
        mitigation = data.get("mitigationAndResponse", {})
        if isinstance(mitigation, dict):
            md.append("## 🚨 Mitigation and Response")
            md.append("")
            
            section_types = [
                ("preventiveMeasures", "Preventive Measures"),
                ("detectionMethods", "Detection Methods"),
                ("responseActions", "Response Actions"),
                ("recoveryGuidance", "Recovery Guidance")
            ]
            
            for key, title in section_types:
                items = mitigation.get(key, [])
                if items and isinstance(items, list):
                    md.append(f"### {title}")
                    md.append("")
                    for item in items:
                        md.append(f"- {item}")
                    md.append("")
        
        # References and Intelligence Sharing
        references = data.get("referencesAndIntelligenceSharing", {})
        if isinstance(references, dict):
            md.append("## 📚 References and Intelligence Sharing")
            md.append("")
            
            sources = references.get("sources", [])
            if sources and isinstance(sources, list):
                md.append("### Sources")
                md.append("")
                for source in sources:
                    if isinstance(source, dict):
                        title = source.get('title', 'Unknown Source')
                        url = source.get('url', '')
                        date = source.get('date', '')
                        relevance = source.get('relevanceScore', '')
                        
                        if url:
                            md.append(f"- [{title}]({url}) - {date} (Relevance: {relevance})")
                        else:
                            md.append(f"- {title} - {date} (Relevance: {relevance})")
                md.append("")
        
        # Integration
        integration = data.get("integration", {})
        if isinstance(integration, dict):
            md.append("## 🔧 Integration Guidance")
            md.append("")
            md.append(f"**SIEM Integration**: {integration.get('siemIntegration', 'No guidance available')}")
            md.append("")
            
            hunting_queries = integration.get("threatHuntingQueries", [])
            if hunting_queries and isinstance(hunting_queries, list):
                md.append("**Threat Hunting Queries**:")
                for query in hunting_queries:
                    md.append(f"- `{query}`")
                md.append("")
            
            md.append(f"**Automated Response**: {integration.get('automatedResponse', 'No guidance available')}")
            md.append("")
        
        # Lineage
        lineage = data.get("lineage", {})
        if isinstance(lineage, dict):
            md.append("## 🧬 Tool Lineage")
            md.append("")
            
            variants = lineage.get("variants", [])
            if variants and isinstance(variants, list):
                md.append("**Known Variants**:")
                for variant in variants:
                    md.append(f"- {variant}")
                md.append("")
            
            md.append(f"**Evolution**: {lineage.get('evolution', 'No evolution data available')}")
            md.append("")
            
            relationships = lineage.get("relationships", [])
            if relationships and isinstance(relationships, list):
                md.append("**Related Tools**:")
                for rel in relationships:
                    md.append(f"- {rel}")
                md.append("")
        
        # Contextual Analysis
        context = data.get("contextualAnalysis", {})
        if isinstance(context, dict):
            md.append("## 📊 Contextual Analysis")
            md.append("")
            
            usage = context.get("usageContexts", {})
            if isinstance(usage, dict):
                md.append("### Usage Contexts")
                md.append("")
                md.append(f"**Legitimate Use**: {usage.get('legitimateUse', 'None identified')}")
                md.append("")
                md.append(f"**Malicious Use**: {usage.get('maliciousUse', 'Unknown')}")
                md.append("")
                md.append(f"**Dual-Use Considerations**: {usage.get('dualUseConsiderations', 'None')}")
                md.append("")
            
            trends = context.get("trendAnalysis", {})
            if isinstance(trends, dict):
                md.append("### Trend Analysis")
                md.append("")
                md.append(f"**Industry Impact**: {trends.get('industryImpact', 'Unknown')}")
                md.append("")
                md.append(f"**Future Outlook**: {trends.get('futureOutlook', 'Unknown')}")
                md.append("")
                md.append(f"**Adoption Trend**: {trends.get('adoptionTrend', 'Unknown')}")
                md.append("")
        
        # Operational Guidance
        operations = data.get("operationalGuidance", {})
        if isinstance(operations, dict):
            md.append("## 🎯 Operational Guidance")
            md.append("")
            
            criteria = operations.get("validationCriteria", [])
            if criteria and isinstance(criteria, list):
                md.append("### Validation Criteria")
                md.append("")
                for criterion in criteria:
                    md.append(f"- {criterion}")
                md.append("")
            
            resources = operations.get("communityResources", [])
            if resources and isinstance(resources, list):
                md.append("### Community Resources")
                md.append("")
                for resource in resources:
                    if isinstance(resource, dict):
                        name = resource.get('name', 'Unknown Resource')
                        url = resource.get('url', '')
                        resource_type = resource.get('resourceType', 'Unknown')
                        focus = resource.get('focus', '')
                        
                        if url:
                            md.append(f"- **{name}** ({resource_type}) - [{url}]({url}) - {focus}")
                        else:
                            md.append(f"- **{name}** ({resource_type}) - {focus}")
                md.append("")
        
        print("MARKDOWN DEBUG: Completed all sections successfully")
        return "\n".join(md)
        
    except Exception as e:
        print(f"MARKDOWN DEBUG: Exception occurred: {e}")
        print(f"MARKDOWN DEBUG: Exception type: {type(e)}")
        import traceback
        traceback.print_exc()
        return f"# ❌ Error in Markdown Generation\n\n**Error**: {str(e)}\n\n**Location**: During markdown generation"