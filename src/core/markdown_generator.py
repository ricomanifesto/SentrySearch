"""
Markdown generator for converting threat intelligence JSON to readable format
"""

import logging
import re
from datetime import datetime
from typing import Any, Mapping

logger = logging.getLogger(__name__)


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


def format_quality_score(score: float | None) -> str:
    """Format a quality score with a descriptive rating."""
    if score is None:
        return "Not scored (evaluator unavailable)"
    if score >= 4.5:
        return f"{score}/5.0 (Excellent)"
    elif score >= 4.0:
        return f"{score}/5.0 (Good)"
    elif score >= 3.5:
        return f"{score}/5.0 (Acceptable)"
    elif score >= 3.0:
        return f"{score}/5.0 (Needs Improvement)"
    else:
        return f"{score}/5.0 (Poor)"


def _humanize_section_name(section_name: str) -> str:
    """Turn a camel-case profile key into a readable table label."""

    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", section_name)
    return words.replace("_", " ").title()


def _markdown_table_cell(value: Any) -> str:
    """Keep dynamic values inside one Markdown table cell."""

    return str(value).replace("\n", " ").replace("|", r"\|")


def render_quality_assessment(quality: Mapping[str, Any]) -> str:
    """Render the inspectable score summary for an evaluated threat profile."""

    summary = quality.get("summary", {})
    section_validations = quality.get("section_validations", {})
    lines = [
        "## Quality Assessment Report",
        "",
        "### Summary",
        "",
        f"- **Overall Quality Score**: {format_quality_score(quality.get('overall_score', 0))}",
        f"- **Sections Evaluated**: {summary.get('total_sections', 0)}",
        f"- **Sections Passed**: {summary.get('passed_sections', 0)}",
        f"- **Sections to Enhance**: {summary.get('enhance_sections', 0)}",
        f"- **Sections Failed**: {summary.get('failed_sections', 0)}",
        f"- **Sections Unavailable**: {summary.get('unavailable_sections', 0)}",
    ]

    if section_validations:
        lines.extend(
            [
                "",
                "### Section Scores",
                "",
                "| Section | Score | Status |",
                "|---------|-------|--------|",
            ]
        )
        for section_name, validation in sorted(section_validations.items()):
            overall = validation.get("scores", {}).get("overall")
            recommendation = str(validation.get("recommendation", "UNKNOWN"))
            label = _markdown_table_cell(_humanize_section_name(section_name))
            status = _markdown_table_cell(recommendation)
            score_label = (
                f"{overall:.1f}/5.0" if isinstance(overall, (int, float)) else "Not scored"
            )
            lines.append(f"| {label} | {score_label} | {status} |")

    recommendations = quality.get("recommendations", [])
    if recommendations:
        lines.extend(["", "### Improvement Recommendations", ""])
        lines.extend(
            f"{position}. {recommendation}"
            for position, recommendation in enumerate(recommendations[:5], start=1)
        )

    skipped_sections = quality.get("skipped_sections", [])
    if skipped_sections:
        lines.extend(["", "### Sections Not Scored", ""])
        lines.extend(
            f"- {_humanize_section_name(section_name)}" for section_name in skipped_sections
        )

    consistency = quality.get("consistency", {})
    if consistency:
        lines.extend(["", "### Cross-Section Consistency", ""])
        if consistency.get("was_evaluated", True):
            lines.append(f"**Consistency Score**: {consistency['consistency_score']}/5.0")
            inconsistencies = consistency.get("inconsistencies", [])
            if inconsistencies:
                lines.extend(["", "**Issues Found:**"])
                lines.extend(f"- {issue}" for issue in inconsistencies)
        else:
            lines.append("**Status**: Not evaluated")

    return "\n".join(lines)


def generate_markdown(data):
    """Generate markdown report from threat intelligence data"""

    if not data or not isinstance(data, dict):
        return "# Error\n\nNo valid threat intelligence data provided."

    md = []

    try:
        # Header with core metadata
        logger.debug("Starting header section...")
        core = data.get("coreMetadata", {})

        md.append(f"# Threat Intelligence Profile: {core.get('name', 'Unknown Tool')}")
        md.append("")

        evidence = data.get("evidenceAdmissibility")
        if isinstance(evidence, Mapping):
            evidence_status = str(evidence.get("status") or "unassessed").replace("_", " ")
            md.append(f"**Operational Evidence Safety**: {evidence_status.title()}")
            md.append(
                f"**Evidence Contract**: Schema {evidence.get('schemaVersion', 'unrecorded')}"
            )
            md.append("")

        if "_quality_assessment" in data:
            quality = data["_quality_assessment"]
            overall_score = quality.get("overall_score")
            md.append(f"**Quality Score**: {format_quality_score(overall_score)}")
            md.append("")

        md.append("---")
        md.append("")

        # Metadata table
        md.append("## Profile Metadata")
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
        md.append("")

        # [All existing section generation code remains the same...]
        # Web Search Sources
        logger.debug("Starting web search sources section...")
        web_sources = data.get("webSearchSources", {})
        if isinstance(web_sources, dict):
            md.append("## Web Search Sources & Research Methodology")
            md.append("")

            # Search Strategy
            strategy = web_sources.get("searchStrategy", "")
            if strategy:
                md.append(f"**Search Strategy**: {strategy}")
                md.append("")

            # Search Queries Used
            queries = web_sources.get("searchQueriesUsed", [])
            if queries and isinstance(queries, list):
                md.append("### Search Queries Used")
                md.append("")
                for query in queries:
                    md.append(f"- `{query}`")
                md.append("")

            # Primary Sources
            primary_sources = web_sources.get("primarySources", [])
            if primary_sources and isinstance(primary_sources, list):
                md.append("### Primary Sources")
                md.append("")
                for source in primary_sources:
                    if isinstance(source, dict):
                        title = source.get("title", "Unknown Source")
                        url = source.get("url", "")
                        domain = source.get("domain", "Unknown Domain")
                        relevance = source.get("relevanceScore", "Unknown")
                        content_type = source.get("contentType", "Unknown")
                        findings = source.get("keyFindings", "No findings listed")
                        access_date = source.get("accessDate", "Unknown")

                        md.append(f"**{title}**")
                        if url:
                            md.append(f"- **URL**: [{url}]({url})")
                        md.append(f"- **Domain**: {domain}")
                        md.append(f"- **Content Type**: {content_type}")
                        md.append(f"- **Relevance**: {relevance}")
                        md.append(f"- **Access Date**: {access_date}")
                        md.append(f"- **Key Findings**: {findings}")
                        md.append("")

            if isinstance(evidence, Mapping):
                source_observations = evidence.get("sourceObservations")
                excluded = [
                    source
                    for source in source_observations or []
                    if isinstance(source, Mapping) and source.get("purpose") != "operational"
                ]
                if excluded:
                    md.append("### Sources Not Used as Operational Evidence")
                    md.append("")
                    for source in excluded:
                        title = source.get("title") or source.get("domain") or "Unknown source"
                        url = source.get("url") or ""
                        purpose = str(source.get("purpose") or "unknown").replace("_", " ")
                        md.append(f"**{title}**")
                        if url:
                            md.append(f"- **URL**: [{url}]({url})")
                        md.append(f"- **Disposition**: {purpose.title()}")
                        md.append(f"- **Reason**: {source.get('reason') or 'Not recorded'}")
                        md.append("")

            # Data Quality Assessment
            freshness = web_sources.get("dataFreshness", "")
            reliability = web_sources.get("sourceReliability", "")
            if freshness or reliability:
                md.append("### Data Quality Assessment")
                md.append("")
                if freshness:
                    md.append(f"**Data Freshness**: {freshness}")
                if reliability:
                    md.append(f"**Source Reliability**: {reliability}")
                md.append("")

        # [Continue with all other existing sections...]

        # Tool Overview
        logger.debug("Starting tool overview section...")
        overview = data.get("toolOverview", {})
        if isinstance(overview, dict):
            md.append("## Tool Overview")
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
        logger.debug("Starting technical details section...")
        technical = data.get("technicalDetails", {})
        if isinstance(technical, dict):
            md.append("## Technical Details")
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
        logger.debug("Starting C2 section...")
        c2 = data.get("commandAndControl", {})
        if isinstance(c2, dict):
            md.append("## Command and Control")
            md.append("")

            md.append(f"**Communication Methods**: {c2.get('communicationMethods', 'Unknown')}")
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
                        md.append(
                            f"- **Detection Notes**: {protocol.get('detectionNotes', 'None')}"
                        )
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
                        indicators = pattern.get("indicators", [])
                        if indicators:
                            # Handle both string and dict indicators
                            indicator_strings = []
                            for indicator in indicators:
                                if isinstance(indicator, dict):
                                    # Extract meaningful string representation from dict
                                    if "value" in indicator:
                                        indicator_strings.append(indicator["value"])
                                    elif "indicator" in indicator:
                                        indicator_strings.append(indicator["indicator"])
                                    elif "name" in indicator:
                                        indicator_strings.append(indicator["name"])
                                    else:
                                        # Fallback to first string value found
                                        for v in indicator.values():
                                            if isinstance(v, str):
                                                indicator_strings.append(v)
                                                break
                                else:
                                    indicator_strings.append(str(indicator))
                            if indicator_strings:
                                md.append(f"- **Indicators**: {', '.join(indicator_strings)}")
                        md.append("")

        # Threat Intelligence
        logger.debug("Starting threat intelligence section...")
        threat_intel = data.get("threatIntelligence", {})
        if isinstance(threat_intel, dict):
            md.append("## Threat Intelligence")
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

                risk_factors = risk.get("riskFactors", [])
                if risk_factors and isinstance(risk_factors, list):
                    md.append("**Risk Factors**:")
                    for factor in risk_factors:
                        md.append(f"- {factor}")
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
                            md.append(
                                f"- **Activity Timeframe**: {actor.get('activityTimeframe', 'Unknown')}"
                            )
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
                            sectors = campaign.get("targetSectors", [])
                            if sectors:
                                md.append(f"- **Target Sectors**: {', '.join(sectors)}")
                            md.append(
                                f"- **Geographic Focus**: {campaign.get('geographicFocus', 'Unknown')}"
                            )
                            md.append("")

        # Forensic Artifacts
        logger.debug("Starting forensic artifacts section...")
        forensics = data.get("forensicArtifacts", {})
        if isinstance(forensics, dict):
            md.append("## Forensic Artifacts")
            md.append("")

            artifact_types = [
                ("fileSystemArtifacts", "File System Artifacts"),
                ("registryArtifacts", "Registry Artifacts"),
                ("networkArtifacts", "Network Artifacts"),
                ("memoryArtifacts", "Memory Artifacts"),
                ("logArtifacts", "Log Artifacts"),
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
        logger.debug("Starting detection section...")
        detection = data.get("detectionAndMitigation", {})
        if isinstance(detection, dict):
            md.append("## Detection and Mitigation")
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
                    ("filenames", "Malicious Filenames"),
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
        logger.debug("Processing remaining sections...")

        # Mitigation and Response
        mitigation = data.get("mitigationAndResponse", {})
        if isinstance(mitigation, dict):
            md.append("## Mitigation and Response")
            md.append("")

            section_types = [
                ("preventiveMeasures", "Preventive Measures"),
                ("detectionMethods", "Detection Methods"),
                ("responseActions", "Response Actions"),
                ("recoveryGuidance", "Recovery Guidance"),
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
            md.append("## References and Intelligence Sharing")
            md.append("")

            sources = references.get("sources", [])
            if sources and isinstance(sources, list):
                md.append("### Sources")
                md.append("")
                for source in sources:
                    if isinstance(source, dict):
                        title = source.get("title", "Unknown Source")
                        url = source.get("url", "")
                        date = source.get("date", "")
                        relevance = source.get("relevanceScore", "")

                        if url:
                            md.append(f"- [{title}]({url}) - {date} (Relevance: {relevance})")
                        else:
                            md.append(f"- {title} - {date} (Relevance: {relevance})")
                md.append("")

            mitre = references.get("mitreAttackMapping", "")
            if mitre:
                md.append(f"**MITRE ATT&CK Mapping**: {mitre}")
                md.append("")

            cves = references.get("cveReferences", "")
            if cves:
                md.append(f"**CVE References**: {cves}")
                md.append("")

        # Integration
        integration = data.get("integration", {})
        if isinstance(integration, dict):
            md.append("## Integration Guidance")
            md.append("")
            md.append(
                f"**SIEM Integration**: {integration.get('siemIntegration', 'No guidance available')}"
            )
            md.append("")

            hunting_queries = integration.get("threatHuntingQueries", [])
            if hunting_queries and isinstance(hunting_queries, list):
                md.append("**Threat Hunting Queries**:")
                for query in hunting_queries:
                    md.append(f"- `{query}`")
                md.append("")

            md.append(
                f"**Automated Response**: {integration.get('automatedResponse', 'No guidance available')}"
            )
            md.append("")

        # Lineage
        lineage = data.get("lineage", {})
        if isinstance(lineage, dict):
            md.append("## Tool Lineage")
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
            md.append("## Contextual Analysis")
            md.append("")

            usage = context.get("usageContexts", {})
            if isinstance(usage, dict):
                md.append("### Usage Contexts")
                md.append("")
                md.append(f"**Legitimate Use**: {usage.get('legitimateUse', 'None identified')}")
                md.append("")
                md.append(f"**Malicious Use**: {usage.get('maliciousUse', 'Unknown')}")
                md.append("")
                md.append(
                    f"**Dual-Use Considerations**: {usage.get('dualUseConsiderations', 'None')}"
                )
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
            md.append("## Operational Guidance")
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
                        name = resource.get("name", "Unknown Resource")
                        url = resource.get("url", "")
                        resource_type = resource.get("resourceType", "Unknown")
                        focus = resource.get("focus", "")

                        if url:
                            md.append(f"- **{name}** ({resource_type}) - [{url}]({url}) - {focus}")
                        else:
                            md.append(f"- **{name}** ({resource_type}) - {focus}")
                md.append("")

        # Quality Assessment Section
        if "_quality_assessment" in data:
            quality = data["_quality_assessment"]
            md.extend(render_quality_assessment(quality).splitlines())
            md.append("")

        # NEW: Comprehensive Web Search Sources Section
        logger.debug("Starting comprehensive sources section...")
        comprehensive_sources = data.get("comprehensiveWebSearchSources", {})
        if isinstance(comprehensive_sources, dict) and comprehensive_sources.get("enabled", False):
            sources_analysis = comprehensive_sources.get("comprehensiveSourceAnalysis", {})

            md.append("## Comprehensive Web Search Sources Analysis")
            md.append("")

            # Overview
            overview = sources_analysis.get("overview", {})
            if overview:
                md.append("### Research Overview")
                md.append("")
                md.append(
                    f"**Description**: {overview.get('description', 'No description available')}"
                )
                md.append("")
                md.append(
                    f"**Methodology**: {overview.get('methodology', 'Standard web search methodology')}"
                )
                md.append("")
                md.append(f"**Time Range**: {overview.get('timeRange', 'Unknown')}")
                md.append("")
                md.append(
                    f"**Quality Assessment**: {overview.get('qualityAssessment', 'Not assessed')}"
                )
                md.append("")

            # Statistics
            stats = sources_analysis.get("statistics", {})
            if stats:
                md.append("### Source Statistics")
                md.append("")
                md.append("| Metric | Value |")
                md.append("|--------|-------|")
                md.append(f"| **Total Unique Sources** | {stats.get('totalSources', 0)} |")
                md.append(f"| **Unique Domains** | {stats.get('uniqueDomains', 0)} |")

                timeline_coverage = stats.get("timelineCoverage", {})
                if timeline_coverage:
                    md.append(f"| **Years Spanned** | {timeline_coverage.get('yearsSpanned', 0)} |")

                # Top domains
                top_domains = stats.get("topDomains", [])
                if top_domains:
                    domain_list = ", ".join(
                        [f"{d['domain']} ({d['count']})" for d in top_domains[:5]]
                    )
                    md.append(f"| **Top Domains** | {domain_list} |")

                md.append("")

            # Content type breakdown
            content_type_breakdown = stats.get("contentTypeBreakdown", {})
            if content_type_breakdown:
                md.append("### Sources by Content Type")
                md.append("")
                for content_type, count in sorted(
                    content_type_breakdown.items(), key=lambda x: x[1], reverse=True
                ):
                    md.append(f"- **{content_type}**: {count} sources")
                md.append("")

            # Chronological timeline (most recent years first)
            chronological_timeline = sources_analysis.get("chronologicalTimeline", {})
            if chronological_timeline:
                md.append("### Chronological Timeline")
                md.append("")
                for year, sources in sorted(chronological_timeline.items(), reverse=True):
                    if year != "unknown" and sources:
                        md.append(f"#### {year} ({len(sources)} sources)")
                        md.append("")
                        for source in sources[:10]:  # Limit to top 10 per year
                            title = source.get("title", "Unknown Title")
                            url = source.get("url", "")
                            domain = source.get("domain", "unknown")
                            pub_date = source.get("publishedDate", "unknown")
                            content_type = source.get("contentType", "Unknown")

                            if url:
                                md.append(
                                    f"- **[{title}]({url})** ({domain}) - *{content_type}* - {pub_date}"
                                )
                            else:
                                md.append(
                                    f"- **{title}** ({domain}) - *{content_type}* - {pub_date}"
                                )

                        if len(sources) > 10:
                            md.append(f"- ... and {len(sources) - 10} more sources from {year}")
                        md.append("")

                # Handle unknown date sources
                if "unknown" in chronological_timeline and chronological_timeline["unknown"]:
                    unknown_sources = chronological_timeline["unknown"]
                    md.append(f"#### Undated Sources ({len(unknown_sources)} sources)")
                    md.append("")
                    for source in unknown_sources[:5]:  # Limit to top 5 undated
                        title = source.get("title", "Unknown Title")
                        url = source.get("url", "")
                        domain = source.get("domain", "unknown")
                        content_type = source.get("contentType", "Unknown")

                        if url:
                            md.append(f"- **[{title}]({url})** ({domain}) - *{content_type}*")
                        else:
                            md.append(f"- **{title}** ({domain}) - *{content_type}*")

                    if len(unknown_sources) > 5:
                        md.append(f"- ... and {len(unknown_sources) - 5} more undated sources")
                    md.append("")

            # Research notes
            research_notes = sources_analysis.get("researchNotes", {})
            if research_notes:
                md.append("### Research Notes")
                md.append("")
                for key, value in research_notes.items():
                    formatted_key = key.replace("_", " ").title()
                    md.append(f"**{formatted_key}**: {value}")
                    md.append("")

            # Metadata
            generated_at = comprehensive_sources.get("generatedAt", "Unknown")
            capture_method = comprehensive_sources.get("captureMethod", "Unknown")
            md.append("### Source Collection Metadata")
            md.append("")
            md.append(f"**Generated At**: {generated_at}")
            md.append("")
            md.append(f"**Collection Method**: {capture_method}")
            md.append("")

        logger.debug("Completed all sections successfully")
        return "\n".join(md)

    except Exception as e:
        logger.exception("Markdown generation failed: %s", e)
        return (
            "# Error in Markdown Generation\n\n"
            "The report could not be rendered. Please retry generation."
        )
