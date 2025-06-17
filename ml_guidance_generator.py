"""
ML Guidance Generator for SentrySearch

Generates markdown-formatted ML guidance sections that integrate seamlessly
with SentrySearch's existing threat intelligence reports.

Features:
- Structured ML approach recommendations
- Company case study formatting
- Source attribution and citations
- Implementation feasibility scoring
- Actionable detection guidance
"""

import os
import time
import random
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging
from datetime import datetime

from pydantic import BaseModel, Field, validator
from ml_agentic_retriever import MLAgenticRetriever, ThreatCharacteristics
from anthropic import Anthropic
import anthropic

logger = logging.getLogger(__name__)


class MLApproach(BaseModel):
    """Structured ML approach with validated fields"""
    technique: str = Field(default="", description="ML technique name")
    source_company: str = Field(default="", description="Company that implemented this approach")
    description: str = Field(default="", description="Description of the approach")
    source_paper: str = Field(default="", description="Source paper or publication")
    applicability_score: float = Field(default=0.5, ge=0.0, le=1.0, description="Applicability score")
    
    @validator('technique', 'source_company', 'description', 'source_paper', pre=True)
    def ensure_string(cls, v):
        """Ensure all string fields are actually strings"""
        if isinstance(v, dict):
            return str(v.get('name', '')) if v else ''
        return str(v) if v else ''


class SourcePaper(BaseModel):
    """Source paper with validated fields"""
    title: str = Field(default="Unknown")
    company: str = Field(default="Unknown") 
    year: str = Field(default="Unknown")
    url: str = Field(default="")
    techniques: List[str] = Field(default_factory=list)


class ImplementationConsideration(BaseModel):
    """Implementation consideration with validated fields"""
    aspect: str = Field(default="Implementation")
    details: str = Field(default="")
    source: str = Field(default="")


class MLGuidanceData(BaseModel):
    """Complete ML guidance data structure"""
    threat_name: str = Field(default="")
    ml_approaches: List[MLApproach] = Field(default_factory=list)
    source_papers: List[SourcePaper] = Field(default_factory=list)
    implementation_considerations: List[ImplementationConsideration] = Field(default_factory=list)


@dataclass
class MLGuidanceSection:
    """Represents a structured ML guidance section"""
    title: str
    content: str
    implementation_complexity: str  # "Low", "Medium", "High"
    data_requirements: List[str]
    expected_accuracy: str
    deployment_timeframe: str
    source_attribution: str


class MLGuidanceGenerator:
    """Generates comprehensive ML guidance in markdown format"""
    
    def __init__(self, anthropic_client, knowledge_base_path: str = "./ml_knowledge_base"):
        self.client = anthropic_client
        self.ml_retriever = MLAgenticRetriever(anthropic_client, knowledge_base_path)
        logger.info("ML Guidance Generator initialized")
    
    def _api_call_with_retry(self, **kwargs):
        """Make API call with intelligent retry logic using retry-after header"""
        max_retries = 3
        base_delay = 5
        
        for attempt in range(max_retries):
            try:
                print(f"DEBUG: ML Guidance API call attempt {attempt + 1}/{max_retries}")
                return self.client.messages.create(**kwargs)
                
            except anthropic.RateLimitError as e:
                if attempt == max_retries - 1:
                    print(f"DEBUG: ML Guidance rate limit exceeded after {max_retries} attempts")
                    raise e
                
                # Check if the error response has retry-after information
                retry_after = None
                if hasattr(e, 'response') and e.response:
                    retry_after_header = e.response.headers.get('retry-after')
                    if retry_after_header:
                        try:
                            retry_after = float(retry_after_header)
                            print(f"DEBUG: ML Guidance API provided retry-after: {retry_after} seconds")
                        except (ValueError, TypeError):
                            pass
                
                # Use retry-after if available, otherwise exponential backoff
                if retry_after:
                    delay = retry_after + random.uniform(1, 3)
                else:
                    delay = base_delay * (2 ** attempt) + random.uniform(1, 5)
                    delay = min(delay, 120)
                
                print(f"DEBUG: ML Guidance rate limit hit. Waiting {delay:.1f} seconds before retry {attempt + 2}")
                time.sleep(delay)
                
            except Exception as e:
                print(f"DEBUG: ML Guidance non-rate-limit error: {e}")
                raise e
    
    def generate_enhanced_ml_guidance_section(self, threat_characteristics: ThreatCharacteristics, 
                                            complete_threat_data: Dict) -> str:
        """Generate enhanced ML guidance leveraging all threat intelligence context"""
        
        try:
            # Get ML guidance from agentic retriever with enhanced context
            ml_guidance_raw = self.ml_retriever.get_enhanced_ml_guidance(
                threat_characteristics, complete_threat_data
            )
            
            if not ml_guidance_raw or 'error' in ml_guidance_raw:
                return self._generate_enhanced_fallback_section(threat_characteristics, complete_threat_data)
            
            # Parse into Pydantic model for type safety
            ml_guidance = MLGuidanceData(**ml_guidance_raw)
            
            # Generate enhanced structured sections with full context
            sections = self._create_enhanced_guidance_sections(
                ml_guidance, threat_characteristics, complete_threat_data
            )
            
            # Format as enhanced markdown with threat context
            markdown = self._format_enhanced_markdown(sections, ml_guidance, complete_threat_data)
            
            return markdown
            
        except Exception as e:
            logger.error(f"Enhanced ML guidance generation failed: {e}")
            return self._generate_enhanced_fallback_section(threat_characteristics, complete_threat_data)
    
    def generate_ml_guidance_section(self, threat_characteristics: ThreatCharacteristics) -> str:
        """Generate complete ML guidance section in markdown format (legacy method)"""
        
        try:
            # Get ML guidance from agentic retriever
            ml_guidance_raw = self.ml_retriever.get_ml_guidance(threat_characteristics)
            
            if not ml_guidance_raw or 'error' in ml_guidance_raw:
                return self._generate_fallback_section(threat_characteristics)
            
            # Parse into Pydantic model for type safety
            ml_guidance = MLGuidanceData(**ml_guidance_raw)
            
            # Generate structured sections
            sections = self._create_guidance_sections(ml_guidance, threat_characteristics)
            
            # Format as markdown
            markdown = self._format_as_markdown(sections, ml_guidance)
            
            return markdown
            
        except Exception as e:
            logger.error(f"ML guidance generation failed: {e}")
            return self._generate_fallback_section(threat_characteristics)
    
    def _create_guidance_sections(self, ml_guidance: MLGuidanceData, 
                                threat_characteristics: ThreatCharacteristics) -> List[MLGuidanceSection]:
        """Create structured guidance sections from ML retrieval results"""
        
        sections = []
        
        # Group ML approaches by implementation complexity
        approaches_by_complexity = {
            "Low": [],
            "Medium": [],
            "High": []
        }
        
        for approach in ml_guidance.ml_approaches:
            complexity = self._assess_implementation_complexity(approach)
            approaches_by_complexity[complexity].append(approach)
        
        # Create sections for each complexity level
        for complexity in ["Low", "Medium", "High"]:
            approaches = approaches_by_complexity[complexity]
            if approaches:
                section = self._create_complexity_section(
                    complexity, approaches, threat_characteristics
                )
                sections.append(section)
        
        # Add implementation considerations section
        if ml_guidance.implementation_considerations:
            impl_section = self._create_implementation_section(ml_guidance)
            sections.append(impl_section)
        
        return sections
    
    def _assess_implementation_complexity(self, approach: MLApproach) -> str:
        """Assess implementation complexity based on technique and requirements"""
        
        # With Pydantic, we're guaranteed to have strings
        technique = approach.technique.lower()
        company = approach.source_company.lower()
        
        # Simple techniques - Low complexity
        simple_techniques = [
            'statistical_analysis', 'anomaly_detection', 'threshold_based',
            'rule_based', 'clustering'
        ]
        
        # Moderate techniques - Medium complexity  
        moderate_techniques = [
            'isolation_forest', 'behavioral_analysis', 'unsupervised_learning',
            'supervised_learning', 'ensemble_methods'
        ]
        
        # Advanced techniques - High complexity
        advanced_techniques = [
            'deep_learning', 'neural_networks', 'graph_ml', 'nlp',
            'computer_vision', 'reinforcement_learning'
        ]
        
        if any(tech in technique for tech in simple_techniques):
            return "Low"
        elif any(tech in technique for tech in moderate_techniques):
            return "Medium"
        elif any(tech in technique for tech in advanced_techniques):
            return "High"
        else:
            return "Medium"
    
    def _create_complexity_section(self, complexity: str, approaches: List[MLApproach],
                                 threat_characteristics: ThreatCharacteristics) -> MLGuidanceSection:
        """Create a section for approaches of specific complexity"""
        
        # Generate detailed content for this complexity level
        content = self._generate_section_content(approaches, threat_characteristics, complexity)
        
        # Determine data requirements
        data_requirements = self._extract_data_requirements(approaches)
        
        # Estimate accuracy and timeframe
        expected_accuracy = self._estimate_accuracy(approaches, complexity)
        deployment_timeframe = self._estimate_deployment_time(complexity)
        
        # Create source attribution
        source_attribution = self._create_source_attribution(approaches)
        
        return MLGuidanceSection(
            title=f"{complexity} Complexity Approaches",
            content=content,
            implementation_complexity=complexity,
            data_requirements=data_requirements,
            expected_accuracy=expected_accuracy,
            deployment_timeframe=deployment_timeframe,
            source_attribution=source_attribution
        )
    
    def _generate_section_content(self, approaches: List[MLApproach], 
                                threat_characteristics: ThreatCharacteristics,
                                complexity: str) -> str:
        """Generate detailed content for a complexity section"""
        
        if not approaches:
            return ""
        
        # Use LLM to synthesize approaches into coherent guidance
        prompt = f"""
Create a comprehensive yet concise detection guidance section for {complexity.lower()} complexity ML approaches.

Threat Context:
- Name: {threat_characteristics.threat_name}
- Type: {threat_characteristics.threat_type}
- Attack Vectors: {', '.join(threat_characteristics.attack_vectors)}
- Behavior Patterns: {', '.join(threat_characteristics.behavior_patterns)}

Available ML Approaches:
{self._format_approaches_for_prompt(approaches)}

Create guidance that includes:
1. Brief overview of the recommended approach(es)
2. Specific implementation steps
3. Key features/signals to monitor
4. Expected detection capabilities
5. Deployment considerations

Keep it practical and actionable. Focus on what security teams can actually implement.
Write in clear, professional language suitable for cybersecurity professionals.
"""
        
        try:
            response = self._api_call_with_retry(
                model="claude-sonnet-4-20250514",
                max_tokens=800,
                messages=[{"role": "user", "content": prompt}]
            )
            
            if response.content and len(response.content) > 0 and hasattr(response.content[0], 'text'):
                return response.content[0].text.strip()
            else:
                logger.warning("Empty or invalid response content from Anthropic API")
                return ""
            
        except Exception as e:
            logger.error(f"Content generation failed: {e}")
            return self._create_fallback_content(approaches, complexity)
    
    def _format_approaches_for_prompt(self, approaches: List[MLApproach]) -> str:
        """Format approaches for LLM prompt"""
        
        formatted = []
        for approach in approaches:
            formatted.append(
                f"- {approach.technique} ({approach.source_company}): "
                f"{approach.description or 'No description available'}"
            )
        
        return '\n'.join(formatted)
    
    def _create_fallback_content(self, approaches: List[MLApproach], complexity: str) -> str:
        """Create fallback content when LLM generation fails"""
        
        if not approaches:
            return f"No {complexity.lower()} complexity approaches available."
        
        content = f"**{complexity} Complexity ML Detection Approaches:**\n\n"
        
        for approach in approaches:
            content += f"**{approach.technique.title()}** "
            content += f"(Source: {approach.source_company})\n"
            content += f"{approach.description or 'Implementation details from industry case study.'}\n\n"
        
        return content
    
    def _extract_data_requirements(self, approaches: List[MLApproach]) -> List[str]:
        """Extract data requirements from approaches"""
        
        requirements = set()
        
        for approach in approaches:
            technique = approach.technique.lower()
            
            # Map techniques to data requirements
            if 'network' in technique or 'traffic' in technique:
                requirements.add("Network traffic logs")
            if 'behavioral' in technique or 'user' in technique:
                requirements.add("User activity logs")
            if 'system' in technique or 'host' in technique:
                requirements.add("System/host logs")
            if 'email' in technique or 'content' in technique:
                requirements.add("Email/content data")
            if 'financial' in technique or 'transaction' in technique:
                requirements.add("Transaction data")
            
            # Default requirements
            requirements.add("Historical baseline data")
            requirements.add("Labeled training examples")
        
        return list(requirements)
    
    def _estimate_accuracy(self, approaches: List[MLApproach], complexity: str) -> str:
        """Estimate detection accuracy based on approaches and complexity"""
        
        if not approaches:
            return "Unknown"
        
        # Base accuracy on complexity and approach quality
        avg_applicability = sum(approach.applicability_score for approach in approaches) / len(approaches)
        
        if complexity == "Low":
            base_accuracy = "70-85%"
        elif complexity == "Medium":  
            base_accuracy = "80-90%"
        else:  # High
            base_accuracy = "85-95%"
        
        # Adjust based on applicability scores
        if avg_applicability < 0.3:
            return f"{base_accuracy} (limited applicability)"
        elif avg_applicability > 0.7:
            return f"{base_accuracy} (high applicability)"
        else:
            return base_accuracy
    
    def _estimate_deployment_time(self, complexity: str) -> str:
        """Estimate deployment timeframe based on complexity"""
        
        timeframes = {
            "Low": "1-2 weeks",
            "Medium": "1-2 months", 
            "High": "3-6 months"
        }
        
        return timeframes.get(complexity, "Unknown")
    
    def _create_source_attribution(self, approaches: List[MLApproach]) -> str:
        """Create source attribution for approaches"""
        
        sources = []
        seen_papers = set()
        
        for approach in approaches:
            paper = approach.source_paper
            company = approach.source_company
            
            if paper and paper not in seen_papers:
                seen_papers.add(paper)
                sources.append(f"{company}: {paper}")
        
        return '; '.join(sources[:3])  # Limit to top 3 sources
    
    def _create_implementation_section(self, ml_guidance: MLGuidanceData) -> MLGuidanceSection:
        """Create implementation considerations section"""
        
        considerations = ml_guidance.implementation_considerations
        
        content = "**Key Implementation Considerations:**\n\n"
        
        for consideration in considerations[:3]:  # Top 3 considerations
            content += f"**{consideration.aspect}:** {consideration.details}"
            if consideration.source:
                content += f" (Source: {consideration.source})"
            content += "\n\n"
        
        return MLGuidanceSection(
            title="Implementation Considerations",
            content=content,
            implementation_complexity="Various",
            data_requirements=["Infrastructure assessment", "Data pipeline setup"],
            expected_accuracy="Depends on implementation quality",
            deployment_timeframe="Ongoing",
            source_attribution="; ".join([c.source for c in considerations[:3] if c.source])
        )
    
    def _format_as_markdown(self, sections: List[MLGuidanceSection], 
                          ml_guidance: MLGuidanceData) -> str:
        """Format guidance sections as markdown"""
        
        markdown = "## 🤖 ML-Based Anomaly Detection Approaches\n\n"
        
        # Add overview
        threat_name = ml_guidance.threat_name or 'this threat'
        num_approaches = len(ml_guidance.ml_approaches)
        num_papers = len(ml_guidance.source_papers)
        
        markdown += f"Based on analysis of {num_papers} industry implementations, "
        markdown += f"we identified {num_approaches} relevant ML approaches for detecting {threat_name}. "
        markdown += "These recommendations are derived from production deployments at leading technology companies.\n\n"
        
        # Add sections
        for section in sections:
            markdown += f"### {section.title}\n\n"
            markdown += f"{section.content}\n\n"
            
            # Add metadata table
            markdown += "| Metric | Value |\n"
            markdown += "|--------|-------|\n"
            markdown += f"| Implementation Complexity | {section.implementation_complexity} |\n"
            markdown += f"| Expected Accuracy | {section.expected_accuracy} |\n"
            markdown += f"| Deployment Timeframe | {section.deployment_timeframe} |\n"
            markdown += f"| Data Requirements | {', '.join(section.data_requirements[:3])} |\n\n"
        
        # Add source papers section
        if ml_guidance.source_papers:
            markdown += "### 📚 Source Papers & Case Studies\n\n"
            markdown += "The following industry implementations informed these recommendations:\n\n"
            
            for paper in ml_guidance.source_papers[:5]:  # Top 5 papers
                markdown += f"**{paper.company} ({paper.year})**: {paper.title}\n"
                if paper.techniques:
                    markdown += f"*Techniques*: {', '.join(paper.techniques[:3])}\n"
                if paper.url:
                    markdown += f"*Source*: [Link]({paper.url})\n"
                markdown += "\n"
        
        # Add implementation priority
        markdown += "### 🎯 Implementation Priority\n\n"
        markdown += "**Recommended Implementation Order:**\n"
        markdown += "1. **Start with Low Complexity approaches** for immediate detection capabilities\n"
        markdown += "2. **Enhance with Medium Complexity methods** for improved accuracy\n"
        markdown += "3. **Consider High Complexity solutions** for advanced threat detection\n\n"
        
        # Add disclaimer
        markdown += "---\n"
        markdown += "*ML detection recommendations are based on publicly available industry implementations. "
        markdown += "Effectiveness may vary depending on your specific environment, data quality, and threat landscape.*\n\n"
        
        return markdown
    
    def _create_enhanced_guidance_sections(self, ml_guidance: MLGuidanceData, 
                                         threat_characteristics: ThreatCharacteristics,
                                         complete_threat_data: Dict) -> List[MLGuidanceSection]:
        """Create enhanced guidance sections leveraging complete threat context"""
        
        sections = []
        
        # Group ML approaches by implementation complexity
        approaches_by_complexity = {
            "Low": [],
            "Medium": [],
            "High": []
        }
        
        for approach in ml_guidance.ml_approaches:
            complexity = self._assess_implementation_complexity(approach)
            approaches_by_complexity[complexity].append(approach)
        
        # Create enhanced sections for each complexity level
        for complexity in ["Low", "Medium", "High"]:
            approaches = approaches_by_complexity[complexity]
            if approaches:
                section = self._create_enhanced_complexity_section(
                    complexity, approaches, threat_characteristics, complete_threat_data
                )
                sections.append(section)
        
        # Add implementation considerations section with threat context
        if ml_guidance.implementation_considerations:
            impl_section = self._create_enhanced_implementation_section(
                ml_guidance, complete_threat_data
            )
            sections.append(impl_section)
        
        return sections
    
    def _create_enhanced_complexity_section(self, complexity: str, approaches: List[MLApproach],
                                          threat_characteristics: ThreatCharacteristics,
                                          complete_threat_data: Dict) -> MLGuidanceSection:
        """Create an enhanced section for approaches leveraging full threat context"""
        
        # Generate enhanced content with threat context
        content = self._generate_enhanced_section_content(
            approaches, threat_characteristics, complexity, complete_threat_data
        )
        
        # Extract enhanced data requirements from threat context
        data_requirements = self._extract_enhanced_data_requirements(approaches, complete_threat_data)
        
        # Estimate accuracy with threat context
        expected_accuracy = self._estimate_enhanced_accuracy(approaches, complexity, complete_threat_data)
        deployment_timeframe = self._estimate_deployment_time(complexity)
        
        # Create source attribution
        source_attribution = self._create_source_attribution(approaches)
        
        return MLGuidanceSection(
            title=f"{complexity} Complexity Approaches",
            content=content,
            implementation_complexity=complexity,
            data_requirements=data_requirements,
            expected_accuracy=expected_accuracy,
            deployment_timeframe=deployment_timeframe,
            source_attribution=source_attribution
        )
    
    def _generate_enhanced_section_content(self, approaches: List[MLApproach], 
                                         threat_characteristics: ThreatCharacteristics,
                                         complexity: str,
                                         complete_threat_data: Dict) -> str:
        """Generate enhanced content leveraging complete threat intelligence context"""
        
        if not approaches:
            return ""
        
        # Extract key context from completed sections
        context_summary = self._extract_threat_context_summary(complete_threat_data)
        
        # Use LLM to synthesize approaches with full threat context
        prompt = f"""
Create comprehensive ML detection guidance for {complexity.lower()} complexity approaches, specifically tailored to this threat.

Threat Context from Completed Intelligence Profile:
- Name: {threat_characteristics.threat_name}
- Type: {threat_characteristics.threat_type}
- Attack Vectors: {', '.join(threat_characteristics.attack_vectors)}
- Behavior Patterns: {', '.join(threat_characteristics.behavior_patterns)}

Additional Threat Context:
{context_summary}

Available ML Approaches:
{self._format_approaches_for_prompt(approaches)}

Create guidance that:
1. Specifically addresses the identified attack vectors and behavior patterns
2. Leverages the technical details and C2 methods identified
3. Incorporates the IOCs and forensic artifacts for training data
4. Provides implementation steps tailored to this threat type
5. Explains how each approach detects the specific threat behaviors
6. References the threat's specific characteristics throughout

Focus on practical implementation that directly counters this threat's specific TTPs.
Write for cybersecurity practitioners who need actionable, threat-specific guidance.
"""
        
        try:
            response = self._api_call_with_retry(
                model="claude-sonnet-4-20250514",
                max_tokens=1200,
                messages=[{"role": "user", "content": prompt}]
            )
            
            if response.content and len(response.content) > 0 and hasattr(response.content[0], 'text'):
                return response.content[0].text.strip()
            else:
                logger.warning("Empty or invalid response content from Anthropic API")
                return ""
            
        except Exception as e:
            logger.error(f"Enhanced content generation failed: {e}")
            return self._create_fallback_content(approaches, complexity)
    
    def _extract_threat_context_summary(self, complete_threat_data: Dict) -> str:
        """Extract a summary of key threat context from all sections"""
        
        context_parts = []
        
        # Technical details
        if tech_details := complete_threat_data.get('technicalDetails'):
            if capabilities := tech_details.get('capabilities'):
                # Ensure capabilities is a list before slicing
                if isinstance(capabilities, list):
                    cap_names = [cap.get('name', str(cap)) if isinstance(cap, dict) else str(cap) 
                               for cap in capabilities[:3]]
                    context_parts.append(f"Key Capabilities: {', '.join(cap_names)}")
        
        # C2 methods
        if c2_data := complete_threat_data.get('commandAndControl'):
            if methods := c2_data.get('communicationMethods'):
                # Ensure methods is a list before slicing
                if isinstance(methods, list):
                    method_names = [method.get('protocol', str(method)) if isinstance(method, dict) else str(method) 
                                  for method in methods[:2]]
                    context_parts.append(f"C2 Protocols: {', '.join(method_names)}")
        
        # Detection indicators
        if detection_data := complete_threat_data.get('detectionAndMitigation'):
            if iocs := detection_data.get('iocs'):
                # Ensure iocs is a list before slicing
                if isinstance(iocs, list):
                    ioc_types = list(set([ioc.get('type', 'unknown') if isinstance(ioc, dict) else 'unknown' 
                                        for ioc in iocs[:5]]))
                    context_parts.append(f"Available IOC Types: {', '.join(ioc_types)}")
        
        # Forensic artifacts  
        if forensic_data := complete_threat_data.get('forensicArtifacts'):
            artifact_types = []
            if forensic_data.get('fileSystemArtifacts'):
                artifact_types.append('filesystem')
            if forensic_data.get('registryArtifacts'):
                artifact_types.append('registry')
            if forensic_data.get('networkArtifacts'):
                artifact_types.append('network')
            if artifact_types:
                context_parts.append(f"Forensic Evidence Types: {', '.join(artifact_types)}")
        
        return '\n'.join(context_parts) if context_parts else "Limited threat context available."
    
    def _extract_enhanced_data_requirements(self, approaches: List[MLApproach], 
                                          complete_threat_data: Dict) -> List[str]:
        """Extract enhanced data requirements based on threat context and approaches"""
        
        requirements = self._extract_data_requirements(approaches)
        
        # Add specific requirements based on threat context
        if complete_threat_data.get('technicalDetails', {}).get('operatingSystems'):
            requirements.append("OS-specific logs")
        
        if complete_threat_data.get('commandAndControl', {}).get('communicationMethods'):
            requirements.append("C2 communication logs")
        
        if complete_threat_data.get('detectionAndMitigation', {}).get('iocs'):
            requirements.append("IOC correlation data")
        
        if complete_threat_data.get('forensicArtifacts'):
            requirements.append("Forensic artifact baselines")
        
        return list(set(requirements))
    
    def _estimate_enhanced_accuracy(self, approaches: List[MLApproach], complexity: str,
                                  complete_threat_data: Dict) -> str:
        """Estimate accuracy considering threat-specific factors"""
        
        base_accuracy = self._estimate_accuracy(approaches, complexity)
        
        # Adjust based on available threat intelligence quality
        quality_factors = 0
        
        if complete_threat_data.get('detectionAndMitigation', {}).get('iocs'):
            quality_factors += 1
        if complete_threat_data.get('forensicArtifacts'):
            quality_factors += 1
        if complete_threat_data.get('commandAndControl', {}).get('communicationMethods'):
            quality_factors += 1
        
        if quality_factors >= 2:
            return f"{base_accuracy} (enhanced with threat context)"
        elif quality_factors == 1:
            return f"{base_accuracy} (some threat context)"
        else:
            return f"{base_accuracy} (limited threat context)"
    
    def _create_enhanced_implementation_section(self, ml_guidance: MLGuidanceData,
                                              complete_threat_data: Dict) -> MLGuidanceSection:
        """Create enhanced implementation considerations with threat context"""
        
        considerations = ml_guidance.implementation_considerations
        
        content = "**Threat-Specific Implementation Considerations:**\n\n"
        
        # Add threat-specific considerations first
        if complete_threat_data.get('technicalDetails', {}).get('operatingSystems'):
            os_list = complete_threat_data['technicalDetails']['operatingSystems']
            # Ensure os_list is a list before slicing
            if isinstance(os_list, list):
                os_names = [os.get('name', str(os)) if isinstance(os, dict) else str(os) for os in os_list[:2]]
                content += f"**Target OS Compatibility:** Ensure detection models are trained on {', '.join(os_names)} environments.\n\n"
        
        # Add original considerations
        if isinstance(considerations, list):
            for consideration in considerations[:2]:  # Top 2 considerations
                content += f"**{consideration.aspect}:** {consideration.details}"
                if consideration.source:
                    content += f" (Source: {consideration.source})"
                content += "\n\n"
        
        return MLGuidanceSection(
            title="Implementation Considerations",
            content=content,
            implementation_complexity="Various",
            data_requirements=["Infrastructure assessment", "Threat-specific data pipeline"],
            expected_accuracy="Depends on threat-specific implementation",
            deployment_timeframe="Ongoing",
            source_attribution="; ".join([c.source for c in (considerations[:2] if isinstance(considerations, list) else []) if c.source])
        )
    
    def _format_enhanced_markdown(self, sections: List[MLGuidanceSection], 
                                ml_guidance: MLGuidanceData,
                                complete_threat_data: Dict) -> str:
        """Format enhanced guidance sections as markdown with threat context"""
        
        markdown = "## 🤖 ML-Based Anomaly Detection Approaches\n\n"
        
        # Add enhanced overview with threat context
        threat_name = ml_guidance.threat_name or 'this threat'
        num_approaches = len(ml_guidance.ml_approaches)
        num_papers = len(ml_guidance.source_papers)
        
        markdown += f"Based on analysis of {num_papers} industry implementations and the complete threat intelligence profile, "
        markdown += f"we identified {num_approaches} ML approaches specifically tailored for detecting {threat_name}. "
        markdown += "These recommendations leverage all available threat context including technical details, C2 methods, IOCs, and forensic artifacts.\n\n"
        
        # Add threat context summary
        context_summary = self._extract_threat_context_summary(complete_threat_data)
        if context_summary != "Limited threat context available.":
            markdown += "### 🎯 Threat-Specific Context Applied\n\n"
            markdown += f"{context_summary}\n\n"
            markdown += "The ML approaches below are specifically designed to detect these threat characteristics.\n\n"
        
        # Add sections (same as before)
        for section in sections:
            markdown += f"### {section.title}\n\n"
            markdown += f"{section.content}\n\n"
            
            # Add metadata table
            markdown += "| Metric | Value |\n"
            markdown += "|--------|-------|\n"
            markdown += f"| Implementation Complexity | {section.implementation_complexity} |\n"
            markdown += f"| Expected Accuracy | {section.expected_accuracy} |\n"
            markdown += f"| Deployment Timeframe | {section.deployment_timeframe} |\n"
            markdown += f"| Data Requirements | {', '.join(section.data_requirements[:3])} |\n\n"
        
        # Add source papers section (same as before)
        if ml_guidance.source_papers:
            markdown += "### 📚 Source Papers & Case Studies\n\n"
            markdown += "The following industry implementations informed these threat-specific recommendations:\n\n"
            
            for paper in ml_guidance.source_papers[:5]:  # Top 5 papers
                markdown += f"**{paper.company} ({paper.year})**: {paper.title}\n"
                if paper.techniques:
                    markdown += f"*Techniques*: {', '.join(paper.techniques[:3])}\n"
                if paper.url:
                    markdown += f"*Source*: [Link]({paper.url})\n"
                markdown += "\n"
        
        # Enhanced implementation priority with threat context
        markdown += "### 🎯 Threat-Specific Implementation Priority\n\n"
        markdown += f"**Recommended Implementation Order for {threat_name}:**\n"
        markdown += "1. **Start with Low Complexity approaches** targeting the identified attack vectors\n"
        markdown += "2. **Enhance with Medium Complexity methods** focusing on behavioral patterns\n"
        markdown += "3. **Deploy High Complexity solutions** for advanced threat-specific detection\n\n"
        
        # Enhanced disclaimer
        markdown += "---\n"
        markdown += "*ML detection recommendations are specifically tailored to this threat based on the complete intelligence profile and industry implementations. "
        markdown += "Effectiveness is optimized for the identified threat characteristics, TTPs, and available threat context.*\n\n"
        
        return markdown
    
    def _generate_enhanced_fallback_section(self, threat_characteristics: ThreatCharacteristics,
                                          complete_threat_data: Dict) -> str:
        """Generate enhanced fallback ML guidance when main pipeline fails"""
        
        markdown = "## 🤖 ML-Based Anomaly Detection Approaches\n\n"
        markdown += f"Threat-specific ML detection approaches for {threat_characteristics.threat_name}:\n\n"
        
        # Use threat context for better fallback
        context_summary = self._extract_threat_context_summary(complete_threat_data)
        
        markdown += "### Threat-Aware Anomaly Detection\n\n"
        markdown += f"**Statistical Anomaly Detection:** Implement baseline monitoring for {threat_characteristics.threat_name} "
        markdown += f"focusing on the identified attack vectors: {', '.join(threat_characteristics.attack_vectors[:3])}.\n\n"
        
        markdown += f"**Behavioral Analysis:** Monitor for behavior patterns specific to {threat_characteristics.threat_name}: "
        markdown += f"{', '.join(threat_characteristics.behavior_patterns[:3])}.\n\n"
        
        if context_summary != "Limited threat context available.":
            markdown += "**Context-Aware Detection:** Leverage the following threat-specific indicators:\n"
            markdown += f"{context_summary}\n\n"
        
        markdown += "| Metric | Value |\n"
        markdown += "|--------|-------|\n"
        markdown += "| Implementation Complexity | Low-Medium |\n"
        markdown += "| Expected Accuracy | 70-80% (threat-specific) |\n"
        markdown += "| Deployment Timeframe | 2-4 weeks |\n"
        markdown += "| Data Requirements | Threat-specific logs, baseline data |\n\n"
        
        markdown += "---\n"
        markdown += "*Enhanced fallback recommendations based on available threat context. "
        markdown += "For optimal results, ensure the ML knowledge base and agentic retriever are properly configured.*\n\n"
        
        return markdown
    
    def _generate_fallback_section(self, threat_characteristics: ThreatCharacteristics) -> str:
        """Generate fallback ML guidance when main pipeline fails"""
        
        markdown = "## 🤖 ML-Based Anomaly Detection Approaches\n\n"
        markdown += f"ML-based detection approaches for {threat_characteristics.threat_name}:\n\n"
        
        markdown += "### General Anomaly Detection\n\n"
        markdown += "**Statistical Anomaly Detection:** Implement baseline statistical monitoring "
        markdown += "for unusual patterns in network traffic, user behavior, and system activities. "
        markdown += "This approach can detect deviations from normal operational patterns.\n\n"
        
        markdown += "**Behavioral Analysis:** Monitor for behavior patterns consistent with "
        markdown += f"{', '.join(threat_characteristics.behavior_patterns)} activities. "
        markdown += "Focus on temporal analysis and sequence detection.\n\n"
        
        markdown += "| Metric | Value |\n"
        markdown += "|--------|-------|\n"
        markdown += "| Implementation Complexity | Low-Medium |\n"
        markdown += "| Expected Accuracy | 70-80% |\n"
        markdown += "| Deployment Timeframe | 2-4 weeks |\n"
        markdown += "| Data Requirements | Network logs, system logs |\n\n"
        
        markdown += "---\n"
        markdown += "*Fallback recommendations provided. For more specific guidance, "
        markdown += "please ensure the ML knowledge base is properly configured.*\n\n"
        
        return markdown


def test_ml_guidance_generator():
    """Test the ML guidance generator"""
    
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        print("Error: ANTHROPIC_API_KEY environment variable not set")
        return
    
    print("📝 Testing ML Guidance Generator")
    print("=" * 40)
    
    # Initialize
    anthropic_client = Anthropic(api_key=api_key)
    generator = MLGuidanceGenerator(anthropic_client)
    
    # Test with sample threat
    threat = ThreatCharacteristics(
        threat_name="Cobalt Strike",
        threat_type="post_exploitation_framework",
        attack_vectors=["network", "memory_injection"],
        target_assets=["corporate_networks", "endpoints"],
        behavior_patterns=["lateral_movement", "persistence", "command_control"],
        time_characteristics="persistent"
    )
    
    print(f"🎯 Generating ML guidance for: {threat.threat_name}")
    print(f"   Type: {threat.threat_type}")
    print(f"   Attack Vectors: {', '.join(threat.attack_vectors)}")
    
    # Generate guidance
    guidance_markdown = generator.generate_ml_guidance_section(threat)
    
    print(f"\n📄 Generated ML Guidance:")
    print(f"   Length: {len(guidance_markdown)} characters")
    print(f"   Sections: {guidance_markdown.count('###')} subsections")
    
    # Save to file for review
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"ml_guidance_test_{timestamp}.md"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(guidance_markdown)
    
    print(f"   Saved to: {output_file}")
    
    # Show preview
    preview_lines = guidance_markdown.split('\n')[:20]
    print(f"\n📖 Preview (first 20 lines):")
    print("-" * 40)
    for line in preview_lines:
        print(line)
    
    print(f"\n✅ ML guidance generation test complete!")


if __name__ == "__main__":
    test_ml_guidance_generator()