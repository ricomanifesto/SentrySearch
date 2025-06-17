"""
ML Agentic Retriever for SentrySearch

Implements Agentic RAG approach with intelligent query optimization.
Provides intelligent ML-focused retrieval for threat intelligence with:
- Query optimization for threat-to-ML translation
- Source identification for relevant paper filtering  
- Enhanced hybrid retrieval with post-processing
- Context-aware result ranking and structuring

Usage:
    retriever = MLAgenticRetriever(anthropic_client, knowledge_base)
    ml_guidance = retriever.get_ml_guidance(threat_characteristics)
"""

import os
import json
import logging
import time
import random
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
import re

from anthropic import Anthropic
import anthropic
from ml_knowledge_base_builder import KnowledgeBaseStorage

logger = logging.getLogger(__name__)


@dataclass
class ThreatCharacteristics:
    """Represents threat characteristics for ML guidance generation"""
    threat_name: str
    threat_type: str  # e.g., "malware", "apt", "insider_threat"
    attack_vectors: List[str]  # e.g., ["network", "email", "web"]
    target_assets: List[str]  # e.g., ["user_accounts", "financial_data"]
    behavior_patterns: List[str]  # e.g., ["lateral_movement", "data_exfiltration"]
    time_characteristics: str  # e.g., "persistent", "burst", "periodic"


@dataclass
class OptimizedQuery:
    """Represents an optimized query for ML retrieval"""
    original_query: str
    optimized_queries: List[str]
    ml_focus_areas: List[str]
    reasoning: str


@dataclass
class SourceSelection:
    """Represents filtered source selection"""
    relevant_companies: List[str]
    relevant_years: List[str]
    relevant_techniques: List[str]
    reasoning: str


@dataclass
class MLRetrievalResult:
    """Represents a structured ML retrieval result"""
    content: str
    metadata: Dict
    relevance_score: float
    source_paper: str
    ml_techniques: List[str]
    implementation_details: str
    applicability_score: float


class QueryOptimizer:
    """Optimizes queries to focus on ML anomaly detection approaches"""
    
    def __init__(self, anthropic_client):
        self.client = anthropic_client
    
    def _api_call_with_retry(self, **kwargs):
        """Make API call with intelligent retry logic using retry-after header"""
        max_retries = 3
        base_delay = 5
        
        for attempt in range(max_retries):
            try:
                print(f"DEBUG: Query Optimizer API call attempt {attempt + 1}/{max_retries}")
                return self.client.messages.create(**kwargs)
                
            except anthropic.RateLimitError as e:
                if attempt == max_retries - 1:
                    print(f"DEBUG: Query Optimizer rate limit exceeded after {max_retries} attempts")
                    raise e
                
                # Check if the error response has retry-after information
                retry_after = None
                if hasattr(e, 'response') and e.response:
                    retry_after_header = e.response.headers.get('retry-after')
                    if retry_after_header:
                        try:
                            retry_after = float(retry_after_header)
                            print(f"DEBUG: Query Optimizer API provided retry-after: {retry_after} seconds")
                        except (ValueError, TypeError):
                            pass
                
                # Use retry-after if available, otherwise exponential backoff
                if retry_after:
                    delay = retry_after + random.uniform(1, 3)
                else:
                    delay = base_delay * (2 ** attempt) + random.uniform(1, 5)
                    delay = min(delay, 120)
                
                print(f"DEBUG: Query Optimizer rate limit hit. Waiting {delay:.1f} seconds before retry {attempt + 2}")
                time.sleep(delay)
                
            except Exception as e:
                print(f"DEBUG: Query Optimizer non-rate-limit error: {e}")
                raise e
    
    def optimize_query(self, threat_characteristics: ThreatCharacteristics) -> OptimizedQuery:
        """Convert threat characteristics into ML-focused queries"""
        
        prompt = f"""
You are an expert in both cybersecurity threats and machine learning anomaly detection. 
Convert this threat information into 3-5 specific queries about ML approaches for detection.

Threat Information:
- Name: {threat_characteristics.threat_name}
- Type: {threat_characteristics.threat_type}
- Attack Vectors: {', '.join(threat_characteristics.attack_vectors)}
- Target Assets: {', '.join(threat_characteristics.target_assets)}
- Behavior Patterns: {', '.join(threat_characteristics.behavior_patterns)}
- Time Characteristics: {threat_characteristics.time_characteristics}

Generate queries that focus on:
1. Specific ML techniques for detecting this threat type
2. Feature engineering approaches for the attack vectors
3. Behavioral analysis methods for the patterns observed
4. Implementation considerations for the target environment

Format your response as:
QUERIES:
1. [Query 1]
2. [Query 2] 
3. [Query 3]
etc.

ML_FOCUS_AREAS: [comma-separated focus areas]

REASONING: [1-2 sentences explaining the ML approach rationale]
"""
        
        try:
            response = self._api_call_with_retry(
                model="claude-sonnet-4-20250514",
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Safe access to response content
            if not response.content or len(response.content) == 0:
                raise ValueError("Empty response from API")
            
            content = response.content[0].text.strip()
            return self._parse_optimization_response(content, threat_characteristics)
            
        except Exception as e:
            logger.error(f"Query optimization failed: {e}")
            # Fallback to simple query
            fallback_query = f"Machine learning approaches for detecting {threat_characteristics.threat_name}"
            return OptimizedQuery(
                original_query=threat_characteristics.threat_name,
                optimized_queries=[fallback_query],
                ml_focus_areas=["anomaly_detection"],
                reasoning="Fallback query due to optimization failure"
            )
    
    def _parse_optimization_response(self, response: str, threat_characteristics: ThreatCharacteristics) -> OptimizedQuery:
        """Parse the LLM response into structured query optimization"""
        
        queries = []
        ml_focus_areas = []
        reasoning = ""
        
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('QUERIES:'):
                current_section = 'queries'
                continue
            elif line.startswith('ML_FOCUS_AREAS:'):
                current_section = 'focus'
                ml_focus_areas = [area.strip() for area in line.replace('ML_FOCUS_AREAS:', '').split(',')]
                continue
            elif line.startswith('REASONING:'):
                current_section = 'reasoning'
                reasoning = line.replace('REASONING:', '').strip()
                continue
            
            if current_section == 'queries' and line:
                # Extract query from numbered list
                query_match = re.match(r'\d+\.\s*(.+)', line)
                if query_match:
                    queries.append(query_match.group(1).strip())
            elif current_section == 'reasoning' and line:
                reasoning += ' ' + line
        
        # Ensure we have at least one query
        if not queries:
            queries = [f"Machine learning detection approaches for {threat_characteristics.threat_name}"]
        
        return OptimizedQuery(
            original_query=threat_characteristics.threat_name,
            optimized_queries=queries,
            ml_focus_areas=ml_focus_areas if ml_focus_areas else ["anomaly_detection"],
            reasoning=reasoning.strip()
        )


class SourceIdentifier:
    """Identifies most relevant papers/sources for a given threat"""
    
    def __init__(self, knowledge_base: KnowledgeBaseStorage):
        self.knowledge_base = knowledge_base
        self._load_source_mappings()
    
    def _load_source_mappings(self):
        """Load mappings between threat types and relevant sources"""
        
        # Company expertise mappings
        self.company_expertise = {
            'Netflix': ['performance_monitoring', 'infrastructure_anomalies', 'streaming_security'],
            'LinkedIn': ['user_behavior', 'abuse_detection', 'social_platform_security'],
            'Slack': ['communication_security', 'invite_spam', 'workspace_security'],
            'Cloudflare': ['network_security', 'bot_detection', 'traffic_analysis'],
            'Uber': ['fraud_detection', 'real_time_systems', 'human_in_the_loop'],
            'Grab': ['financial_fraud', 'graph_analysis', 'transaction_security'],
            'OLX Group': ['marketplace_fraud', 'deep_learning', 'user_verification'],
            'Stack Exchange': ['content_moderation', 'spam_detection', 'community_security'],
            'Mercari': ['e_commerce_security', 'content_moderation', 'automated_review']
        }
        
        # Attack vector to technique mappings
        self.attack_vector_techniques = {
            'network': ['traffic_analysis', 'graph_ml', 'behavioral_analysis'],
            'email': ['text_classification', 'nlp', 'spam_detection'],
            'web': ['bot_detection', 'traffic_analysis', 'behavioral_analysis'],
            'insider': ['user_behavior', 'behavioral_analysis', 'anomaly_detection'],
            'financial': ['fraud_detection', 'transaction_analysis', 'graph_ml']
        }
        
        # Threat type to ML approach mappings
        self.threat_ml_mappings = {
            'malware': ['behavioral_analysis', 'static_analysis', 'dynamic_analysis'],
            'apt': ['behavioral_analysis', 'network_analysis', 'long_term_patterns'],
            'fraud': ['fraud_detection', 'transaction_analysis', 'user_behavior'],
            'spam': ['text_classification', 'content_moderation', 'nlp'],
            'abuse': ['user_behavior', 'abuse_detection', 'behavioral_analysis']
        }
    
    def identify_relevant_sources(self, optimized_query: OptimizedQuery, 
                                threat_characteristics: ThreatCharacteristics) -> SourceSelection:
        """Identify most relevant papers/sources for the optimized queries"""
        
        relevant_companies = set()
        relevant_techniques = set()
        
        # Map attack vectors to companies
        for vector in threat_characteristics.attack_vectors:
            for company, expertise in self.company_expertise.items():
                for expert_area in expertise:
                    if any(keyword in expert_area for keyword in [vector, threat_characteristics.threat_type]):
                        relevant_companies.add(company)
            
            # Add techniques for this attack vector
            if vector in self.attack_vector_techniques:
                relevant_techniques.update(self.attack_vector_techniques[vector])
        
        # Map threat type to companies and techniques
        threat_type = threat_characteristics.threat_type.lower()
        for company, expertise in self.company_expertise.items():
            if any(threat_type in expert_area or expert_area in threat_type for expert_area in expertise):
                relevant_companies.add(company)
        
        # Add techniques for threat type
        if threat_type in self.threat_ml_mappings:
            relevant_techniques.update(self.threat_ml_mappings[threat_type])
        
        # Add techniques from ML focus areas
        relevant_techniques.update(optimized_query.ml_focus_areas)
        
        # Always include available companies from knowledge base
        stats = self.knowledge_base.get_stats()
        available_companies = set(stats['companies'])
        
        # For now, include all available companies to ensure we get results
        # In production, you can make this more selective
        relevant_companies.update(available_companies)
        
        # If still empty somehow, use all available
        if not relevant_companies:
            relevant_companies = available_companies
        
        # Generate reasoning
        reasoning = f"Selected companies based on expertise in {threat_characteristics.threat_type} and {', '.join(threat_characteristics.attack_vectors)}. Focus on {', '.join(list(relevant_techniques)[:3])} techniques."
        
        return SourceSelection(
            relevant_companies=list(relevant_companies),
            relevant_years=['2019', '2020', '2021', '2022'],  # All available years
            relevant_techniques=list(relevant_techniques),
            reasoning=reasoning
        )


class EnhancedRetriever:
    """Enhanced hybrid retriever with post-processing"""
    
    def __init__(self, knowledge_base: KnowledgeBaseStorage):
        self.knowledge_base = knowledge_base
    
    def retrieve_with_context(self, optimized_query: OptimizedQuery, 
                            source_selection: SourceSelection,
                            max_results: int = 10) -> List[MLRetrievalResult]:
        """Retrieve and rank results with context-aware processing"""
        
        all_results = []
        
        # Search with each optimized query
        for query in optimized_query.optimized_queries:
            results = self.knowledge_base.search(query, n_results=max_results)
            
            for result in results:
                # Filter by relevant sources
                metadata = result['metadata']
                company = metadata.get('company', '')
                
                if company in source_selection.relevant_companies:
                    ml_result = self._create_ml_result(result, optimized_query, source_selection)
                    all_results.append(ml_result)
        
        # Post-process results
        processed_results = self._post_process_results(all_results)
        
        # Rank by combined relevance and applicability
        ranked_results = sorted(processed_results, 
                              key=lambda x: (x.applicability_score * x.relevance_score), 
                              reverse=True)
        
        return ranked_results[:max_results]
    
    def _create_ml_result(self, search_result: Dict, 
                         optimized_query: OptimizedQuery,
                         source_selection: SourceSelection) -> MLRetrievalResult:
        """Convert search result to structured ML result"""
        
        metadata = search_result['metadata']
        
        # Calculate applicability score based on technique overlap
        ml_techniques_raw = metadata.get('ml_techniques', '')
        # Ensure we have a string before splitting
        ml_techniques_str = str(ml_techniques_raw) if ml_techniques_raw else ''
        paper_techniques = set(str(t).strip() for t in ml_techniques_str.split('|') if str(t).strip())
        relevant_techniques = set(source_selection.relevant_techniques)
        
        technique_overlap = len(paper_techniques.intersection(relevant_techniques))
        applicability_score = min(technique_overlap / max(len(relevant_techniques), 1), 1.0)
        
        # Extract implementation details from content
        content = search_result['document']
        implementation_details = self._extract_implementation_details(content)
        
        return MLRetrievalResult(
            content=content,
            metadata=metadata,
            relevance_score=search_result['score'],
            source_paper=metadata.get('source_title', ''),
            ml_techniques=list(paper_techniques),
            implementation_details=implementation_details,
            applicability_score=applicability_score
        )
    
    def _extract_implementation_details(self, content: str) -> str:
        """Extract key implementation details from content"""
        
        # Look for implementation-specific keywords
        impl_keywords = [
            'architecture', 'framework', 'algorithm', 'model',
            'feature', 'training', 'deployment', 'performance',
            'accuracy', 'precision', 'recall', 'latency'
        ]
        
        sentences = content.split('.')
        impl_sentences = []
        
        for sentence in sentences:
            if any(keyword in sentence.lower() for keyword in impl_keywords):
                impl_sentences.append(sentence.strip())
        
        return '. '.join(impl_sentences[:3])  # Top 3 relevant sentences
    
    def _post_process_results(self, results: List[MLRetrievalResult]) -> List[MLRetrievalResult]:
        """Post-process results for deduplication and enhancement"""
        
        # Simple deduplication by content hash
        seen_hashes = set()
        deduplicated = []
        
        for result in results:
            content_hash = hash(result.content[:200])  # Hash first 200 chars
            
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                deduplicated.append(result)
        
        return deduplicated


class MLAgenticRetriever:
    """Main agentic retriever orchestrating all components"""
    
    def __init__(self, anthropic_client, knowledge_base_path: str = "./ml_knowledge_base"):
        self.client = anthropic_client
        self.knowledge_base = KnowledgeBaseStorage(knowledge_base_path)
        
        # Initialize agents
        self.query_optimizer = QueryOptimizer(anthropic_client)
        self.source_identifier = SourceIdentifier(self.knowledge_base)
        self.enhanced_retriever = EnhancedRetriever(self.knowledge_base)
        
        logger.info("ML Agentic Retriever initialized")
    
    def get_ml_guidance(self, threat_characteristics: ThreatCharacteristics) -> Dict:
        """Get comprehensive ML guidance for threat detection"""
        
        try:
            logger.info(f"Getting ML guidance for: {threat_characteristics.threat_name}")
            
            # Step 1: Query Optimization
            optimized_query = self.query_optimizer.optimize_query(threat_characteristics)
            logger.info(f"Generated {len(optimized_query.optimized_queries)} optimized queries")
            
            # Step 2: Source Identification
            source_selection = self.source_identifier.identify_relevant_sources(
                optimized_query, threat_characteristics
            )
            logger.info(f"Identified {len(source_selection.relevant_companies)} relevant companies")
            
            # Step 3: Enhanced Retrieval
            ml_results = self.enhanced_retriever.retrieve_with_context(
                optimized_query, source_selection, max_results=8
            )
            logger.info(f"Retrieved {len(ml_results)} relevant ML approaches")
            
            # Step 4: Structure results
            guidance = self._structure_ml_guidance(
                threat_characteristics, optimized_query, source_selection, ml_results
            )
            
            return guidance
            
        except Exception as e:
            logger.error(f"ML guidance generation failed: {e}")
            return self._create_fallback_guidance(threat_characteristics)
    
    def get_enhanced_ml_guidance(self, threat_characteristics: ThreatCharacteristics, 
                               complete_threat_data: Dict) -> Dict:
        """Get enhanced ML guidance leveraging complete threat intelligence context"""
        
        try:
            logger.info(f"Getting enhanced ML guidance for: {threat_characteristics.threat_name}")
            
            # Step 1: Enhanced Query Optimization with threat context
            optimized_query = self._optimize_query_with_context(threat_characteristics, complete_threat_data)
            logger.info(f"Generated {len(optimized_query.optimized_queries)} context-enhanced queries")
            
            # Step 2: Enhanced Source Identification
            source_selection = self.source_identifier.identify_relevant_sources(
                optimized_query, threat_characteristics
            )
            logger.info(f"Identified {len(source_selection.relevant_companies)} relevant companies")
            
            # Step 3: Enhanced Retrieval with threat context
            ml_results = self.enhanced_retriever.retrieve_with_context(
                optimized_query, source_selection, max_results=10  # More results for enhanced mode
            )
            logger.info(f"Retrieved {len(ml_results)} relevant ML approaches")
            
            # Step 4: Structure results with enhanced context
            guidance = self._structure_enhanced_ml_guidance(
                threat_characteristics, optimized_query, source_selection, ml_results, complete_threat_data
            )
            
            return guidance
            
        except Exception as e:
            logger.error(f"Enhanced ML guidance generation failed: {e}")
            return self._create_enhanced_fallback_guidance(threat_characteristics, complete_threat_data)
    
    def _structure_ml_guidance(self, threat_characteristics: ThreatCharacteristics,
                             optimized_query: OptimizedQuery,
                             source_selection: SourceSelection,
                             ml_results: List[MLRetrievalResult]) -> Dict:
        """Structure the ML guidance into organized sections"""
        
        # Group results by ML technique
        techniques_map = {}
        for result in ml_results:
            for technique in result.ml_techniques:
                if technique not in techniques_map:
                    techniques_map[technique] = []
                techniques_map[technique].append(result)
        
        # Create structured guidance
        guidance = {
            'threat_name': threat_characteristics.threat_name,
            'ml_approaches': [],
            'implementation_considerations': [],
            'source_papers': [],
            'query_optimization': {
                'original_query': optimized_query.original_query,
                'optimized_queries': optimized_query.optimized_queries,
                'reasoning': optimized_query.reasoning
            },
            'source_selection': {
                'relevant_companies': source_selection.relevant_companies,
                'reasoning': source_selection.reasoning
            }
        }
        
        # Add ML approaches
        for technique, results in techniques_map.items():
            if results:  # Only include techniques with results
                best_result = max(results, key=lambda x: x.applicability_score)
                
                approach = {
                    'technique': str(technique),
                    'description': best_result.implementation_details,
                    'source_company': str(best_result.metadata.get('company', '')),
                    'source_paper': str(best_result.source_paper),
                    'applicability_score': best_result.applicability_score,
                    'relevance_score': best_result.relevance_score
                }
                
                guidance['ml_approaches'].append(approach)
        
        # Add implementation considerations
        for result in ml_results[:3]:  # Top 3 results
            consideration = {
                'aspect': f"{result.metadata.get('company', '')} Implementation",
                'details': result.implementation_details,
                'source': result.source_paper
            }
            guidance['implementation_considerations'].append(consideration)
        
        # Add source papers
        seen_papers = set()
        for result in ml_results:
            paper_title = result.source_paper
            if paper_title not in seen_papers:
                seen_papers.add(paper_title)
                paper_info = {
                    'title': paper_title,
                    'company': result.metadata.get('company', ''),
                    'year': result.metadata.get('year', ''),
                    'url': result.metadata.get('source_url', ''),
                    'techniques': result.ml_techniques
                }
                guidance['source_papers'].append(paper_info)
        
        return guidance
    
    def _create_fallback_guidance(self, threat_characteristics: ThreatCharacteristics) -> Dict:
        """Create fallback guidance when main pipeline fails"""
        
        return {
            'threat_name': threat_characteristics.threat_name,
            'ml_approaches': [{
                'technique': 'anomaly_detection',
                'description': 'General anomaly detection approaches using statistical methods and machine learning',
                'source_company': 'General',
                'source_paper': 'Fallback recommendation',
                'applicability_score': 0.5,
                'relevance_score': 0.5
            }],
            'implementation_considerations': [{
                'aspect': 'General Implementation',
                'details': 'Consider implementing statistical anomaly detection as a baseline approach',
                'source': 'Fallback recommendation'
            }],
            'source_papers': [],
            'error': 'ML guidance generation failed - fallback recommendations provided'
        }


def create_test_threat_characteristics() -> ThreatCharacteristics:
    """Create test threat characteristics for validation"""
    
    return ThreatCharacteristics(
        threat_name="ShadowPad",
        threat_type="malware",
        attack_vectors=["network", "lateral_movement"],
        target_assets=["corporate_networks", "sensitive_data"],
        behavior_patterns=["persistence", "data_exfiltration", "command_control"],
        time_characteristics="persistent"
    )


# Add enhanced methods to MLAgenticRetriever class
def _optimize_query_with_context(self, threat_characteristics: ThreatCharacteristics,
                               complete_threat_data: Dict) -> OptimizedQuery:
    """Create enhanced queries using complete threat intelligence context"""
    
    # Extract additional context for query enhancement
    context_elements = []
    
    # Technical capabilities
    if tech_details := complete_threat_data.get('technicalDetails'):
        if capabilities := tech_details.get('capabilities'):
            # Ensure capabilities is a list before slicing
            if isinstance(capabilities, list):
                cap_names = [cap.get('name', str(cap)) if isinstance(cap, dict) else str(cap) 
                           for cap in capabilities[:3]]
                context_elements.extend(cap_names)
    
    # C2 protocols
    if c2_data := complete_threat_data.get('commandAndControl'):
        if methods := c2_data.get('communicationMethods'):
            # Ensure methods is a list before slicing
            if isinstance(methods, list):
                protocols = [method.get('protocol', str(method)) if isinstance(method, dict) else str(method) 
                           for method in methods[:2]]
                context_elements.extend(protocols)
    
    # Use the regular optimizer with enhanced threat characteristics
    enhanced_characteristics = ThreatCharacteristics(
        threat_name=threat_characteristics.threat_name,
        threat_type=threat_characteristics.threat_type,
        attack_vectors=threat_characteristics.attack_vectors + context_elements[:2],
        target_assets=threat_characteristics.target_assets,
        behavior_patterns=threat_characteristics.behavior_patterns + context_elements[2:4],
        time_characteristics=threat_characteristics.time_characteristics
    )
    
    return self.query_optimizer.optimize_query(enhanced_characteristics)

def _structure_enhanced_ml_guidance(self, threat_characteristics: ThreatCharacteristics,
                                  optimized_query: OptimizedQuery,
                                  source_selection: SourceSelection,
                                  ml_results: List,  # MLRetrievalResult type
                                  complete_threat_data: Dict) -> Dict:
    """Structure enhanced ML guidance with threat context"""
    
    # Start with regular structuring
    guidance = self._structure_ml_guidance(
        threat_characteristics, optimized_query, source_selection, ml_results
    )
    
    # Enhance with threat context
    guidance['threat_context_applied'] = True
    guidance['context_sources'] = {
        'technical_details': bool(complete_threat_data.get('technicalDetails')),
        'command_and_control': bool(complete_threat_data.get('commandAndControl')),
        'detection_and_mitigation': bool(complete_threat_data.get('detectionAndMitigation')),
        'forensic_artifacts': bool(complete_threat_data.get('forensicArtifacts'))
    }
    
    # Add threat-specific implementation considerations
    if tech_details := complete_threat_data.get('technicalDetails'):
        if os_data := tech_details.get('operatingSystems'):
            # Ensure os_data is a list before slicing
            if isinstance(os_data, list):
                os_names = [os.get('name', str(os)) if isinstance(os, dict) else str(os) for os in os_data[:2]]
                guidance['implementation_considerations'].append({
                    'aspect': 'OS Compatibility',
                    'details': f'Ensure ML models are trained on {", ".join(os_names)} environments for optimal detection.',
                    'source': 'Threat Intelligence Profile'
                })
    
    return guidance

def _create_enhanced_fallback_guidance(self, threat_characteristics: ThreatCharacteristics,
                                     complete_threat_data: Dict) -> Dict:
    """Create enhanced fallback guidance with threat context"""
    
    fallback = self._create_fallback_guidance(threat_characteristics)
    
    # Add context-aware recommendations
    fallback['threat_context_applied'] = True
    fallback['enhanced_fallback'] = True
    
    # Add context-specific ML approaches
    if complete_threat_data.get('commandAndControl'):
        fallback['ml_approaches'].append({
            'technique': 'C2 Traffic Analysis',
            'source_company': 'Context-Derived',
            'description': 'ML-based detection of command and control communication patterns identified in the threat profile.',
            'applicability_score': 0.8
        })
    
    if complete_threat_data.get('forensicArtifacts'):
        fallback['ml_approaches'].append({
            'technique': 'Artifact-Based Detection',
            'source_company': 'Context-Derived', 
            'description': 'Machine learning models trained on forensic artifacts specific to this threat.',
            'applicability_score': 0.7
        })
    
    return fallback

# Monkey patch these methods onto the MLAgenticRetriever class
MLAgenticRetriever._optimize_query_with_context = _optimize_query_with_context
MLAgenticRetriever._structure_enhanced_ml_guidance = _structure_enhanced_ml_guidance
MLAgenticRetriever._create_enhanced_fallback_guidance = _create_enhanced_fallback_guidance


def main():
    """Test the ML Agentic Retriever"""
    
    # Initialize
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        print("Error: ANTHROPIC_API_KEY environment variable not set")
        return
    
    print("🤖 Testing ML Agentic Retriever")
    print("=" * 40)
    
    # Create components
    anthropic_client = Anthropic(api_key=api_key)
    retriever = MLAgenticRetriever(anthropic_client)
    
    # Test with sample threat
    threat = create_test_threat_characteristics()
    
    print(f"🎯 Testing with threat: {threat.threat_name}")
    print(f"   Type: {threat.threat_type}")
    print(f"   Attack Vectors: {', '.join(threat.attack_vectors)}")
    print(f"   Behavior Patterns: {', '.join(threat.behavior_patterns)}")
    
    # Get ML guidance
    guidance = retriever.get_ml_guidance(threat)
    
    print(f"\n🧠 ML Guidance Generated:")
    print(f"   ML Approaches: {len(guidance['ml_approaches'])}")
    print(f"   Implementation Considerations: {len(guidance['implementation_considerations'])}")
    print(f"   Source Papers: {len(guidance['source_papers'])}")
    
    # Show details
    if guidance['ml_approaches']:
        print(f"\n📊 Top ML Approaches:")
        for i, approach in enumerate(guidance['ml_approaches'][:3], 1):
            print(f"   {i}. {approach['technique']} ({approach['source_company']})")
            print(f"      Applicability: {approach['applicability_score']:.2f}")
            print(f"      Description: {approach['description'][:100]}...")
    
    if guidance['source_papers']:
        print(f"\n📚 Source Papers:")
        for paper in guidance['source_papers'][:3]:
            print(f"   • {paper['company']} ({paper['year']}): {paper['title'][:60]}...")
    
    print(f"\n✅ Agentic retrieval test complete!")


if __name__ == "__main__":
    main()