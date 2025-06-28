"""
Workers-based ML Retriever for SentrySearch

Updated MLAgenticRetriever that calls Cloudflare Workers for hybrid search
instead of local ChromaDB, providing production-ready global performance.
"""

import os
import json
import logging
import time
import random
import hashlib
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
import re
import requests
from datetime import datetime

from anthropic import Anthropic
import anthropic

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
class WorkersSearchResult:
    """Represents a search result from Cloudflare Workers"""
    chunk_id: str
    content: str
    enriched_content: str
    metadata: Dict
    scores: Dict
    retrieval_method: str
    matched_terms: List[str]


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
    
    def __init__(self, workers_client):
        self.workers_client = workers_client
        self._load_source_mappings()
    
    def _load_source_mappings(self):
        """Load mappings between threat types and relevant sources"""
        
        # Company expertise mappings
        self.company_expertise = {
            'Netflix': ['performance_monitoring', 'infrastructure_anomalies', 'streaming_security'],
            'LinkedIn': ['user_behavior', 'abuse_detection', 'social_platform_security'],
            'Stack Exchange': ['content_moderation', 'spam_detection', 'community_security'],
            'Cloudflare': ['network_security', 'bot_detection', 'traffic_analysis'],
            'Uber': ['fraud_detection', 'real_time_systems', 'human_in_the_loop'],
            'Grab': ['financial_fraud', 'graph_analysis', 'transaction_security']
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
        
        # Get available companies from Workers metadata
        try:
            available_companies = self.workers_client.get_available_companies()
            relevant_companies.update(available_companies)
        except Exception as e:
            logger.warning(f"Failed to get available companies: {e}")
        
        # If still empty somehow, use default set
        if not relevant_companies:
            relevant_companies = {'Netflix', 'LinkedIn', 'Stack Exchange', 'Cloudflare', 'Grab'}
        
        # Generate reasoning
        reasoning = f"Selected companies based on expertise in {threat_characteristics.threat_type} and {', '.join(threat_characteristics.attack_vectors)}. Focus on {', '.join(list(relevant_techniques)[:3])} techniques."
        
        return SourceSelection(
            relevant_companies=list(relevant_companies),
            relevant_years=['2019', '2020', '2021', '2022'],  # All available years
            relevant_techniques=list(relevant_techniques),
            reasoning=reasoning
        )


class WorkersClient:
    """Client for Cloudflare Workers API"""
    
    def __init__(self, workers_url: str, timeout: int = 30):
        self.workers_url = workers_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'SentrySearch-Python-Client/1.0'
        })
    
    def hybrid_search(self, queries: List[str], max_results: int = 10, 
                     hybrid_weights: Dict = None, filters: Dict = None) -> List[WorkersSearchResult]:
        """Perform hybrid search using Workers API"""
        
        payload = {
            'queries': queries,
            'maxResults': max_results,
            'hybridWeights': hybrid_weights or {'vector': 0.6, 'keyword': 0.4},
            'filters': filters or {}
        }
        
        try:
            response = self.session.post(
                f"{self.workers_url}/hybrid-search",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Convert to WorkersSearchResult objects
            results = []
            for result_data in data.get('results', []):
                result = WorkersSearchResult(
                    chunk_id=result_data.get('chunkId', ''),
                    content=result_data.get('content', ''),
                    enriched_content=result_data.get('enrichedContent', ''),
                    metadata=result_data.get('metadata', {}),
                    scores=result_data.get('scores', {}),
                    retrieval_method=result_data.get('retrievalMethod', 'unknown'),
                    matched_terms=result_data.get('matchedTerms', [])
                )
                results.append(result)
            
            return results
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Workers hybrid search failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in hybrid search: {e}")
            raise
    
    def vector_search(self, query: str, max_results: int = 10, filters: Dict = None) -> List[WorkersSearchResult]:
        """Perform vector search using Workers API"""
        
        payload = {
            'query': query,
            'maxResults': max_results,
            'filters': filters or {}
        }
        
        try:
            response = self.session.post(
                f"{self.workers_url}/vector-search",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            return self._parse_search_results(data.get('results', []))
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Workers vector search failed: {e}")
            raise
    
    def keyword_search(self, query: str, max_results: int = 10, filters: Dict = None) -> List[WorkersSearchResult]:
        """Perform keyword search using Workers API"""
        
        payload = {
            'query': query,
            'maxResults': max_results,
            'filters': filters or {}
        }
        
        try:
            response = self.session.post(
                f"{self.workers_url}/keyword-search",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            return self._parse_search_results(data.get('results', []))
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Workers keyword search failed: {e}")
            raise
    
    def get_available_companies(self) -> List[str]:
        """Get available companies from Workers metadata"""
        try:
            response = self.session.get(f"{self.workers_url}/metadata/companies", timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            companies = data.get('companies', [])
            return [company.get('name', '') for company in companies if company.get('name')]
            
        except Exception as e:
            logger.error(f"Failed to get available companies: {e}")
            return []
    
    def get_available_years(self) -> List[str]:
        """Get available years from Workers metadata"""
        try:
            response = self.session.get(f"{self.workers_url}/metadata/years", timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            years = data.get('years', [])
            return [year.get('year', '') for year in years if year.get('year')]
            
        except Exception as e:
            logger.error(f"Failed to get available years: {e}")
            return []
    
    def get_available_techniques(self) -> List[str]:
        """Get available ML techniques from Workers metadata"""
        try:
            response = self.session.get(f"{self.workers_url}/metadata/techniques", timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            techniques = data.get('techniques', [])
            return [tech.get('name', '') for tech in techniques if tech.get('name')]
            
        except Exception as e:
            logger.error(f"Failed to get available techniques: {e}")
            return []
    
    def health_check(self) -> bool:
        """Check if Workers API is healthy"""
        try:
            response = self.session.get(f"{self.workers_url}/health", timeout=5)
            response.raise_for_status()
            return True
        except Exception:
            return False
    
    def _parse_search_results(self, results_data: List[Dict]) -> List[WorkersSearchResult]:
        """Parse search results from API response"""
        results = []
        for result_data in results_data:
            result = WorkersSearchResult(
                chunk_id=result_data.get('chunkId', ''),
                content=result_data.get('content', ''),
                enriched_content=result_data.get('enrichedContent', ''),
                metadata=result_data.get('metadata', {}),
                scores=result_data.get('scores', {}),
                retrieval_method=result_data.get('method', 'unknown'),
                matched_terms=result_data.get('matchedTerms', [])
            )
            results.append(result)
        return results


class MLWorkersRetriever:
    """Main ML retriever using Cloudflare Workers for hybrid search"""
    
    def __init__(self, anthropic_client, workers_url: str):
        self.client = anthropic_client
        self.workers_client = WorkersClient(workers_url)
        
        # Initialize components
        self.query_optimizer = QueryOptimizer(anthropic_client)
        self.source_identifier = SourceIdentifier(self.workers_client)
        
        logger.info(f"ML Workers Retriever initialized with endpoint: {workers_url}")
    
    def get_ml_guidance(self, threat_characteristics: ThreatCharacteristics, trace_exporter=None) -> Dict:
        """Get comprehensive ML guidance for threat detection using Workers"""
        
        try:
            logger.info(f"Getting ML guidance for: {threat_characteristics.threat_name}")
            
            # Check Workers health
            if not self.workers_client.health_check():
                logger.warning("Workers API health check failed, proceeding anyway")
            
            # Step 1: Query Optimization
            optimized_query = self.query_optimizer.optimize_query(threat_characteristics)
            logger.info(f"Generated {len(optimized_query.optimized_queries)} optimized queries")
            
            # Step 2: Source Identification
            source_selection = self.source_identifier.identify_relevant_sources(
                optimized_query, threat_characteristics
            )
            logger.info(f"Identified {len(source_selection.relevant_companies)} relevant companies")
            
            # Step 3: Workers Hybrid Search
            filters = {
                'companies': source_selection.relevant_companies,
                'years': source_selection.relevant_years,
                'techniques': source_selection.relevant_techniques
            }
            
            search_results = self.workers_client.hybrid_search(
                queries=optimized_query.optimized_queries,
                max_results=8,
                filters=filters
            )
            logger.info(f"Retrieved {len(search_results)} results from Workers")
            
            # Step 4: Structure results
            guidance = self._structure_ml_guidance(
                threat_characteristics, optimized_query, source_selection, search_results
            )
            
            return guidance
            
        except Exception as e:
            logger.error(f"ML guidance generation failed: {e}")
            return self._create_fallback_guidance(threat_characteristics)
    
    def _structure_ml_guidance(self, threat_characteristics: ThreatCharacteristics,
                             optimized_query: OptimizedQuery,
                             source_selection: SourceSelection,
                             search_results: List[WorkersSearchResult]) -> Dict:
        """Structure the ML guidance into organized sections"""
        
        # Group results by ML technique
        techniques_map = {}
        for result in search_results:
            metadata = result.metadata
            ml_techniques = metadata.get('mlTechniques', [])
            
            for technique in ml_techniques:
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
            },
            'workers_metadata': {
                'total_results': len(search_results),
                'retrieval_methods': list(set(r.retrieval_method for r in search_results)),
                'average_scores': self._calculate_average_scores(search_results)
            }
        }
        
        # Add ML approaches
        for technique, results in techniques_map.items():
            if results:  # Only include techniques with results
                best_result = max(results, key=lambda x: x.scores.get('hybridScore', 0))
                
                approach = {
                    'technique': str(technique),
                    'description': best_result.enriched_content or best_result.content,
                    'source_company': str(best_result.metadata.get('company', '')),
                    'source_paper': str(best_result.metadata.get('sourceTitle', '')),
                    'applicability_score': best_result.scores.get('applicabilityScore', 0),
                    'relevance_score': best_result.scores.get('vectorScore', 0),
                    'retrieval_method': best_result.retrieval_method,
                    'hybrid_score': best_result.scores.get('hybridScore', 0),
                    'keyword_score': best_result.scores.get('keywordScore', 0),
                    'matched_terms': best_result.matched_terms
                }
                
                guidance['ml_approaches'].append(approach)
        
        # Add implementation considerations
        for result in search_results[:3]:  # Top 3 results
            consideration = {
                'aspect': f"{result.metadata.get('company', '')} Implementation",
                'details': result.enriched_content or result.content,
                'source': result.metadata.get('sourceTitle', ''),
                'retrieval_method': result.retrieval_method
            }
            guidance['implementation_considerations'].append(consideration)
        
        # Add source papers
        seen_papers = set()
        for result in search_results:
            paper_title = result.metadata.get('sourceTitle', '')
            if paper_title and paper_title not in seen_papers:
                seen_papers.add(paper_title)
                paper_info = {
                    'title': paper_title,
                    'company': result.metadata.get('company', ''),
                    'year': result.metadata.get('year', ''),
                    'url': result.metadata.get('sourceUrl', ''),
                    'techniques': result.metadata.get('mlTechniques', [])
                }
                guidance['source_papers'].append(paper_info)
        
        return guidance
    
    def _calculate_average_scores(self, search_results: List[WorkersSearchResult]) -> Dict:
        """Calculate average scores across all results"""
        if not search_results:
            return {}
        
        total_scores = {
            'vector': 0,
            'keyword': 0,
            'hybrid': 0,
            'applicability': 0
        }
        
        for result in search_results:
            scores = result.scores
            total_scores['vector'] += scores.get('vectorScore', 0)
            total_scores['keyword'] += scores.get('keywordScore', 0)
            total_scores['hybrid'] += scores.get('hybridScore', 0)
            total_scores['applicability'] += scores.get('applicabilityScore', 0)
        
        count = len(search_results)
        return {
            'average_vector_score': total_scores['vector'] / count,
            'average_keyword_score': total_scores['keyword'] / count,
            'average_hybrid_score': total_scores['hybrid'] / count,
            'average_applicability_score': total_scores['applicability'] / count
        }
    
    def _create_fallback_guidance(self, threat_characteristics: ThreatCharacteristics) -> Dict:
        """Create fallback guidance when Workers search fails"""
        
        return {
            'threat_name': threat_characteristics.threat_name,
            'ml_approaches': [{
                'technique': 'anomaly_detection',
                'description': 'General anomaly detection approaches using statistical methods and machine learning',
                'source_company': 'Fallback',
                'source_paper': 'Fallback recommendation',
                'applicability_score': 0.5,
                'relevance_score': 0.5,
                'retrieval_method': 'fallback'
            }],
            'implementation_considerations': [{
                'aspect': 'General Implementation',
                'details': 'Consider implementing statistical anomaly detection as a baseline approach',
                'source': 'Fallback recommendation',
                'retrieval_method': 'fallback'
            }],
            'source_papers': [],
            'error': 'Workers search failed - fallback recommendations provided',
            'workers_available': self.workers_client.health_check()
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


def main():
    """Test the ML Workers Retriever"""
    
    # Configuration
    api_key = os.getenv('ANTHROPIC_API_KEY')
    workers_url = os.getenv('WORKERS_URL', 'https://sentry-search-hybrid.your-subdomain.workers.dev')
    
    if not api_key:
        print("Error: ANTHROPIC_API_KEY environment variable not set")
        return
    
    print("🤖 Testing ML Workers Retriever")
    print("=" * 40)
    print(f"Workers URL: {workers_url}")
    
    # Create components
    anthropic_client = Anthropic(api_key=api_key)
    retriever = MLWorkersRetriever(anthropic_client, workers_url)
    
    # Test Workers health
    if retriever.workers_client.health_check():
        print("✅ Workers API is healthy")
    else:
        print("❌ Workers API health check failed")
        return
    
    # Test with sample threat
    threat = create_test_threat_characteristics()
    
    print(f"\n🎯 Testing with threat: {threat.threat_name}")
    print(f"   Type: {threat.threat_type}")
    print(f"   Attack Vectors: {', '.join(threat.attack_vectors)}")
    print(f"   Behavior Patterns: {', '.join(threat.behavior_patterns)}")
    
    # Get ML guidance
    guidance = retriever.get_ml_guidance(threat)
    
    print(f"\n🧠 ML Guidance Generated:")
    print(f"   ML Approaches: {len(guidance['ml_approaches'])}")
    print(f"   Implementation Considerations: {len(guidance['implementation_considerations'])}")
    print(f"   Source Papers: {len(guidance['source_papers'])}")
    
    if 'workers_metadata' in guidance:
        metadata = guidance['workers_metadata']
        print(f"   Workers Results: {metadata['total_results']}")
        print(f"   Retrieval Methods: {', '.join(metadata['retrieval_methods'])}")
    
    # Show details
    if guidance['ml_approaches']:
        print(f"\n📊 Top ML Approaches:")
        for i, approach in enumerate(guidance['ml_approaches'][:3], 1):
            print(f"   {i}. {approach['technique']} ({approach['source_company']})")
            print(f"      Hybrid Score: {approach.get('hybrid_score', 0):.3f}")
            print(f"      Method: {approach.get('retrieval_method', 'unknown')}")
    
    if guidance['source_papers']:
        print(f"\n📚 Source Papers:")
        for paper in guidance['source_papers'][:3]:
            print(f"   • {paper['company']} ({paper['year']}): {paper['title'][:60]}...")
    
    print(f"\n✅ Workers retrieval test complete!")


if __name__ == "__main__":
    main()