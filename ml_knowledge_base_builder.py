"""
ML Knowledge Base Builder for SentrySearch

Builds a production-ready knowledge base from curated ML anomaly detection papers
and blog posts. Implements Agentic RAG approach with intelligent content processing.

Features:
- Real content ingestion from URLs
- LLM-powered content enrichment
- Persistent ChromaDB storage
- Question-like chunk processing
- Production-ready error handling
"""

import os
import json
import time
import random
import hashlib
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import logging
from pathlib import Path

import requests
from bs4 import BeautifulSoup
import chromadb
from chromadb.config import Settings
from anthropic import Anthropic
import anthropic
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class MLPaperSource:
    """Represents a source ML paper or blog post"""
    title: str
    url: str
    company: str
    year: str
    description: str
    ml_techniques: List[str]


@dataclass
class EnrichedChunk:
    """Represents a processed and enriched document chunk"""
    chunk_id: str
    source_title: str
    source_url: str
    company: str
    year: str
    original_content: str
    enriched_content: str  # Question-like format
    ml_techniques: List[str]
    chunk_summary: str
    keywords: List[str]
    chunk_index: int
    content_hash: str
    bm25_terms: List[str] = None  # Additional search terms for BM25
    faq_questions: List[str] = None  # FAQ-style questions


class ContentExtractor:
    """Extracts and cleans content from web pages"""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        })
    
    def extract_from_url(self, url: str) -> Optional[str]:
        """Extract clean text content from a URL"""
        try:
            logger.info(f"Extracting content from: {url}")
            
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove unwanted elements
            for element in soup(['script', 'style', 'nav', 'header', 'footer', 'aside']):
                element.decompose()
            
            # Extract main content
            content = self._extract_main_content(soup)
            
            # Clean and normalize text
            cleaned_content = self._clean_text(content)
            
            logger.info(f"Extracted {len(cleaned_content)} characters from {url}")
            return cleaned_content
            
        except requests.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Content extraction failed for {url}: {e}")
            return None
    
    def _extract_main_content(self, soup: BeautifulSoup) -> str:
        """Extract main content from parsed HTML"""
        
        # Try common article selectors
        content_selectors = [
            'article',
            '[role="main"]',
            '.post-content',
            '.article-content',
            '.entry-content',
            '.content',
            'main'
        ]
        
        for selector in content_selectors:
            content_elem = soup.select_one(selector)
            if content_elem:
                return content_elem.get_text()
        
        # Fallback to body content
        body = soup.find('body')
        return body.get_text() if body else soup.get_text()
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize extracted text"""
        # Remove extra whitespace
        lines = [line.strip() for line in text.split('\n')]
        lines = [line for line in lines if line]
        
        # Join lines and normalize spaces
        cleaned = ' '.join(lines)
        cleaned = ' '.join(cleaned.split())
        
        return cleaned


class ContentEnricher:
    """Enriches content using LLM-powered processing"""
    
    def __init__(self, anthropic_client):
        self.client = anthropic_client
    
    def _api_call_with_retry(self, **kwargs):
        """Make API call with intelligent retry logic using retry-after header"""
        max_retries = 3
        base_delay = 5
        
        for attempt in range(max_retries):
            try:
                print(f"DEBUG: Content Enricher API call attempt {attempt + 1}/{max_retries}")
                return self.client.messages.create(**kwargs)
                
            except anthropic.RateLimitError as e:
                if attempt == max_retries - 1:
                    print(f"DEBUG: Content Enricher rate limit exceeded after {max_retries} attempts")
                    raise e
                
                # Check if the error response has retry-after information
                retry_after = None
                if hasattr(e, 'response') and e.response:
                    retry_after_header = e.response.headers.get('retry-after')
                    if retry_after_header:
                        try:
                            retry_after = float(retry_after_header)
                            print(f"DEBUG: Content Enricher API provided retry-after: {retry_after} seconds")
                        except (ValueError, TypeError):
                            pass
                
                # Use retry-after if available, otherwise exponential backoff
                if retry_after:
                    delay = retry_after + random.uniform(1, 3)
                else:
                    delay = base_delay * (2 ** attempt) + random.uniform(1, 5)
                    delay = min(delay, 120)
                
                print(f"DEBUG: Content Enricher rate limit hit. Waiting {delay:.1f} seconds before retry {attempt + 2}")
                time.sleep(delay)
                
            except Exception as e:
                print(f"DEBUG: Content Enricher non-rate-limit error: {e}")
                raise e
    
    def enrich_chunk(self, chunk: str, source: MLPaperSource) -> Dict[str, str]:
        """Enrich a chunk with summary, keywords, question-like format, and BM25-optimized metadata"""
        
        prompt = f"""
Analyze this text chunk from a machine learning anomaly detection paper/blog and provide:

1. QUESTION_FORMAT: Rewrite the chunk content as if it's answering questions about the ML approach
2. SUMMARY: A 2-line summary of what this chunk covers
3. KEYWORDS: 5-8 relevant technical keywords (comma-separated)
4. BM25_TERMS: Additional search terms for BM25 retrieval (comma-separated, include variations, synonyms, acronyms)
5. FAQ_QUESTIONS: 2-3 potential questions this chunk could answer (pipe-separated)

Source Context:
- Company: {source.company}
- ML Techniques: {', '.join(source.ml_techniques)}
- Year: {source.year}

Text Chunk:
{chunk[:1500]}

Format your response as:
QUESTION_FORMAT: [rewritten content]
SUMMARY: [summary]
KEYWORDS: [keywords]
BM25_TERMS: [search terms with variations]
FAQ_QUESTIONS: [question1|question2|question3]
"""
        
        try:
            response = self._api_call_with_retry(
                model="claude-sonnet-4-20250514",
                max_tokens=800,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Safe access to response content
            if not response.content or len(response.content) == 0:
                raise ValueError("Empty response from content enrichment API")
            
            if not hasattr(response.content[0], 'text'):
                raise ValueError("Response content missing text attribute")
            
            content = response.content[0].text.strip()
            return self._parse_enrichment_response(content)
            
        except Exception as e:
            logger.error(f"Content enrichment failed: {e}")
            # Return fallback enrichment
            return {
                'question_format': chunk,
                'summary': f"Content about {source.ml_techniques[0]} implementation at {source.company}",
                'keywords': ', '.join(source.ml_techniques + [source.company.lower(), 'anomaly detection']),
                'bm25_terms': ', '.join(source.ml_techniques + [source.company.lower(), 'ml', 'detection', 'analysis']),
                'faq_questions': f"How does {source.company} implement {source.ml_techniques[0]}?|What is {source.ml_techniques[0]} used for?"
            }
    
    def _parse_enrichment_response(self, response: str) -> Dict[str, str]:
        """Parse LLM response into structured enrichment data"""
        result = {
            'question_format': '',
            'summary': '',
            'keywords': '',
            'bm25_terms': '',
            'faq_questions': ''
        }
        
        lines = response.split('\n')
        current_field = None
        
        for line in lines:
            line = line.strip()
            if line.startswith('QUESTION_FORMAT:'):
                current_field = 'question_format'
                result[current_field] = line.replace('QUESTION_FORMAT:', '').strip()
            elif line.startswith('SUMMARY:'):
                current_field = 'summary'
                result[current_field] = line.replace('SUMMARY:', '').strip()
            elif line.startswith('KEYWORDS:'):
                current_field = 'keywords'
                result[current_field] = line.replace('KEYWORDS:', '').strip()
            elif line.startswith('BM25_TERMS:'):
                current_field = 'bm25_terms'
                result[current_field] = line.replace('BM25_TERMS:', '').strip()
            elif line.startswith('FAQ_QUESTIONS:'):
                current_field = 'faq_questions'
                result[current_field] = line.replace('FAQ_QUESTIONS:', '').strip()
            elif current_field and line:
                result[current_field] += ' ' + line
        
        return result


class DocumentProcessor:
    """Processes documents into enriched chunks"""
    
    def __init__(self, content_enricher: ContentEnricher, chunk_size: int = 800):
        self.enricher = content_enricher
        self.chunk_size = chunk_size
    
    def process_document(self, source: MLPaperSource, content: str) -> List[EnrichedChunk]:
        """Process a document into enriched chunks"""
        
        if not content or len(content) < 100:
            logger.warning(f"Content too short for {source.title}")
            return []
        
        # Create chunks
        chunks = self._create_chunks(content, source)
        
        # Enrich each chunk
        enriched_chunks = []
        for i, chunk_content in enumerate(chunks):
            
            # Generate content hash for deduplication
            content_hash = hashlib.md5(chunk_content.encode()).hexdigest()
            
            # Enrich with LLM
            enrichment = self.enricher.enrich_chunk(chunk_content, source)
            
            chunk = EnrichedChunk(
                chunk_id=f"{source.company}_{source.year}_{i}_{content_hash[:8]}",
                source_title=source.title,
                source_url=source.url,
                company=source.company,
                year=source.year,
                original_content=chunk_content,
                enriched_content=enrichment['question_format'],
                ml_techniques=source.ml_techniques,
                chunk_summary=enrichment['summary'],
                keywords=enrichment['keywords'].split(', ') if enrichment['keywords'] else [],
                chunk_index=i,
                content_hash=content_hash
            )
            
            # Add BM25-specific metadata to chunk
            chunk.bm25_terms = enrichment.get('bm25_terms', '').split(', ') if enrichment.get('bm25_terms') else []
            chunk.faq_questions = enrichment.get('faq_questions', '').split('|') if enrichment.get('faq_questions') else []
            
            enriched_chunks.append(chunk)
            
            # Rate limiting for API calls
            time.sleep(0.5)
        
        logger.info(f"Processed {len(enriched_chunks)} chunks for {source.title}")
        return enriched_chunks
    
    def _create_chunks(self, content: str, source: MLPaperSource) -> List[str]:
        """Create overlapping chunks from content"""
        chunks = []
        overlap = self.chunk_size // 4  # 25% overlap
        
        for i in range(0, len(content), self.chunk_size - overlap):
            chunk = content[i:i + self.chunk_size]
            
            # Skip very short chunks
            if len(chunk) < 200:
                continue
            
            # Try to break at sentence boundaries
            if i + self.chunk_size < len(content):
                last_period = chunk.rfind('.')
                if last_period > len(chunk) * 0.7:  # If period is in last 30%
                    chunk = chunk[:last_period + 1]
            
            chunks.append(chunk.strip())
        
        return chunks


class KnowledgeBaseStorage:
    """Manages persistent storage of the knowledge base"""
    
    def __init__(self, storage_path: str = "./ml_knowledge_base"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        # Initialize ChromaDB with persistent storage
        self.chroma_client = chromadb.PersistentClient(
            path=str(self.storage_path / "chroma_db")
        )
        
        self.collection_name = "ml_anomaly_detection"
        self.collection = None
        self._initialize_collection()
    
    def _initialize_collection(self):
        """Initialize or get existing collection"""
        try:
            # Try to get existing collection
            self.collection = self.chroma_client.get_collection(self.collection_name)
            logger.info(f"Loaded existing collection with {self.collection.count()} documents")
        except:
            # Create new collection
            self.collection = self.chroma_client.create_collection(
                name=self.collection_name,
                metadata={"description": "ML Anomaly Detection Knowledge Base"}
            )
            logger.info("Created new collection")
    
    def add_chunks(self, chunks: List[EnrichedChunk]) -> bool:
        """Add enriched chunks to the knowledge base"""
        try:
            if not chunks:
                return True
            
            # Prepare data for ChromaDB
            documents = []
            metadatas = []
            ids = []
            
            for chunk in chunks:
                # Create enriched document text
                document_text = f"""
Title: {chunk.source_title}
Company: {chunk.company}
Year: {chunk.year}
ML Techniques: {', '.join(chunk.ml_techniques)}
Keywords: {', '.join(chunk.keywords)}
Summary: {chunk.chunk_summary}

Content: {chunk.enriched_content}
                """.strip()
                
                documents.append(document_text)
                metadatas.append({
                    'source_title': chunk.source_title,
                    'source_url': chunk.source_url,
                    'company': chunk.company,
                    'year': chunk.year,
                    'ml_techniques': '|'.join(chunk.ml_techniques),
                    'keywords': '|'.join(chunk.keywords),
                    'chunk_summary': chunk.chunk_summary,
                    'chunk_index': chunk.chunk_index,
                    'content_hash': chunk.content_hash,
                    'bm25_terms': '|'.join(chunk.bm25_terms) if chunk.bm25_terms else '',
                    'faq_questions': '|'.join(chunk.faq_questions) if chunk.faq_questions else ''
                })
                ids.append(chunk.chunk_id)
            
            # Add to ChromaDB
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
            # Save chunk details as JSON backup
            self._save_chunks_backup(chunks)
            
            logger.info(f"Added {len(chunks)} chunks to knowledge base")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add chunks to knowledge base: {e}")
            return False
    
    def _save_chunks_backup(self, chunks: List[EnrichedChunk]):
        """Save chunk details as JSON backup"""
        backup_file = self.storage_path / "chunks_backup.jsonl"
        
        with open(backup_file, 'a', encoding='utf-8') as f:
            for chunk in chunks:
                f.write(json.dumps(asdict(chunk), ensure_ascii=False) + '\n')
    
    def get_stats(self) -> Dict:
        """Get knowledge base statistics"""
        try:
            count = self.collection.count()
            
            # Get unique companies and years
            if count > 0:
                results = self.collection.get(include=['metadatas'])
                companies = set()
                years = set()
                ml_techniques = set()
                
                for metadata in results['metadatas']:
                    companies.add(metadata.get('company', ''))
                    years.add(metadata.get('year', ''))
                    techniques = metadata.get('ml_techniques', '').split('|')
                    ml_techniques.update([t for t in techniques if t])
                
                return {
                    'total_chunks': count,
                    'companies': sorted(list(companies)),
                    'years': sorted(list(years)),
                    'ml_techniques': sorted(list(ml_techniques)),
                    'storage_path': str(self.storage_path)
                }
            else:
                return {
                    'total_chunks': 0,
                    'companies': [],
                    'years': [],
                    'ml_techniques': [],
                    'storage_path': str(self.storage_path)
                }
                
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {'error': str(e)}
    
    def search(self, query: str, n_results: int = 10) -> List[Dict]:
        """Search the knowledge base"""
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results,
                include=['documents', 'metadatas', 'distances']
            )
            
            search_results = []
            for i, doc in enumerate(results['documents'][0]):
                search_results.append({
                    'document': doc,
                    'metadata': results['metadatas'][0][i],
                    'distance': results['distances'][0][i],
                    'score': 1 / (1 + results['distances'][0][i])  # Convert distance to similarity
                })
            
            return search_results
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []


def get_curated_ml_sources() -> List[MLPaperSource]:
    """Get the curated list of ML anomaly detection sources"""
    
    sources = [
        MLPaperSource(
            title="Detecting Performance Anomalies in External Firmware Deployments",
            url="https://netflixtechblog.com/detecting-performance-anomalies-in-external-firmware-deployments-ed41b1bfcf46",
            company="Netflix",
            year="2019",
            description="Netflix's approach to detecting anomalies in firmware performance using ML",
            ml_techniques=["statistical_analysis", "anomaly_detection", "performance_monitoring"]
        ),
        MLPaperSource(
            title="Detecting and Preventing Abuse on LinkedIn using Isolation Forests",
            url="https://engineering.linkedin.com/blog/2019/isolation-forest",
            company="LinkedIn",
            year="2019",
            description="LinkedIn's implementation of isolation forests for abuse detection",
            ml_techniques=["isolation_forest", "unsupervised_learning", "abuse_detection"]
        ),
        MLPaperSource(
            title="How Does Spam Protection Work on Stack Exchange?",
            url="https://stackoverflow.blog/2020/06/25/how-does-spam-protection-work-on-stack-exchange/",
            company="Stack Exchange",
            year="2020",
            description="Stack Exchange's ML-based spam detection system",
            ml_techniques=["text_classification", "nlp", "spam_detection"]
        ),
        MLPaperSource(
            title="Blocking Slack Invite Spam With Machine Learning",
            url="https://slack.engineering/blocking-slack-invite-spam-with-machine-learning/",
            company="Slack",
            year="2020",
            description="Slack's ML approach to preventing invite spam",
            ml_techniques=["classification", "feature_engineering", "spam_detection"]
        ),
        MLPaperSource(
            title="Cloudflare Bot Management: Machine Learning and More",
            url="https://blog.cloudflare.com/cloudflare-bot-management-machine-learning-and-more/",
            company="Cloudflare",
            year="2020",
            description="Cloudflare's ML-powered bot detection and management",
            ml_techniques=["behavioral_analysis", "traffic_analysis", "bot_detection"]
        ),
        MLPaperSource(
            title="Graph for Fraud Detection",
            url="https://engineering.grab.com/graph-for-fraud-detection",
            company="Grab",
            year="2022",
            description="Grab's graph-based approach to fraud detection",
            ml_techniques=["graph_ml", "fraud_detection", "network_analysis"]
        ),
        MLPaperSource(
            title="Machine Learning for Fraud Detection in Streaming Services",
            url="https://netflixtechblog.com/machine-learning-for-fraud-detection-in-streaming-services-b0b4ef3be3f6",
            company="Netflix",
            year="2023",
            description="Netflix's ML approach to detecting fraud in streaming services",
            ml_techniques=["fraud_detection", "streaming_analytics", "behavioral_analysis"]
        ),
        MLPaperSource(
            title="Data Generation and Sampling Strategies",
            url="https://blog.cloudflare.com/data-generation-and-sampling-strategies/",
            company="Cloudflare",
            year="2023",
            description="Cloudflare's data generation and sampling strategies for ML training",
            ml_techniques=["data_generation", "sampling", "training_data"]
        ),
        MLPaperSource(
            title="Machine Learning Mobile Traffic Bots",
            url="https://blog.cloudflare.com/machine-learning-mobile-traffic-bots/",
            company="Cloudflare",
            year="2023",
            description="Cloudflare's ML approach to detecting mobile traffic bots",
            ml_techniques=["bot_detection", "mobile_traffic", "behavioral_analysis"]
        ),
        MLPaperSource(
            title="Project Radar: Intelligent Early Fraud Detection",
            url="https://www.uber.com/blog/project-radar-intelligent-early-fraud-detection/",
            company="Uber",
            year="2023",
            description="Uber's Project Radar for intelligent early fraud detection",
            ml_techniques=["fraud_detection", "early_detection", "real_time_ml"]
        )
    ]
    
    return sources


def main():
    """Main function to build the ML knowledge base"""
    
    # Initialize components
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        logger.error("ANTHROPIC_API_KEY environment variable not set")
        return
    
    print("🔨 Building ML Anomaly Detection Knowledge Base")
    print("=" * 50)
    
    # Initialize components
    anthropic_client = Anthropic(api_key=api_key)
    content_extractor = ContentExtractor()
    content_enricher = ContentEnricher(anthropic_client)
    document_processor = DocumentProcessor(content_enricher)
    knowledge_base = KnowledgeBaseStorage()
    
    # Get current stats
    current_stats = knowledge_base.get_stats()
    print(f"📊 Current knowledge base: {current_stats['total_chunks']} chunks")
    
    # Get sources to process
    sources = get_curated_ml_sources()
    print(f"📚 Processing {len(sources)} ML sources...")
    
    # Process each source
    total_chunks_added = 0
    successful_sources = 0
    
    for i, source in enumerate(sources, 1):
        print(f"\n🔄 [{i}/{len(sources)}] Processing: {source.title}")
        print(f"   Company: {source.company} | Year: {source.year}")
        
        # Extract content
        content = content_extractor.extract_from_url(source.url)
        
        if not content:
            print(f"   ❌ Failed to extract content")
            continue
        
        print(f"   📝 Extracted {len(content):,} characters")
        
        # Process into chunks
        chunks = document_processor.process_document(source, content)
        
        if not chunks:
            print(f"   ❌ No chunks generated")
            continue
        
        print(f"   🧩 Generated {len(chunks)} chunks")
        
        # Add to knowledge base
        if knowledge_base.add_chunks(chunks):
            total_chunks_added += len(chunks)
            successful_sources += 1
            print(f"   ✅ Added to knowledge base")
        else:
            print(f"   ❌ Failed to add to knowledge base")
    
    # Final stats
    print(f"\n🎉 Knowledge Base Build Complete!")
    print("=" * 50)
    print(f"Sources processed: {successful_sources}/{len(sources)}")
    print(f"Total chunks added: {total_chunks_added}")
    
    final_stats = knowledge_base.get_stats()
    print(f"Final knowledge base size: {final_stats['total_chunks']} chunks")
    print(f"Companies: {', '.join(final_stats['companies'])}")
    print(f"Years: {', '.join(final_stats['years'])}")
    print(f"Storage location: {final_stats['storage_path']}")
    
    # Test search
    print(f"\n🔍 Testing search functionality...")
    test_queries = [
        "How does Netflix detect performance anomalies?",
        "What ML techniques work for fraud detection?",
        "Isolation forest implementation details"
    ]
    
    for query in test_queries:
        results = knowledge_base.search(query, n_results=3)
        print(f"\nQuery: '{query}'")
        print(f"Results: {len(results)} found")
        if results:
            top_result = results[0]
            print(f"Top match: {top_result['metadata']['company']} - {top_result['metadata']['source_title'][:60]}...")
            print(f"Score: {top_result['score']:.3f}")


if __name__ == "__main__":
    main()