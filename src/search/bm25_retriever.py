"""
BM25 Retriever for SentrySearch

Implements BM25-based retrieval with enriched metadata support for the agentic RAG system.
Provides complementary keyword-based retrieval alongside vector search for enhanced precision.

Features:
- BM25 algorithm for exact keyword matching
- Enriched metadata indexing (summaries, FAQs, keywords)
- Integration with existing knowledge base
- Result scoring and ranking
- Efficient document preprocessing
"""

import os
import json
import logging
import time
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from pathlib import Path
import re
import pickle

from rank_bm25 import BM25Okapi
import numpy as np
from data.ml_knowledge_base_builder import KnowledgeBaseStorage

logger = logging.getLogger(__name__)


@dataclass
class BM25Document:
    """Represents a document optimized for BM25 retrieval"""
    doc_id: str
    content: str
    enriched_content: str  # Enhanced with metadata
    metadata: Dict
    keywords: List[str]
    summary: str
    preprocessed_tokens: List[str]


@dataclass
class BM25SearchResult:
    """Represents a BM25 search result"""
    doc_id: str
    content: str
    metadata: Dict
    bm25_score: float
    matched_terms: List[str]
    relevance_score: float  # Normalized score


class BM25Preprocessor:
    """Preprocesses documents for BM25 indexing"""
    
    def __init__(self):
        # Common stopwords for technical content
        self.stopwords = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 
            'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
            'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
            'should', 'may', 'might', 'can', 'this', 'that', 'these', 'those',
            'i', 'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them'
        }
    
    def preprocess_text(self, text: str) -> List[str]:
        """Preprocess text for BM25 indexing"""
        if not text:
            return []
        
        # Convert to lowercase
        text = text.lower()
        
        # Keep technical terms and alphanumeric sequences
        # Split on whitespace and punctuation but preserve underscores and hyphens in technical terms
        tokens = re.findall(r'\b[a-zA-Z0-9_-]+\b', text)
        
        # Filter tokens
        filtered_tokens = []
        for token in tokens:
            # Skip stopwords
            if token in self.stopwords:
                continue
            
            # Skip very short tokens unless they're technical (like ML, AI, etc.)
            if len(token) < 2 and not token.isupper():
                continue
            
            # Skip very long tokens (likely noise)
            if len(token) > 50:
                continue
            
            filtered_tokens.append(token)
        
        return filtered_tokens
    
    def create_enriched_content(self, chunk_data: Dict) -> str:
        """Create enriched content optimized for BM25 search"""
        content_parts = []
        
        # Original content
        if chunk_data.get('enriched_content'):
            content_parts.append(chunk_data['enriched_content'])
        
        # Add weighted metadata
        metadata = chunk_data.get('metadata', {})
        
        # Company name (high weight)
        if company := metadata.get('company'):
            content_parts.append(f"{company} {company} {company}")  # Triple weight
        
        # ML techniques (high weight)
        if ml_techniques := metadata.get('ml_techniques'):
            techniques = ml_techniques.split('|') if isinstance(ml_techniques, str) else []
            for technique in techniques:
                if technique.strip():
                    # Double weight for techniques
                    content_parts.append(f"{technique} {technique}")
        
        # Keywords (medium weight)
        if keywords := metadata.get('keywords'):
            keyword_list = keywords.split('|') if isinstance(keywords, str) else []
            content_parts.extend(keyword_list)
        
        # Summary (medium weight)
        if summary := metadata.get('chunk_summary'):
            content_parts.append(summary)
        
        # Source title (medium weight)
        if title := metadata.get('source_title'):
            content_parts.append(title)
        
        return ' '.join(content_parts)


class BM25Retriever:
    """BM25-based retriever with enriched metadata support"""
    
    def __init__(self, knowledge_base: KnowledgeBaseStorage, 
                 storage_path: str = "./ml_knowledge_base"):
        self.knowledge_base = knowledge_base
        self.storage_path = Path(storage_path)
        self.preprocessor = BM25Preprocessor()
        
        # BM25 components
        self.bm25_index = None
        self.documents = []
        self.doc_lookup = {}  # doc_id -> document mapping
        
        # Storage files
        self.bm25_cache_file = self.storage_path / "bm25_index.pkl"
        self.docs_cache_file = self.storage_path / "bm25_documents.json"
        
        # Initialize
        self._initialize_bm25_index()
    
    def _initialize_bm25_index(self):
        """Initialize or load existing BM25 index"""
        try:
            # Try to load cached index
            if self._load_cached_index():
                logger.info(f"Loaded cached BM25 index with {len(self.documents)} documents")
                return
            
            # Build new index
            logger.info("Building new BM25 index...")
            self._build_bm25_index()
            
        except Exception as e:
            logger.error(f"Failed to initialize BM25 index: {e}")
            self.bm25_index = None
            self.documents = []
    
    def _load_cached_index(self) -> bool:
        """Load cached BM25 index if available"""
        if not (self.bm25_cache_file.exists() and self.docs_cache_file.exists()):
            return False
        
        try:
            # Load BM25 index
            with open(self.bm25_cache_file, 'rb') as f:
                self.bm25_index = pickle.load(f)
            
            # Load documents
            with open(self.docs_cache_file, 'r', encoding='utf-8') as f:
                docs_data = json.load(f)
            
            # Reconstruct documents
            self.documents = []
            self.doc_lookup = {}
            
            for doc_data in docs_data:
                doc = BM25Document(**doc_data)
                self.documents.append(doc)
                self.doc_lookup[doc.doc_id] = doc
            
            return True
            
        except Exception as e:
            logger.warning(f"Failed to load cached BM25 index: {e}")
            return False
    
    def _build_bm25_index(self):
        """Build BM25 index from knowledge base"""
        try:
            # Get all documents from ChromaDB
            results = self.knowledge_base.collection.get(
                include=['documents', 'metadatas']
            )
            
            if not results['ids']:
                logger.warning("No documents found in knowledge base")
                return
            
            logger.info(f"Processing {len(results['ids'])} documents for BM25 indexing...")
            
            # Process each document
            bm25_documents = []
            tokenized_docs = []
            
            for i, doc_id in enumerate(results['ids']):
                try:
                    # Create enriched content for BM25
                    chunk_data = {
                        'enriched_content': results['documents'][i],
                        'metadata': results['metadatas'][i]
                    }
                    
                    enriched_content = self.preprocessor.create_enriched_content(chunk_data)
                    
                    # Preprocess for BM25
                    tokens = self.preprocessor.preprocess_text(enriched_content)
                    
                    if not tokens:  # Skip empty documents
                        continue
                    
                    # Create BM25 document
                    bm25_doc = BM25Document(
                        doc_id=doc_id,
                        content=results['documents'][i],
                        enriched_content=enriched_content,
                        metadata=results['metadatas'][i],
                        keywords=results['metadatas'][i].get('keywords', '').split('|'),
                        summary=results['metadatas'][i].get('chunk_summary', ''),
                        preprocessed_tokens=tokens
                    )
                    
                    bm25_documents.append(bm25_doc)
                    tokenized_docs.append(tokens)
                    
                except Exception as e:
                    logger.warning(f"Failed to process document {doc_id}: {e}")
                    continue
            
            if not bm25_documents:
                logger.error("No valid documents processed for BM25")
                return
            
            # Build BM25 index
            logger.info(f"Building BM25 index with {len(bm25_documents)} documents...")
            self.bm25_index = BM25Okapi(tokenized_docs)
            self.documents = bm25_documents
            
            # Create lookup dictionary
            self.doc_lookup = {doc.doc_id: doc for doc in self.documents}
            
            # Cache the index
            self._cache_bm25_index()
            
            logger.info(f"BM25 index built successfully with {len(self.documents)} documents")
            
        except Exception as e:
            logger.error(f"Failed to build BM25 index: {e}")
            self.bm25_index = None
            self.documents = []
    
    def _cache_bm25_index(self):
        """Cache BM25 index to disk"""
        try:
            # Cache BM25 index
            with open(self.bm25_cache_file, 'wb') as f:
                pickle.dump(self.bm25_index, f)
            
            # Cache documents (convert to JSON-serializable format)
            docs_data = []
            for doc in self.documents:
                doc_dict = {
                    'doc_id': doc.doc_id,
                    'content': doc.content,
                    'enriched_content': doc.enriched_content,
                    'metadata': doc.metadata,
                    'keywords': doc.keywords,
                    'summary': doc.summary,
                    'preprocessed_tokens': doc.preprocessed_tokens
                }
                docs_data.append(doc_dict)
            
            with open(self.docs_cache_file, 'w', encoding='utf-8') as f:
                json.dump(docs_data, f, ensure_ascii=False, indent=2)
            
            logger.info("BM25 index cached successfully")
            
        except Exception as e:
            logger.warning(f"Failed to cache BM25 index: {e}")
    
    def search(self, query: str, n_results: int = 10, 
               min_score: float = 0.0) -> List[BM25SearchResult]:
        """Search using BM25 algorithm"""
        if not self.bm25_index or not self.documents:
            logger.warning("BM25 index not available")
            return []
        
        try:
            # Preprocess query
            query_tokens = self.preprocessor.preprocess_text(query)
            
            if not query_tokens:
                logger.warning("No valid tokens in query")
                return []
            
            # Get BM25 scores
            scores = self.bm25_index.get_scores(query_tokens)
            
            # Create results with scores
            results = []
            for i, score in enumerate(scores):
                if score <= min_score:
                    continue
                
                doc = self.documents[i]
                
                # Find matched terms
                matched_terms = self._find_matched_terms(query_tokens, doc.preprocessed_tokens)
                
                # Calculate relevance score (normalized)
                relevance_score = min(score / 10.0, 1.0)  # Normalize to 0-1 range
                
                result = BM25SearchResult(
                    doc_id=doc.doc_id,
                    content=doc.content,
                    metadata=doc.metadata,
                    bm25_score=score,
                    matched_terms=matched_terms,
                    relevance_score=relevance_score
                )
                
                results.append(result)
            
            # Sort by BM25 score (descending)
            results.sort(key=lambda x: x.bm25_score, reverse=True)
            
            # Return top N results
            return results[:n_results]
            
        except Exception as e:
            logger.error(f"BM25 search failed: {e}")
            return []
    
    def _find_matched_terms(self, query_tokens: List[str], doc_tokens: List[str]) -> List[str]:
        """Find which query terms matched in the document"""
        doc_token_set = set(doc_tokens)
        matched = [token for token in query_tokens if token in doc_token_set]
        return matched
    
    def get_stats(self) -> Dict:
        """Get BM25 retriever statistics"""
        return {
            'total_documents': len(self.documents),
            'index_available': self.bm25_index is not None,
            'cache_files_exist': {
                'index': self.bm25_cache_file.exists(),
                'documents': self.docs_cache_file.exists()
            },
            'storage_path': str(self.storage_path)
        }
    
    def rebuild_index(self):
        """Force rebuild of BM25 index"""
        logger.info("Rebuilding BM25 index...")
        
        # Clear existing index
        self.bm25_index = None
        self.documents = []
        self.doc_lookup = {}
        
        # Remove cache files
        try:
            if self.bm25_cache_file.exists():
                self.bm25_cache_file.unlink()
            if self.docs_cache_file.exists():
                self.docs_cache_file.unlink()
        except Exception as e:
            logger.warning(f"Failed to remove cache files: {e}")
        
        # Rebuild
        self._build_bm25_index()


def main():
    """Test the BM25 retriever"""
    
    print("🔍 Testing BM25 Retriever")
    print("=" * 40)
    
    # Initialize knowledge base and BM25 retriever
    knowledge_base = KnowledgeBaseStorage()
    bm25_retriever = BM25Retriever(knowledge_base)
    
    # Get stats
    stats = bm25_retriever.get_stats()
    print(f"📊 BM25 Index Stats:")
    print(f"   Documents: {stats['total_documents']}")
    print(f"   Index Available: {stats['index_available']}")
    
    if not stats['index_available']:
        print("❌ BM25 index not available")
        return
    
    # Test queries
    test_queries = [
        "Netflix anomaly detection",
        "isolation forest LinkedIn",
        "fraud detection machine learning",
        "bot detection Cloudflare",
        "spam classification",
        "graph neural networks"
    ]
    
    print(f"\n🔍 Testing BM25 Search:")
    for query in test_queries:
        print(f"\nQuery: '{query}'")
        
        results = bm25_retriever.search(query, n_results=3)
        print(f"Results: {len(results)} found")
        
        for i, result in enumerate(results, 1):
            company = result.metadata.get('company', 'Unknown')
            title = result.metadata.get('source_title', 'No title')[:50]
            print(f"  {i}. {company} - {title}...")
            print(f"     BM25 Score: {result.bm25_score:.3f}")
            print(f"     Matched Terms: {', '.join(result.matched_terms[:5])}")
    
    print(f"\n✅ BM25 retriever test complete!")


if __name__ == "__main__":
    main()