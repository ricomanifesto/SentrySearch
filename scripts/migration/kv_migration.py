"""
Cloudflare KV Migration Script for SentrySearch

Builds BM25 indices and prepares keyword search data for Cloudflare KV storage,
complementing the Pinecone vector search in the hybrid architecture.
"""

import os
import json
import time
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict
import hashlib
from datetime import datetime
import re
from collections import defaultdict, Counter
import math

from rank_bm25 import BM25Okapi
import numpy as np
from ml_knowledge_base_builder import KnowledgeBaseStorage

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class KVDocument:
    """Document optimized for Cloudflare KV storage"""
    chunk_id: str
    content: str
    enriched_content: str
    metadata: Dict[str, Any]
    search_terms: Dict[str, Any]  # BM25 terms, FAQ questions, etc.
    bm25_data: Dict[str, Any]     # TF, document length, etc.
    last_updated: str


@dataclass
class BM25TermIndex:
    """BM25 term index for keyword search"""
    term: str
    document_frequency: int
    total_documents: int
    postings_list: List[Dict[str, Any]]
    last_updated: str


@dataclass
class MetadataCache:
    """Metadata cache for fast filtering"""
    companies: List[Dict[str, Any]]
    years: List[Dict[str, Any]]
    techniques: List[Dict[str, Any]]
    last_updated: str


class TextPreprocessor:
    """Text preprocessing for BM25 indexing"""
    
    def __init__(self):
        # Common stop words for technical content
        self.stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 
            'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have',
            'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should',
            'this', 'that', 'these', 'those', 'we', 'they', 'it', 'its', 'our',
            'their', 'can', 'may', 'might', 'must', 'shall', 'from', 'into',
            'through', 'during', 'before', 'after', 'above', 'below', 'up', 'down'
        }
    
    def preprocess_text(self, text: str) -> List[str]:
        """Preprocess text into tokens for BM25"""
        if not text:
            return []
        
        # Convert to lowercase
        text = text.lower()
        
        # Replace hyphens with spaces for better tokenization
        text = re.sub(r'-', ' ', text)
        
        # Extract alphanumeric tokens (preserve underscores for technical terms)
        tokens = re.findall(r'\b[a-z0-9_]+\b', text)
        
        # Remove stop words but keep technical terms
        filtered_tokens = []
        for token in tokens:
            if len(token) >= 2 and token not in self.stop_words:
                # Keep technical terms with underscores or numbers
                if '_' in token or any(c.isdigit() for c in token) or len(token) >= 3:
                    filtered_tokens.append(token)
        
        return filtered_tokens
    
    def extract_technical_terms(self, text: str) -> List[str]:
        """Extract technical terms and acronyms"""
        technical_terms = []
        
        # Extract acronyms (2-6 uppercase letters)
        acronyms = re.findall(r'\b[A-Z]{2,6}\b', text)
        technical_terms.extend([term.lower() for term in acronyms])
        
        # Extract technical terms with specific patterns
        patterns = [
            r'\b[a-z]+_[a-z]+\b',           # snake_case
            r'\b[A-Z][a-z]+[A-Z][a-z]+\b', # CamelCase
            r'\b[a-z]+\d+\b',               # text with numbers
            r'\b\d+[a-z]+\b',               # numbers with text
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            technical_terms.extend([term.lower() for term in matches])
        
        return list(set(technical_terms))


class BM25IndexBuilder:
    """Builds BM25 indices for keyword search"""
    
    def __init__(self):
        self.preprocessor = TextPreprocessor()
        self.documents = []
        self.bm25_index = None
        self.term_document_frequency = defaultdict(int)
        self.document_lengths = []
        self.average_document_length = 0
    
    def add_document(self, doc: KVDocument):
        """Add document to BM25 index"""
        # Combine content sources for indexing
        combined_text = f"{doc.content} {doc.enriched_content}"
        
        # Add metadata terms
        metadata_text = f"{doc.metadata.get('company', '')} {doc.metadata.get('source_title', '')}"
        if doc.metadata.get('keywords'):
            if isinstance(doc.metadata['keywords'], list):
                metadata_text += " " + " ".join(doc.metadata['keywords'])
            else:
                metadata_text += " " + str(doc.metadata['keywords'])
        
        # Add search terms
        if doc.search_terms.get('bm25_terms'):
            metadata_text += " " + " ".join(doc.search_terms['bm25_terms'])
        
        if doc.search_terms.get('faq_questions'):
            metadata_text += " " + " ".join(doc.search_terms['faq_questions'])
        
        full_text = f"{combined_text} {metadata_text}"
        
        # Preprocess text
        tokens = self.preprocessor.preprocess_text(full_text)
        
        # Add technical terms
        technical_terms = self.preprocessor.extract_technical_terms(full_text)
        tokens.extend(technical_terms)
        
        # Store document data
        doc.bm25_data = {
            'tokens': tokens,
            'term_frequencies': Counter(tokens),
            'document_length': len(tokens),
            'unique_terms': len(set(tokens))
        }
        
        self.documents.append(doc)
        self.document_lengths.append(len(tokens))
        
        # Update term document frequencies
        for term in set(tokens):
            self.term_document_frequency[term] += 1
    
    def build_index(self):
        """Build the BM25 index"""
        logger.info("Building BM25 index...")
        
        # Calculate average document length
        self.average_document_length = sum(self.document_lengths) / len(self.document_lengths) if self.document_lengths else 0
        
        # Build BM25 index using rank-bm25
        tokenized_docs = [doc.bm25_data['tokens'] for doc in self.documents]
        self.bm25_index = BM25Okapi(tokenized_docs)
        
        logger.info(f"Built BM25 index with {len(self.documents)} documents")
        logger.info(f"Average document length: {self.average_document_length:.2f}")
        logger.info(f"Vocabulary size: {len(self.term_document_frequency)}")
    
    def get_term_indices(self) -> Dict[str, BM25TermIndex]:
        """Generate term indices for KV storage"""
        logger.info("Generating term indices...")
        
        term_indices = {}
        total_docs = len(self.documents)
        
        for term, doc_freq in self.term_document_frequency.items():
            postings_list = []
            
            # Find documents containing this term
            for i, doc in enumerate(self.documents):
                if term in doc.bm25_data['term_frequencies']:
                    tf = doc.bm25_data['term_frequencies'][term]
                    doc_length = doc.bm25_data['document_length']
                    
                    # Calculate BM25 score for this term in this document
                    # BM25 formula: IDF * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * (|d| / avgdl)))
                    k1, b = 1.2, 0.75  # Standard BM25 parameters
                    idf = math.log((total_docs - doc_freq + 0.5) / (doc_freq + 0.5))
                    tf_component = (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * (doc_length / self.average_document_length)))
                    bm25_score = idf * tf_component
                    
                    postings_list.append({
                        'chunk_id': doc.chunk_id,
                        'term_frequency': tf,
                        'document_length': doc_length,
                        'score': round(bm25_score, 4)
                    })
            
            # Sort by score descending
            postings_list.sort(key=lambda x: x['score'], reverse=True)
            
            term_indices[term] = BM25TermIndex(
                term=term,
                document_frequency=doc_freq,
                total_documents=total_docs,
                postings_list=postings_list,
                last_updated=datetime.now().isoformat()
            )
        
        logger.info(f"Generated {len(term_indices)} term indices")
        return term_indices
    
    def search(self, query: str, top_k: int = 10) -> List[Dict]:
        """Search using BM25 index"""
        if not self.bm25_index:
            return []
        
        query_tokens = self.preprocessor.preprocess_text(query)
        if not query_tokens:
            return []
        
        # Get BM25 scores
        scores = self.bm25_index.get_scores(query_tokens)
        
        # Get top results
        top_indices = np.argsort(scores)[::-1][:top_k]
        
        results = []
        for i in top_indices:
            if scores[i] > 0:  # Only include non-zero scores
                doc = self.documents[i]
                matched_terms = [term for term in query_tokens if term in doc.bm25_data['term_frequencies']]
                
                results.append({
                    'chunk_id': doc.chunk_id,
                    'score': float(scores[i]),
                    'matched_terms': matched_terms,
                    'metadata': doc.metadata
                })
        
        return results


class KVMigrator:
    """Handles migration to Cloudflare KV format"""
    
    def __init__(self, output_dir: str = "./kv_data"):
        self.output_dir = output_dir
        self.bm25_builder = BM25IndexBuilder()
        self.documents = []
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Migration statistics
        self.stats = {
            'total_documents': 0,
            'processed_documents': 0,
            'term_indices': 0,
            'metadata_caches': 0,
            'start_time': None,
            'end_time': None
        }
    
    def extract_chromadb_data(self, knowledge_base_path: str = "./ml_knowledge_base"):
        """Extract data from ChromaDB for KV migration"""
        logger.info("Extracting data from ChromaDB for KV migration...")
        
        knowledge_base = KnowledgeBaseStorage(knowledge_base_path)
        
        # Get current stats
        stats = knowledge_base.get_stats()
        self.stats['total_documents'] = stats['total_chunks']
        
        # Extract all documents
        results = knowledge_base.collection.get(
            include=['metadatas', 'documents']
        )
        
        for i, doc_id in enumerate(results['ids']):
            try:
                # Get data safely
                metadata = {}
                metadatas_list = results.get('metadatas')
                if metadatas_list is not None and i < len(metadatas_list):
                    metadata = metadatas_list[i]
                
                content = ""
                documents_list = results.get('documents')
                if documents_list is not None and i < len(documents_list):
                    content = documents_list[i]
                
                # Parse metadata for search terms
                search_terms = {
                    'bm25_terms': self._parse_list_field(metadata.get('bm25_terms', '')),
                    'faq_questions': self._parse_list_field(metadata.get('faq_questions', '')),
                    'keywords': self._parse_list_field(metadata.get('keywords', ''))
                }
                
                # Create KV document
                kv_doc = KVDocument(
                    chunk_id=doc_id,
                    content=content,
                    enriched_content=metadata.get('chunk_summary', ''),
                    metadata={
                        'source_title': str(metadata.get('source_title', '')),
                        'source_url': str(metadata.get('source_url', '')),
                        'company': str(metadata.get('company', '')),
                        'year': str(metadata.get('year', '')),
                        'ml_techniques': self._parse_list_field(metadata.get('ml_techniques', '')),
                        'keywords': search_terms['keywords'],
                        'chunk_summary': str(metadata.get('chunk_summary', '')),
                        'chunk_index': int(metadata.get('chunk_index', 0)),
                        'content_hash': str(metadata.get('content_hash', ''))
                    },
                    search_terms=search_terms,
                    bm25_data={},
                    last_updated=datetime.now().isoformat()
                )
                
                self.documents.append(kv_doc)
                self.bm25_builder.add_document(kv_doc)
                self.stats['processed_documents'] += 1
                
            except Exception as e:
                logger.error(f"Failed to process document {i} ({doc_id}): {e}")
                continue
        
        logger.info(f"Extracted {len(self.documents)} documents for KV migration")
    
    def _parse_list_field(self, field_value, delimiter='|') -> List[str]:
        """Parse pipe-separated field into list"""
        if isinstance(field_value, list):
            return [str(item).strip() for item in field_value if str(item).strip()]
        elif isinstance(field_value, str) and field_value:
            return [item.strip() for item in field_value.split(delimiter) if item.strip()]
        else:
            return []
    
    def build_kv_data(self):
        """Build all KV data structures"""
        logger.info("Building KV data structures...")
        
        # Build BM25 index
        self.bm25_builder.build_index()
        
        # Generate term indices
        term_indices = self.bm25_builder.get_term_indices()
        self.stats['term_indices'] = len(term_indices)
        
        # Save documents
        self._save_documents()
        
        # Save term indices
        self._save_term_indices(term_indices)
        
        # Generate and save metadata caches
        self._save_metadata_caches()
        
        # Save search test data
        self._save_search_tests()
    
    def _save_documents(self):
        """Save documents for KV storage"""
        logger.info("Saving documents for KV...")
        
        documents_file = os.path.join(self.output_dir, "kv_documents.jsonl")
        
        with open(documents_file, 'w', encoding='utf-8') as f:
            for doc in self.documents:
                # Create KV key-value pair
                kv_entry = {
                    'key': f"doc:{doc.chunk_id}",
                    'value': {
                        'chunkId': doc.chunk_id,
                        'content': doc.content,
                        'enrichedContent': doc.enriched_content,
                        'metadata': doc.metadata,
                        'searchTerms': doc.search_terms,
                        'bm25Data': {
                            'termFrequencies': dict(doc.bm25_data.get('term_frequencies', {})),
                            'documentLength': doc.bm25_data.get('document_length', 0),
                            'averageDocumentLength': self.bm25_builder.average_document_length,
                            'uniqueTerms': doc.bm25_data.get('unique_terms', 0)
                        },
                        'lastUpdated': doc.last_updated
                    }
                }
                f.write(json.dumps(kv_entry, ensure_ascii=False) + '\n')
        
        logger.info(f"Saved {len(self.documents)} documents to {documents_file}")
    
    def _save_term_indices(self, term_indices: Dict[str, BM25TermIndex]):
        """Save term indices for KV storage"""
        logger.info("Saving term indices for KV...")
        
        # Save main term indices
        terms_file = os.path.join(self.output_dir, "kv_term_indices.jsonl")
        
        with open(terms_file, 'w', encoding='utf-8') as f:
            for term, index in term_indices.items():
                kv_entry = {
                    'key': f"bm25:term:{term}",
                    'value': {
                        'term': index.term,
                        'documentFrequency': index.document_frequency,
                        'totalDocuments': index.total_documents,
                        'postingsList': index.postings_list,
                        'lastUpdated': index.last_updated
                    }
                }
                f.write(json.dumps(kv_entry, ensure_ascii=False) + '\n')
        
        # Save company-specific indices (top terms for each company)
        company_terms_file = os.path.join(self.output_dir, "kv_company_terms.jsonl")
        
        with open(company_terms_file, 'w', encoding='utf-8') as f:
            companies = set(doc.metadata['company'] for doc in self.documents if doc.metadata['company'])
            
            for company in companies:
                company_docs = [doc for doc in self.documents if doc.metadata['company'] == company]
                company_terms = defaultdict(float)
                
                # Aggregate scores for this company
                for term, index in term_indices.items():
                    for posting in index.postings_list:
                        doc = next((d for d in company_docs if d.chunk_id == posting['chunk_id']), None)
                        if doc:
                            company_terms[term] += posting['score']
                
                # Get top terms for this company
                top_terms = sorted(company_terms.items(), key=lambda x: x[1], reverse=True)[:50]
                
                kv_entry = {
                    'key': f"bm25:company:{company.lower()}",
                    'value': {
                        'company': company,
                        'topTerms': [{'term': term, 'score': score} for term, score in top_terms],
                        'documentCount': len(company_docs),
                        'lastUpdated': datetime.now().isoformat()
                    }
                }
                f.write(json.dumps(kv_entry, ensure_ascii=False) + '\n')
        
        logger.info(f"Saved {len(term_indices)} term indices")
    
    def _save_metadata_caches(self):
        """Save metadata caches for fast filtering"""
        logger.info("Saving metadata caches...")
        
        # Aggregate metadata
        companies = defaultdict(lambda: {'documentCount': 0, 'years': set(), 'techniques': set()})
        years = defaultdict(lambda: {'documentCount': 0, 'companies': set()})
        techniques = defaultdict(lambda: {'documentCount': 0, 'companies': set()})
        
        for doc in self.documents:
            company = doc.metadata['company']
            year = doc.metadata['year']
            doc_techniques = doc.metadata.get('ml_techniques', [])
            
            if company:
                companies[company]['documentCount'] += 1
                companies[company]['years'].add(year)
                companies[company]['techniques'].update(doc_techniques)
            
            if year:
                years[year]['documentCount'] += 1
                years[year]['companies'].add(company)
            
            for technique in doc_techniques:
                if technique:
                    techniques[technique]['documentCount'] += 1
                    techniques[technique]['companies'].add(company)
        
        # Save caches
        metadata_file = os.path.join(self.output_dir, "kv_metadata.jsonl")
        
        with open(metadata_file, 'w', encoding='utf-8') as f:
            # Companies cache
            companies_cache = {
                'key': 'meta:companies',
                'value': {
                    'companies': [
                        {
                            'name': name,
                            'documentCount': data['documentCount'],
                            'years': sorted(list(data['years'])),
                            'techniques': sorted(list(data['techniques']))
                        }
                        for name, data in companies.items()
                    ],
                    'lastUpdated': datetime.now().isoformat()
                }
            }
            f.write(json.dumps(companies_cache, ensure_ascii=False) + '\n')
            
            # Years cache
            years_cache = {
                'key': 'meta:years',
                'value': {
                    'years': [
                        {
                            'year': year,
                            'documentCount': data['documentCount'],
                            'companies': sorted(list(data['companies']))
                        }
                        for year, data in years.items()
                    ],
                    'lastUpdated': datetime.now().isoformat()
                }
            }
            f.write(json.dumps(years_cache, ensure_ascii=False) + '\n')
            
            # Techniques cache
            techniques_cache = {
                'key': 'meta:techniques',
                'value': {
                    'techniques': [
                        {
                            'name': name,
                            'documentCount': data['documentCount'],
                            'companies': sorted(list(data['companies']))
                        }
                        for name, data in techniques.items()
                    ],
                    'lastUpdated': datetime.now().isoformat()
                }
            }
            f.write(json.dumps(techniques_cache, ensure_ascii=False) + '\n')
        
        self.stats['metadata_caches'] = 3
        logger.info("Saved metadata caches")
    
    def _save_search_tests(self):
        """Save search test data"""
        logger.info("Saving search test data...")
        
        test_queries = [
            "Netflix anomaly detection machine learning",
            "fraud detection isolation forest",
            "Cloudflare bot detection",
            "graph neural networks",
            "behavioral analysis"
        ]
        
        test_results = []
        for query in test_queries:
            results = self.bm25_builder.search(query, top_k=5)
            test_results.append({
                'query': query,
                'results': results,
                'result_count': len(results)
            })
        
        # Save test results
        test_file = os.path.join(self.output_dir, "search_test_results.json")
        with open(test_file, 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved search test results for {len(test_queries)} queries")
    
    def run_migration(self) -> bool:
        """Run the complete KV migration"""
        logger.info("Starting ChromaDB to Cloudflare KV migration...")
        self.stats['start_time'] = datetime.now()
        
        try:
            # Extract data from ChromaDB
            self.extract_chromadb_data()
            
            # Build KV data structures
            self.build_kv_data()
            
            self.stats['end_time'] = datetime.now()
            duration = self.stats['end_time'] - self.stats['start_time']
            
            # Print final stats
            logger.info("KV migration completed!")
            logger.info(f"Duration: {duration}")
            logger.info(f"Total documents: {self.stats['total_documents']}")
            logger.info(f"Processed: {self.stats['processed_documents']}")
            logger.info(f"Term indices: {self.stats['term_indices']}")
            logger.info(f"Metadata caches: {self.stats['metadata_caches']}")
            logger.info(f"Output directory: {self.output_dir}")
            
            return True
            
        except Exception as e:
            logger.error(f"KV migration failed: {e}")
            self.stats['end_time'] = datetime.now()
            return False


def main():
    """Main migration function"""
    
    print("🚀 Starting SentrySearch ChromaDB to Cloudflare KV Migration")
    print("=" * 60)
    
    # Run migration
    migrator = KVMigrator()
    success = migrator.run_migration()
    
    if success:
        print("\n✅ KV Migration completed successfully!")
        print("📁 Output files generated:")
        print("  • kv_documents.jsonl - Document data for KV")
        print("  • kv_term_indices.jsonl - BM25 term indices")
        print("  • kv_company_terms.jsonl - Company-specific terms")
        print("  • kv_metadata.jsonl - Metadata caches")
        print("  • search_test_results.json - Search validation")
        print("\n🔄 Next steps:")
        print("  1. Upload KV data to Cloudflare")
        print("  2. Implement Workers functions")
        print("  3. Test hybrid search")
    else:
        print("\n❌ KV Migration failed!")
        print("🔍 Check logs for details")


if __name__ == "__main__":
    main()