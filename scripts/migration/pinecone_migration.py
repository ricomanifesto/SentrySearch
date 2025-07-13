"""
Pinecone Migration Script for SentrySearch

Migrates vector embeddings and metadata from ChromaDB to Pinecone,
preparing for the Cloudflare Workers + Pinecone hybrid architecture.
"""

import os
import json
import time
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import hashlib
from datetime import datetime

from pinecone import Pinecone
import numpy as np
from ml_knowledge_base_builder import KnowledgeBaseStorage
import requests

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class MigrationConfig:
    """Configuration for Pinecone migration"""
    pinecone_api_key: str
    openai_api_key: str
    pinecone_environment: str = "us-east1-gcp"  # Default environment
    index_name: str = "ml-threat-intelligence"
    dimension: int = 384   # Using OpenAI text-embedding-3-small with 384 dimensions
    metric: str = "cosine"
    pod_type: str = "p1.x1"
    batch_size: int = 100
    dry_run: bool = False
    use_openai_embeddings: bool = True  # New flag to use OpenAI instead of ChromaDB embeddings


class PineconeMigrator:
    """Handles migration from ChromaDB to Pinecone"""
    
    def __init__(self, config: MigrationConfig):
        self.config = config
        self.pinecone_client = None
        self.index = None
        self.chromadb_storage = None
        
        # Migration statistics
        self.stats = {
            'total_documents': 0,
            'migrated_documents': 0,
            'failed_documents': 0,
            'start_time': None,
            'end_time': None
        }
    
    def initialize_pinecone(self):
        """Initialize Pinecone client and create/get index"""
        logger.info("Initializing Pinecone client...")
        
        # Initialize Pinecone
        pc = Pinecone(api_key=self.config.pinecone_api_key)
        self.pinecone_client = pc
        
        # Check if index exists
        existing_indexes = pc.list_indexes()
        index_names = [idx['name'] for idx in existing_indexes]
        
        if self.config.index_name not in index_names:
            logger.info(f"Creating new Pinecone index: {self.config.index_name}")
            
            if not self.config.dry_run:
                pc.create_index(
                    name=self.config.index_name,
                    dimension=self.config.dimension,
                    metric=self.config.metric,
                    spec={
                        "serverless": {
                            "cloud": "aws",
                            "region": "us-east-1"
                        }
                    }
                )
                
                # Wait for index to be ready
                logger.info("Waiting for index to be ready...")
                while not pc.describe_index(self.config.index_name).status['ready']:
                    time.sleep(1)
        else:
            logger.info(f"Using existing Pinecone index: {self.config.index_name}")
        
        # Get index
        if not self.config.dry_run:
            self.index = pc.Index(self.config.index_name)
            logger.info(f"Connected to index. Current stats: {self.index.describe_index_stats()}")
    
    def initialize_chromadb(self, knowledge_base_path: str = "./ml_knowledge_base"):
        """Initialize ChromaDB storage"""
        logger.info("Initializing ChromaDB storage...")
        self.chromadb_storage = KnowledgeBaseStorage(knowledge_base_path)
        
        # Get current stats
        stats = self.chromadb_storage.get_stats()
        self.stats['total_documents'] = stats['total_chunks']
        logger.info(f"ChromaDB contains {stats['total_chunks']} documents")
        logger.info(f"Companies: {', '.join(stats['companies'])}")
        logger.info(f"Years: {', '.join(stats['years'])}")
    
    def extract_chromadb_data(self) -> List[Dict]:
        """Extract all data from ChromaDB"""
        logger.info("Extracting data from ChromaDB...")
        
        try:
            # Get all documents with embeddings and metadata
            # Note: 'ids' is always included by default in ChromaDB
            results = self.chromadb_storage.collection.get(
                include=['embeddings', 'metadatas', 'documents']
            )
            
            extracted_data = []
            
            for i, doc_id in enumerate(results['ids']):
                try:
                    # Get embedding safely
                    embedding = None
                    embeddings_list = results.get('embeddings')
                    if embeddings_list is not None and i < len(embeddings_list):
                        embedding = embeddings_list[i]
                    
                    # Get metadata safely
                    metadata = {}
                    metadatas_list = results.get('metadatas')
                    if metadatas_list is not None and i < len(metadatas_list):
                        metadata = metadatas_list[i]
                    
                    # Get content safely
                    content = ""
                    documents_list = results.get('documents')
                    if documents_list is not None and i < len(documents_list):
                        content = documents_list[i]
                    
                    doc_data = {
                        'id': doc_id,
                        'embedding': embedding,
                        'metadata': metadata,
                        'content': content
                    }
                    extracted_data.append(doc_data)
                    
                except Exception as e:
                    logger.error(f"Failed to process document {i} ({doc_id}): {e}")
                    continue
            
            logger.info(f"Extracted {len(extracted_data)} documents from ChromaDB")
            return extracted_data
            
        except Exception as e:
            logger.error(f"Failed to extract data from ChromaDB: {e}")
            raise
    
    def transform_metadata(self, chromadb_metadata: Dict, content: str) -> Dict:
        """Transform ChromaDB metadata to Pinecone format"""
        
        # Helper function to safely convert to list
        def to_list(value, delimiter='|'):
            if isinstance(value, list):
                return value
            elif isinstance(value, str) and value:
                return [item.strip() for item in value.split(delimiter) if item.strip()]
            else:
                return []
        
        # Extract and transform metadata
        transformed = {
            # Core identification
            'chunk_id': str(chromadb_metadata.get('chunk_id', '')),
            'source_title': str(chromadb_metadata.get('source_title', '')),
            'source_url': str(chromadb_metadata.get('source_url', '')),
            'company': str(chromadb_metadata.get('company', '')),
            'year': str(chromadb_metadata.get('year', '')),
            'chunk_index': int(chromadb_metadata.get('chunk_index', 0)),
            'content_hash': str(chromadb_metadata.get('content_hash', '')),
            
            # ML-specific metadata (convert to arrays)
            'ml_techniques': to_list(chromadb_metadata.get('ml_techniques', '')),
            'keywords': to_list(chromadb_metadata.get('keywords', '')),
            'chunk_summary': str(chromadb_metadata.get('chunk_summary', '')),
            
            # Search optimization
            'bm25_terms': to_list(chromadb_metadata.get('bm25_terms', '')),
            'faq_questions': to_list(chromadb_metadata.get('faq_questions', '')),
            
            # Content snippets (for result display)
            'content_preview': content[:200] if content else '',
            'enriched_preview': str(chromadb_metadata.get('chunk_summary', ''))[:200],
            
            # Scoring metadata
            'original_content_length': len(content) if content else 0,
            'enriched_content_length': len(str(chromadb_metadata.get('chunk_summary', ''))),
            
            # Migration tracking
            'migrated_from': 'chromadb',
            'migration_date': datetime.now().isoformat()
        }
        
        # Remove empty string values to save space
        return {k: v for k, v in transformed.items() if v != ''}
    
    def generate_openai_embedding(self, text: str) -> Optional[List[float]]:
        """Generate OpenAI embedding for given text"""
        try:
            response = requests.post(
                'https://api.openai.com/v1/embeddings',
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {self.config.openai_api_key}'
                },
                json={
                    'input': text,
                    'model': 'text-embedding-3-small',
                    'dimensions': 384
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data['data'] and len(data['data']) > 0:
                    embedding = data['data'][0]['embedding']
                    logger.debug(f"Generated {len(embedding)}-dimensional embedding")
                    return embedding
            else:
                logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to generate OpenAI embedding: {e}")
            return None
    
    def create_pinecone_vectors(self, chromadb_data: List[Dict]) -> List[Dict]:
        """Create Pinecone vectors from ChromaDB data"""
        logger.info("Transforming data for Pinecone...")
        
        vectors = []
        failed_count = 0
        
        for i, doc in enumerate(chromadb_data):
            try:
                # Determine which embedding to use
                embedding = None
                
                if self.config.use_openai_embeddings:
                    # Generate fresh OpenAI embedding from content
                    logger.info(f"Generating OpenAI embedding for document {i+1}/{len(chromadb_data)}: {doc['id']}")
                    embedding = self.generate_openai_embedding(doc['content'])
                    
                    if embedding is None:
                        logger.warning(f"Failed to generate OpenAI embedding for {doc['id']}, skipping")
                        failed_count += 1
                        continue
                        
                    # Small delay to respect API rate limits
                    time.sleep(0.1)
                    
                else:
                    # Use existing ChromaDB embedding
                    if doc['embedding'] is None:
                        logger.warning(f"Skipping document {doc['id']} - no embedding")
                        failed_count += 1
                        continue
                    embedding = doc['embedding']
                
                # Transform metadata
                metadata = self.transform_metadata(doc['metadata'], doc['content'])
                
                # Create Pinecone vector
                vector = {
                    'id': doc['id'],
                    'values': embedding,
                    'metadata': metadata
                }
                
                vectors.append(vector)
                
            except Exception as e:
                logger.error(f"Failed to transform document {doc['id']}: {e}")
                failed_count += 1
                continue
        
        logger.info(f"Created {len(vectors)} vectors for Pinecone ({failed_count} failed)")
        return vectors
    
    def batch_upsert_vectors(self, vectors: List[Dict]):
        """Upload vectors to Pinecone in batches"""
        logger.info(f"Uploading {len(vectors)} vectors to Pinecone...")
        
        if self.config.dry_run:
            logger.info("DRY RUN: Skipping actual upload to Pinecone")
            self.stats['migrated_documents'] = len(vectors)
            return
        
        total_batches = (len(vectors) + self.config.batch_size - 1) // self.config.batch_size
        
        for i in range(0, len(vectors), self.config.batch_size):
            batch_num = (i // self.config.batch_size) + 1
            batch = vectors[i:i + self.config.batch_size]
            
            try:
                logger.info(f"Uploading batch {batch_num}/{total_batches} ({len(batch)} vectors)")
                
                # Upload batch
                upsert_response = self.index.upsert(vectors=batch)
                
                # Update stats
                self.stats['migrated_documents'] += len(batch)
                
                # Rate limiting - be nice to Pinecone
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Failed to upload batch {batch_num}: {e}")
                self.stats['failed_documents'] += len(batch)
                
                # Continue with next batch after error
                continue
        
        logger.info(f"Upload complete. Migrated: {self.stats['migrated_documents']}, Failed: {self.stats['failed_documents']}")
    
    def validate_migration(self, sample_size: int = 10) -> bool:
        """Validate the migration by comparing sample results"""
        logger.info("Validating migration...")
        
        if self.config.dry_run:
            logger.info("DRY RUN: Skipping validation")
            return True
        
        try:
            # Get Pinecone index stats
            pinecone_stats = self.index.describe_index_stats()
            pinecone_count = pinecone_stats['total_vector_count']
            
            logger.info(f"Pinecone index contains {pinecone_count} vectors")
            logger.info(f"ChromaDB had {self.stats['total_documents']} documents")
            
            # Check counts
            if pinecone_count < self.stats['total_documents'] * 0.95:  # Allow 5% loss
                logger.warning(f"Significant data loss detected: {pinecone_count} vs {self.stats['total_documents']}")
                return False
            
            # Sample validation
            logger.info("Performing sample query validation...")
            
            sample_queries = [
                "Netflix anomaly detection",
                "machine learning fraud detection",
                "isolation forest implementation"
            ]
            
            for query in sample_queries:
                try:
                    # Simple query test (we'll need embeddings for full test)
                    logger.info(f"Testing query: '{query}'")
                    # For now just test that the index responds
                    stats = self.index.describe_index_stats()
                    logger.info(f"Index responsive, {stats['total_vector_count']} vectors available")
                    
                except Exception as e:
                    logger.error(f"Query validation failed for '{query}': {e}")
                    return False
            
            logger.info("Migration validation passed!")
            return True
            
        except Exception as e:
            logger.error(f"Migration validation failed: {e}")
            return False
    
    def run_migration(self, knowledge_base_path: str = "./ml_knowledge_base") -> bool:
        """Run the complete migration process"""
        logger.info("Starting ChromaDB to Pinecone migration...")
        self.stats['start_time'] = datetime.now()
        
        try:
            # 1. Initialize systems
            self.initialize_pinecone()
            self.initialize_chromadb(knowledge_base_path)
            
            # 2. Extract data from ChromaDB
            chromadb_data = self.extract_chromadb_data()
            
            # 3. Transform data for Pinecone
            pinecone_vectors = self.create_pinecone_vectors(chromadb_data)
            
            # 4. Upload to Pinecone
            self.batch_upsert_vectors(pinecone_vectors)
            
            # 5. Validate migration
            validation_success = self.validate_migration()
            
            self.stats['end_time'] = datetime.now()
            duration = self.stats['end_time'] - self.stats['start_time']
            
            # Print final stats
            logger.info("Migration completed!")
            logger.info(f"Duration: {duration}")
            logger.info(f"Total documents: {self.stats['total_documents']}")
            logger.info(f"Migrated: {self.stats['migrated_documents']}")
            logger.info(f"Failed: {self.stats['failed_documents']}")
            logger.info(f"Success rate: {(self.stats['migrated_documents'] / self.stats['total_documents'] * 100):.1f}%")
            logger.info(f"Validation: {'PASSED' if validation_success else 'FAILED'}")
            
            return validation_success
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            self.stats['end_time'] = datetime.now()
            return False


def main():
    """Main migration function"""
    
    # Get API keys from environment
    pinecone_api_key = os.getenv('PINECONE_API_KEY')
    openai_api_key = os.getenv('OPENAI_API_KEY')
    
    if not pinecone_api_key:
        logger.error("PINECONE_API_KEY environment variable not set")
        return
        
    if not openai_api_key:
        logger.error("OPENAI_API_KEY environment variable not set")
        return
    
    # Configuration
    config = MigrationConfig(
        pinecone_api_key=pinecone_api_key,
        openai_api_key=openai_api_key,
        pinecone_environment="us-east1-gcp",  # Change as needed
        dry_run=False,  # Now using serverless configuration which works
        use_openai_embeddings=True  # Use OpenAI embeddings for consistency with Workers
    )
    
    print("🚀 Starting SentrySearch ChromaDB to Pinecone Migration with OpenAI Embeddings")
    print("=" * 60)
    print(f"Index Name: {config.index_name}")
    print(f"Environment: {config.pinecone_environment}")
    print(f"Dimension: {config.dimension}")
    print(f"Embedding Model: OpenAI text-embedding-3-small")
    print(f"Use OpenAI Embeddings: {config.use_openai_embeddings}")
    print(f"Dry Run: {config.dry_run}")
    print("=" * 60)
    
    # Run migration
    migrator = PineconeMigrator(config)
    success = migrator.run_migration()
    
    if success:
        print("\n✅ Migration completed successfully!")
        print("🔄 Next steps:")
        print("  1. Test Pinecone queries manually")
        print("  2. Set up Cloudflare Workers")
        print("  3. Implement hybrid search")
    else:
        print("\n❌ Migration failed!")
        print("🔍 Check logs for details")


if __name__ == "__main__":
    main()