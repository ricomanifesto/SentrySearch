"""
Debug ChromaDB structure to understand the data format
"""

from ml_knowledge_base_builder import KnowledgeBaseStorage
import json

def debug_chromadb():
    """Debug ChromaDB to understand data structure"""
    
    print("🔍 Debugging ChromaDB structure...")
    
    # Initialize ChromaDB
    knowledge_base = KnowledgeBaseStorage("./ml_knowledge_base")
    
    # Get basic stats
    stats = knowledge_base.get_stats()
    print(f"📊 Total documents: {stats['total_chunks']}")
    print(f"Companies: {', '.join(stats['companies'])}")
    
    # Try different get methods
    try:
        print("\n🧪 Testing different ChromaDB get methods...")
        
        # Method 1: Get just IDs
        print("Method 1: Get IDs only")
        results_ids = knowledge_base.collection.get()
        print(f"  Keys: {list(results_ids.keys())}")
        print(f"  IDs count: {len(results_ids.get('ids', []))}")
        
        # Method 2: Get with specific includes
        print("\nMethod 2: Get with metadatas only")
        results_meta = knowledge_base.collection.get(include=['metadatas'])
        print(f"  Keys: {list(results_meta.keys())}")
        if 'metadatas' in results_meta:
            print(f"  Metadata count: {len(results_meta['metadatas'])}")
            if results_meta['metadatas']:
                print(f"  First metadata keys: {list(results_meta['metadatas'][0].keys())}")
        
        # Method 3: Get embeddings
        print("\nMethod 3: Get embeddings only")
        results_embed = knowledge_base.collection.get(include=['embeddings'])
        print(f"  Keys: {list(results_embed.keys())}")
        if 'embeddings' in results_embed:
            print(f"  Embeddings count: {len(results_embed['embeddings'])}")
            if results_embed['embeddings']:
                print(f"  First embedding shape: {len(results_embed['embeddings'][0])}")
        
        # Method 4: Get documents
        print("\nMethod 4: Get documents only")
        results_docs = knowledge_base.collection.get(include=['documents'])
        print(f"  Keys: {list(results_docs.keys())}")
        if 'documents' in results_docs:
            print(f"  Documents count: {len(results_docs['documents'])}")
            if results_docs['documents']:
                print(f"  First document length: {len(results_docs['documents'][0])}")
        
        # Method 5: Get first few items only
        print("\nMethod 5: Get first 3 items with all data")
        results_sample = knowledge_base.collection.get(
            limit=3,
            include=['metadatas', 'documents', 'embeddings']
        )
        print(f"  Keys: {list(results_sample.keys())}")
        for key, value in results_sample.items():
            if isinstance(value, list):
                print(f"  {key}: {len(value)} items")
            else:
                print(f"  {key}: {type(value)}")
        
        # Show sample data
        if results_sample.get('ids'):
            print(f"\n📄 Sample data:")
            for i, doc_id in enumerate(results_sample['ids'][:2]):
                print(f"  Document {i+1}:")
                print(f"    ID: {doc_id}")
                if results_sample.get('metadatas') and i < len(results_sample['metadatas']):
                    metadata = results_sample['metadatas'][i]
                    print(f"    Metadata keys: {list(metadata.keys())}")
                    print(f"    Company: {metadata.get('company', 'N/A')}")
                    print(f"    Source: {metadata.get('source_title', 'N/A')}")
                if results_sample.get('embeddings') and i < len(results_sample['embeddings']):
                    embedding = results_sample['embeddings'][i]
                    print(f"    Embedding: {type(embedding)} with {len(embedding)} dimensions")
                print()
        
    except Exception as e:
        print(f"❌ Error during debugging: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    debug_chromadb()