"""
Check Pinecone index status and contents
"""

import os
import time
from pinecone import Pinecone

def check_index_status():
    """Check Pinecone index status"""
    
    api_key = os.getenv('PINECONE_API_KEY')
    if not api_key:
        print("❌ PINECONE_API_KEY environment variable not set")
        return
    
    try:
        print("🔍 Checking Pinecone index status...")
        
        # Initialize client
        pc = Pinecone(api_key=api_key)
        index_name = "ml-threat-intelligence"
        
        # Get index
        index = pc.Index(index_name)
        
        # Check stats multiple times as indexing can take time
        for i in range(5):
            stats = index.describe_index_stats()
            print(f"\n📊 Index stats (check {i+1}/5):")
            print(f"  Total vectors: {stats['total_vector_count']}")
            print(f"  Dimension: {stats['dimension']}")
            print(f"  Index fullness: {stats['index_fullness']}")
            print(f"  Namespaces: {stats['namespaces']}")
            
            if stats['total_vector_count'] > 0:
                print("✅ Vectors found in index!")
                
                # Try a test query
                print("\n🔍 Testing query...")
                try:
                    test_results = index.query(
                        vector=[0.1] * 384,  # Dummy vector with correct dimensions
                        top_k=3,
                        include_metadata=True
                    )
                    print(f"  Query returned {len(test_results['matches'])} results")
                    if test_results['matches']:
                        first_match = test_results['matches'][0]
                        print(f"  First match ID: {first_match['id']}")
                        print(f"  First match score: {first_match['score']:.4f}")
                        if 'metadata' in first_match:
                            metadata = first_match['metadata']
                            print(f"  Company: {metadata.get('company', 'N/A')}")
                            print(f"  Source: {metadata.get('source_title', 'N/A')}")
                except Exception as e:
                    print(f"  Query failed: {e}")
                
                break
            else:
                print("⏳ No vectors found yet, waiting 10 seconds...")
                time.sleep(10)
        
        if stats['total_vector_count'] == 0:
            print("❌ No vectors found after multiple checks")
        
    except Exception as e:
        print(f"❌ Failed to check index: {e}")


if __name__ == "__main__":
    check_index_status()