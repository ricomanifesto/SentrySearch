"""
Delete existing Pinecone index to recreate with correct dimensions
"""

import os
from pinecone import Pinecone

def delete_pinecone_index():
    """Delete existing index to recreate with correct dimensions"""
    
    api_key = os.getenv('PINECONE_API_KEY')
    if not api_key:
        print("❌ PINECONE_API_KEY environment variable not set")
        return
    
    try:
        print("🗑️ Deleting existing Pinecone index...")
        
        # Initialize client
        pc = Pinecone(api_key=api_key)
        
        # List existing indexes
        indexes = pc.list_indexes()
        index_names = [idx['name'] for idx in indexes]
        
        index_name = "ml-threat-intelligence"
        
        if index_name in index_names:
            print(f"Deleting index: {index_name}")
            pc.delete_index(index_name)
            print("✅ Index deleted successfully")
        else:
            print(f"Index {index_name} not found")
        
    except Exception as e:
        print(f"❌ Failed to delete index: {e}")


if __name__ == "__main__":
    delete_pinecone_index()