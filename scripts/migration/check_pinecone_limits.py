"""
Check Pinecone account limits and available configurations
"""

import os
from pinecone import Pinecone

def check_pinecone_account():
    """Check Pinecone account limits and configurations"""
    
    api_key = os.getenv('PINECONE_API_KEY')
    if not api_key:
        print("❌ PINECONE_API_KEY environment variable not set")
        return
    
    try:
        print("🔍 Checking Pinecone account configuration...")
        
        # Initialize client
        pc = Pinecone(api_key=api_key)
        
        # List existing indexes
        print("\n📊 Existing Indexes:")
        indexes = pc.list_indexes()
        if indexes:
            for idx in indexes:
                print(f"  • {idx['name']} - {idx.get('dimension', 'unknown')} dims - {idx.get('metric', 'unknown')} metric")
        else:
            print("  No existing indexes found")
        
        # Try to get account info
        print("\n🏗️ Testing index creation with serverless...")
        
        # Test with serverless configuration (free tier)
        test_config = {
            "name": "test-serverless-config",
            "dimension": 1536,
            "metric": "cosine",
            "spec": {
                "serverless": {
                    "cloud": "aws",
                    "region": "us-east-1"
                }
            }
        }
        
        print(f"  Attempting to create: {test_config['name']}")
        print(f"  Cloud: AWS, Region: us-east-1")
        print(f"  Spec: Serverless (free tier)")
        
        # This is just a test - we'll catch the error to see what's available
        try:
            pc.create_index(**test_config)
            print("  ✅ Serverless index creation successful!")
            
            # Clean up test index
            pc.delete_index(test_config['name'])
            print("  🧹 Test index cleaned up")
            
        except Exception as e:
            print(f"  ❌ Serverless creation failed: {e}")
            
            # Try with different cloud/region combinations
            test_configs = [
                {"cloud": "gcp", "region": "us-central1"},
                {"cloud": "aws", "region": "us-west-2"},
                {"cloud": "azure", "region": "eastus"}
            ]
            
            for config in test_configs:
                try:
                    test_spec = {
                        "name": f"test-{config['cloud']}-{config['region']}",
                        "dimension": 1536,
                        "metric": "cosine", 
                        "spec": {
                            "serverless": config
                        }
                    }
                    print(f"  Testing {config['cloud']} - {config['region']}...")
                    # Just test the spec, don't actually create
                    print(f"    Config: {test_spec}")
                    
                except Exception as test_e:
                    print(f"    ❌ {config}: {test_e}")
        
        print("\n💡 Recommendations:")
        print("1. Use serverless configuration for free tier")
        print("2. Try different cloud providers if one fails")
        print("3. Check Pinecone console for account limits")
        print("4. Consider upgrading account if needed")
        
    except Exception as e:
        print(f"❌ Failed to check Pinecone account: {e}")
        print("\n🔧 Troubleshooting:")
        print("1. Verify API key is correct")
        print("2. Check internet connection")
        print("3. Ensure Pinecone account is active")


if __name__ == "__main__":
    check_pinecone_account()