#!/usr/bin/env python3
"""
SentrySearch API Server Launcher

Launch the FastAPI server for frontend integration.
Optimized for development and Vercel deployment.
"""

import sys
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run the API
if __name__ == "__main__":
    import uvicorn
    from api.main import app
    
    print("🚀 Starting SentrySearch API Server")
    print("📖 API Documentation: http://localhost:8001/api/docs")
    print("🔍 Health Check: http://localhost:8001/api/health")
    
    # Get port from environment (Railway sets this automatically)
    port = int(os.getenv("PORT", 8001))
    
    print(f"🚀 Starting on port {port}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        reload=False,  # Disable reload in production
        log_level="info"
    )