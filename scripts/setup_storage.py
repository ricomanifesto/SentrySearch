#!/usr/bin/env python3
"""
Setup script for SentrySearch cloud storage
Creates database tables and S3 bucket
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def setup_database():
    """Create database tables"""
    print("🔧 Setting up database...")
    
    try:
        from src.storage import create_tables, test_connection
        
        # Test connection first
        if test_connection():
            print("✅ Database connection successful")
        else:
            print("❌ Database connection failed")
            return False
        
        # Create tables
        create_tables()
        print("✅ Database tables created successfully")
        return True
        
    except Exception as e:
        print(f"❌ Database setup failed: {e}")
        return False

def setup_s3():
    """Create S3 bucket"""
    print("🪣 Setting up S3 storage...")
    
    try:
        from src.storage import s3_manager
        
        # Create bucket if it doesn't exist
        s3_manager.create_bucket_if_not_exists()
        print("✅ S3 bucket setup successful")
        return True
        
    except Exception as e:
        print(f"❌ S3 setup failed: {e}")
        return False

def verify_setup():
    """Verify the setup is working"""
    print("🔍 Verifying setup...")
    
    try:
        from src.storage import report_service
        
        # Test basic functionality
        stats = report_service.get_report_stats()
        print(f"✅ Storage verification successful: {stats['total_reports']} reports found")
        return True
        
    except Exception as e:
        print(f"❌ Storage verification failed: {e}")
        return False

def main():
    """Main setup function"""
    print("🚀 SentrySearch Cloud Storage Setup")
    print("=" * 50)
    
    # Check required environment variables
    required_vars = [
        'DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD',
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_S3_BUCKET'
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        print("Please check your .env file and ensure all required variables are set.")
        sys.exit(1)
    
    # Setup components
    success = True
    
    success &= setup_database()
    success &= setup_s3()
    success &= verify_setup()
    
    if success:
        print("\n✅ Setup completed successfully!")
        print("🎉 SentrySearch is ready to store reports in the cloud!")
        print("\nNext steps:")
        print("1. Start the application: python run_app.py")
        print("2. Generate a report to test storage")
        print("3. Check the Report Library tab to see stored reports")
    else:
        print("\n❌ Setup failed. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()