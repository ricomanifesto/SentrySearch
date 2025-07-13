#!/usr/bin/env python3
"""
Database initialization script for SentrySearch
Creates tables and sets up initial data
"""
import os
import sys
from pathlib import Path

# Add src to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

import logging
from dotenv import load_dotenv

from storage.database import db_manager, create_tables, test_connection
from storage.models import Report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Initialize database with tables and test data"""
    # Load environment variables
    env_path = project_root / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        logger.info(f"Loaded environment from {env_path}")
    else:
        logger.warning(f"No .env file found at {env_path}")
    
    # Test database connection
    logger.info("Testing database connection...")
    if not test_connection():
        logger.error("Database connection failed!")
        logger.error("Please ensure PostgreSQL is running and check your .env configuration")
        return False
    
    logger.info("Database connection successful!")
    
    # Create tables
    logger.info("Creating database tables...")
    try:
        create_tables()
        logger.info("Database tables created successfully!")
    except Exception as e:
        logger.error(f"Failed to create tables: {e}")
        return False
    
    # Test table creation by checking if we can query
    try:
        with db_manager.get_session() as session:
            count = session.query(Report).count()
            logger.info(f"Reports table is ready (current count: {count})")
    except Exception as e:
        logger.error(f"Failed to query reports table: {e}")
        return False
    
    logger.info("Database initialization completed successfully!")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)