"""
Database configuration and connection management for SentrySearch
"""
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from contextlib import contextmanager
import logging

from .models import Base

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize database connection from environment variables"""
        # Database connection parameters
        db_host = os.getenv('DB_HOST', 'localhost')
        db_port = os.getenv('DB_PORT', '5432')
        db_name = os.getenv('DB_NAME', 'sentrysearch')
        db_user = os.getenv('DB_USER', 'postgres')
        db_password = os.getenv('DB_PASSWORD', '')
        
        # Construct connection URL
        if db_password:
            db_url = f"postgresql+psycopg://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        else:
            db_url = f"postgresql+psycopg://{db_user}@{db_host}:{db_port}/{db_name}"
        
        # Create engine with connection pooling
        self.engine = create_engine(
            db_url,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            echo=os.getenv('DB_DEBUG', 'false').lower() == 'true'
        )
        
        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        
        logger.info(f"Database initialized: {db_host}:{db_port}/{db_name}")
    
    def create_tables(self):
        """Create all database tables"""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating tables: {e}")
            raise
    
    def test_connection(self):
        """Test database connection"""
        try:
            with self.engine.connect() as connection:
                result = connection.execute(text("SELECT 1"))
                logger.info("Database connection test successful")
                return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    @contextmanager
    def get_session(self):
        """Get database session with automatic cleanup"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def get_session_sync(self) -> Session:
        """Get synchronous database session"""
        return self.SessionLocal()

# Global database manager instance
db_manager = DatabaseManager()

# Convenience functions
def get_db_session():
    """Get database session (for dependency injection)"""
    return db_manager.get_session_sync()

def create_tables():
    """Create database tables"""
    return db_manager.create_tables()

def test_connection():
    """Test database connection"""
    return db_manager.test_connection()