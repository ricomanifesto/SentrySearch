"""Database configuration, release checks and session ownership."""

import logging
import os
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

from .config import database_url
from . import schema

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(self):
        self.engine: Engine
        self.SessionLocal: sessionmaker[Session]
        self._initialize_connection()

    def _initialize_connection(self):
        self.engine = create_engine(
            database_url(),
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_timeout=5,
            pool_pre_ping=True,
            hide_parameters=True,
            echo=os.getenv("DB_DEBUG", "false").lower() == "true",
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        logger.info("Database engine configured")

    def create_tables(self):
        """Initialize storage through the same versioned release path."""
        self.migrate_schema()

    def migrate_schema(self):
        """Release command only; serving processes must use require_schema."""
        schema.migrate(self.engine)

    def require_schema(self) -> None:
        schema.require_schema(self.engine)

    def check_schema(self) -> bool:
        try:
            self.require_schema()
            return True
        except RuntimeError:
            return False

    def test_connection(self):
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
                return True
        except Exception:
            logger.warning("Database connection unavailable")
            return False

    @contextmanager
    def get_session(self):
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            logger.error("Database session failed")
            raise
        finally:
            session.close()

    def get_session_sync(self) -> Session:
        return self.SessionLocal()


db_manager = DatabaseManager()


def get_db_session():
    return db_manager.get_session_sync()


def create_tables():
    return db_manager.create_tables()


def migrate_schema():
    return db_manager.migrate_schema()


def test_connection():
    return db_manager.test_connection()
