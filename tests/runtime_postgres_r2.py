"""Explicit integration suite: the PostgreSQL consistency cases over the R2 backend.

Re-collects every case in ``tests/runtime_postgres.py`` with the ``reports``
fixture replaced, so publication, fencing, evaluation and deletion run against
``R2ArtifactStore`` and the offline R2 model instead of the S3 stub. Run it with
``dev/check_runtime_consistency.py``. The deadline-evaluator case builds its
own S3 stub inside a spawned worker and therefore still exercises S3.
"""

from collections.abc import Iterator, Mapping
import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from release_cloudflare.r2_client import R2Target
from src.storage.database import DatabaseManager
from src.storage.models import Base
from src.storage.r2_artifacts import R2ArtifactStore, R2Credentials, build_client
from src.storage.report_service import ReportStorageService
from tests.r2_fakes import ACCOUNT_ID, R2Backend
from tests.runtime_postgres import *  # noqa: F401,F403

ARTIFACTS = R2Target(account_id=ACCOUNT_ID, bucket="sentry-test-artifacts")
CREDENTIALS = R2Credentials("fixture-artifact-key-id", "fixture-artifact-secret")


class ObjectsView(Mapping):
    """The artifact bucket's objects as ``key -> bytes``, like the S3 stub's dict."""

    def __init__(self, backend: R2Backend) -> None:
        self._backend = backend

    def __getitem__(self, key: str) -> bytes:
        return self._backend.raw(key)

    def __iter__(self) -> Iterator[str]:
        return iter(self._backend.keys())

    def __len__(self) -> int:
        return len(self._backend.keys())


@pytest.fixture
def reports():
    url = make_url(os.environ["SENTRYSEARCH_TEST_DATABASE_URL"])
    name = "sentrysearch_test_" + uuid.uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = create_engine(url.set(database=name))
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.engine = engine
    manager.SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    manager.migrate_schema()
    backend = R2Backend(target=ARTIFACTS)

    def factory():
        client = build_client(ARTIFACTS, CREDENTIALS, ca_bundle=None)
        client.meta.events.register("before-send.s3", backend.handle)
        return client

    service = ReportStorageService(
        artifacts=R2ArtifactStore(ARTIFACTS, CREDENTIALS, client_factory=factory)
    )
    service.db_manager = manager
    try:
        yield service, ObjectsView(backend)
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()
