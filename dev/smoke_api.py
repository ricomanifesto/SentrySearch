#!/usr/bin/env python3
"""Local API smoke checks that do not require production credentials."""

from __future__ import annotations

import os
import sys
import asyncio
from pathlib import Path

import httpx


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"


def configure_local_environment() -> None:
    """Set harmless defaults before importing modules with env-driven singletons."""
    os.environ.setdefault("DB_HOST", "localhost")
    os.environ.setdefault("DB_PORT", "5432")
    os.environ.setdefault("DB_NAME", "sentrysearch")
    os.environ.setdefault("DB_USER", "postgres")
    os.environ.setdefault("DB_DEBUG", "false")
    os.environ.setdefault("AWS_REGION", "us-east-1")
    os.environ.setdefault("AWS_S3_BUCKET", "sentrysearch-local-dev")


def assert_status(response, expected: set[int], label: str) -> None:
    if response.status_code not in expected:
        raise AssertionError(
            f"{label}: expected status in {sorted(expected)}, "
            f"got {response.status_code}: {response.text}"
        )


async def run_checks() -> int:
    configure_local_environment()
    sys.path.insert(0, str(REPO_ROOT))
    sys.path.insert(0, str(SRC_ROOT))

    from api import main as api_main  # pylint: disable=import-outside-toplevel

    api_main.report_service.test_connection = lambda: False
    app = api_main.app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://sentrysearch.local",
    ) as client:
        root_response = await client.get("/")
        assert_status(root_response, {200}, "root endpoint")
        root_payload = root_response.json()
        assert root_payload["status"] == "operational"

        openapi_response = await client.get("/api/docs")
        assert_status(openapi_response, {200}, "API docs")

        health_response = await client.get("/api/health")
        assert_status(health_response, {200}, "health endpoint")
        health_payload = health_response.json()
        assert health_payload["status"] == "degraded"
        assert health_payload["database"] == "disconnected"

        create_response = await client.post("/api/reports", json={"tool_name": "SmokeTest"})
        assert_status(create_response, {401, 403, 503}, "create report auth boundary")

    print("SentrySearch API smoke checks passed")
    print(f"  root: {root_payload['message']} {root_payload['version']}")
    print(f"  health: {health_payload['status']} / {health_payload['database']}")
    print(f"  create report without auth: HTTP {create_response.status_code}")
    return 0


def main() -> int:
    return asyncio.run(run_checks())


if __name__ == "__main__":
    raise SystemExit(main())
