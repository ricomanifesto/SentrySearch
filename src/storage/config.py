"""Explicit product persistence settings; parsing performs no network I/O."""

import ipaddress
import os
from pathlib import Path

from sqlalchemy import URL


def is_deployed() -> bool:
    environment = os.getenv("ENVIRONMENT", "development")
    if environment not in {"development", "test", "staging", "production"}:
        raise ValueError("Invalid ENVIRONMENT")
    return environment in {"staging", "production"}


def database_url() -> URL:
    deployed = is_deployed()
    if os.getenv("PGHOSTADDR") or os.getenv("PGSERVICE"):
        raise ValueError("Use explicit DB_* routing; PGHOSTADDR and PGSERVICE are unsupported")
    if deployed and any(
        not os.getenv(key) for key in ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
    ):
        raise ValueError(
            "Deployed storage requires explicit DB_HOST, DB_NAME, DB_USER and DB_PASSWORD"
        )
    host = os.getenv("DB_HOST", "localhost")
    if not host or any(char.isspace() or char in ",@?#" for char in host):
        raise ValueError("DB_HOST must identify one host or local socket directory")
    try:
        local = ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = host == "localhost" or host.startswith("/")
    try:
        port = int(os.getenv("DB_PORT", "5432"))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise ValueError("DB_PORT must be a valid port") from None
    mode = os.getenv("DB_SSLMODE", "disable" if local and not deployed else "verify-full")
    ca = os.getenv("DB_SSLROOTCERT", "")
    if mode not in {"disable", "verify-full"} or (mode == "disable" and (deployed or not local)):
        raise ValueError("Remote and deployed databases require DB_SSLMODE=verify-full")
    if mode == "verify-full":
        if host.startswith("/"):
            raise ValueError("Verified database TLS requires a TCP host")
        if not ca or not Path(ca).is_file():
            raise ValueError("Verified database TLS requires a readable DB_SSLROOTCERT file")
    elif ca:
        raise ValueError("DB_SSLROOTCERT requires DB_SSLMODE=verify-full")
    if deployed and os.getenv("DB_DEBUG", "false").lower() != "false":
        raise ValueError("DB_DEBUG must be false for deployed storage")
    query = {
        "sslmode": mode,
        "gssencmode": "disable",
        "connect_timeout": "5",
        "options": "-c search_path=public -c statement_timeout=10000 -c lock_timeout=3000",
    }
    if ca:
        query["sslrootcert"] = ca
    return URL.create(
        "postgresql+psycopg",
        username=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
        host=host,
        port=port,
        database=os.getenv("DB_NAME", "sentrysearch"),
        query=query,
    )
