"""Explicit session files and the only clients and environments a kit builds from them.

A step that touches the account reads one session file the operator names on the
command line, under exactly the release CLI's rules (owner-only 0400 file, no
symlink, outside any repository, temporary key with a token, session name equal
to the plan's operator, expiring after the step's margin). Nothing is read from
the environment, a profile, a configuration file or instance metadata.

SDK clients come from the release CLI's isolated botocore session. Terraform runs
as a child process whose environment is built here from nothing: the session's
three values, the region, and switches that turn every other credential source
off. The rehearsal points the same clients at loopback stand-ins; any other
endpoint is refused.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from botocore.config import Config

from release_cli.clients import client_config, isolated_session
from release_cli.credentials import SessionCredentials, load_session_credentials

KIT_SERVICES = ("cloudwatch", "ecr", "ecs", "iam", "logs", "rds", "s3", "secretsmanager", "sts")
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
NOWHERE = "/nonexistent/sentry-release-kit"
# A step must finish well inside the session: Terraform applies and image pushes
# can take a while, so a session that ends within this margin is refused.
STEP_MARGIN = timedelta(hours=1)


class SessionRefused(Exception):
    """No usable explicit session for this step."""


@dataclass(frozen=True)
class Session:
    credentials: SessionCredentials
    path: Path
    endpoint: str | None = None

    def describe(self) -> dict[str, str]:
        """What a receipt may say about the session: never a key, secret or token."""
        return {"session_file": str(self.path), "session_name": self.credentials.session_name,
                "expires_at": self.credentials.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")}  # fmt: skip

    @property
    def secrets(self) -> tuple[str, ...]:
        """Values a receipt must never contain."""
        credentials = self.credentials
        return (credentials.access_key_id, credentials.secret_access_key,
                credentials.session_token)  # fmt: skip


def load(path: str | None, *, operator: str, now: datetime | None = None,
         margin: timedelta = STEP_MARGIN, endpoint: str | None = None) -> Session:  # fmt: skip
    if not path:
        raise SessionRefused("this step needs an explicit --session file; nothing ambient is used")
    if endpoint is not None:
        parsed = urlparse(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in LOOPBACK:
            raise SessionRefused("a stand-in endpoint must be plain HTTP on loopback")
    moment = now or datetime.now(UTC)
    try:
        credentials = load_session_credentials(
            Path(path), operator=operator, now=moment, required_until=moment + margin
        )
    except Exception as error:  # the CLI's refusal reasons never contain a value
        reason = getattr(error, "reason", type(error).__name__)
        raise SessionRefused(f"session file refused: {reason}") from None
    return Session(credentials, Path(path), endpoint)


def client(session: Session, service: str, region: str) -> Any:
    if service not in KIT_SERVICES:
        raise ValueError(f"no kit client for {service}")
    config = client_config()
    if session.endpoint is not None and service == "s3":
        s3 = getattr(config, "s3", None) or {}
        config = config.merge(Config(s3={**s3, "addressing_style": "path"}))
    credentials = session.credentials
    return isolated_session().create_client(
        service, region_name=region, endpoint_url=session.endpoint,
        aws_access_key_id=credentials.access_key_id,
        aws_secret_access_key=credentials.secret_access_key,
        aws_session_token=credentials.session_token, verify=True, config=config,
    )  # fmt: skip


def terraform_environment(session: Session | None, *, region: str, home: Path,
                          data_dir: Path) -> dict[str, str]:  # fmt: skip
    """Terraform's whole environment: nothing inherited, no other credential source."""
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "LANG": "C",
        "TF_IN_AUTOMATION": "1", "CHECKPOINT_DISABLE": "1", "TF_INPUT": "0",
        "TF_DATA_DIR": str(data_dir), "TF_CLI_CONFIG_FILE": NOWHERE + "/terraformrc",
        "AWS_REGION": region, "AWS_CONFIG_FILE": NOWHERE + "/config",
        "AWS_SHARED_CREDENTIALS_FILE": NOWHERE + "/credentials",
        "AWS_EC2_METADATA_DISABLED": "true", "AWS_SDK_LOAD_CONFIG": "0",
    }  # fmt: skip
    if session is not None:
        credentials = session.credentials
        environment |= {"AWS_ACCESS_KEY_ID": credentials.access_key_id,
                        "AWS_SECRET_ACCESS_KEY": credentials.secret_access_key,
                        "AWS_SESSION_TOKEN": credentials.session_token}  # fmt: skip
    return environment
