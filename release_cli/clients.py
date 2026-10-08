"""Isolated AWS SDK clients: the only place release code builds a session or client.

Every client comes from a botocore session whose configuration variables read no
environment variable, configuration or credentials file, customer model
directory or configured endpoint URL, and which has no credential provider chain
at all. Each client gets the operator's explicit session credentials, the
manifest's region, no SDK retries (the controller owns every retry), bounded
connect and read timeouts, an empty proxy map, fixed S3 settings, a fixed user
agent and no Lambda recursion-detection header, so none of the SDK's remaining
direct environment reads (``AWS_S3_*``, ``AWS_EXECUTION_ENV``,
``AWS_LAMBDA_FUNCTION_NAME`` with ``_X_AMZN_TRACE_ID``) changes a request. The SDK
also reads ``SSLKEYLOGFILE`` when it builds a TLS context; the CLI refuses to run
with it set rather than let session secrets be logged. ``release_aws`` adapters
refuse any client that does not match. Constructing a client sends nothing.
"""

from __future__ import annotations

from typing import Any

from botocore import configprovider, handlers
from botocore.config import Config
from botocore.credentials import CredentialResolver
from botocore.loaders import Loader
from botocore.session import Session

from release_aws.errors import require_client
from release_cli.credentials import SessionCredentials

SERVICES = ("ecs", "logs", "s3", "sts")
CONNECT_TIMEOUT_SECONDS = 10
READ_TIMEOUT_SECONDS = 30
_NOWHERE = "/nonexistent/sentry-release-cli"
USER_AGENT = "sentry-release-cli/1"


def client_config() -> Config:
    return Config(
        retries={"total_max_attempts": 1, "mode": "standard"},
        connect_timeout=CONNECT_TIMEOUT_SECONDS,
        read_timeout=READ_TIMEOUT_SECONDS,
        # An explicit empty map: botocore consults HTTP(S)_PROXY only when this is None.
        proxies={},
        # Fixed rather than read from AWS_S3_* variables.
        s3={
            "addressing_style": "virtual",
            "use_arn_region": False,
            "us_east_1_regional_endpoint": "regional",
            "s3_disable_multiregion_access_points": True,
            "use_accelerate_endpoint": False,
            "use_dualstack_endpoint": False,
        },
        # A constant user agent: nothing from AWS_EXECUTION_ENV or the host.
        user_agent=USER_AGENT,
    )


def isolated_session() -> Session:
    """A botocore session with every ambient input removed."""
    variables = {
        name: (config_name, None, default, conversion)
        for name, (config_name, _env, default, conversion) in (
            configprovider.BOTOCORE_DEFAUT_SESSION_VARIABLES.items()
        )
    }
    # No environment variable is ever consulted; these keep files out as well.
    variables["config_file"] = (None, None, _NOWHERE + "/config", None)
    variables["credentials_file"] = (None, None, _NOWHERE + "/credentials", None)
    variables["data_path"] = (None, None, None, None)
    variables["ignore_configured_endpoint_urls"] = (None, None, True, None)
    variables["ca_bundle"] = (None, None, None, None)
    session = Session(session_vars=variables)
    # Only the models shipped with the locked SDK, never ~/.aws/models.
    builtin = Loader.BUILTIN_DATA_PATH
    session.register_component(
        "data_loader", Loader(extra_search_paths=[builtin], include_default_search_paths=False)
    )
    # No provider chain: a client without explicit credentials cannot sign anything.
    session.register_component("credential_provider", CredentialResolver(providers=[]))
    # Never forward a Lambda trace id taken from the environment.
    session.unregister("before-call", handlers.add_recursion_detection_header)
    return session


class AwsClients:
    """One client per port, from explicit session credentials and the manifest region."""

    def __init__(self, credentials: SessionCredentials, region: str) -> None:
        self._credentials = credentials
        self.region = region
        self._session = isolated_session()

    def client(self, service: str) -> Any:
        if service not in SERVICES:
            raise ValueError("no client for that service")
        credentials = self._credentials
        built = self._session.create_client(
            service,
            region_name=self.region,
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            aws_session_token=credentials.session_token,
            # The locked default CA bundle; never AWS_CA_BUNDLE or a configured override.
            verify=True,
            config=client_config(),
        )
        require_client(built, service=service, region=self.region)
        return built
