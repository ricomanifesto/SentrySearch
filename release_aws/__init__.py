"""AWS SDK adapters for the release controller's ports.

The core ``release`` package stays SDK-free; this package translates each port
call into a fixed, bounded set of SDK requests (one, or the complete pages and
descriptions an enumeration needs). Every adapter takes an injected client
and never creates a session, resolves credentials, reads dotenv or chooses an
endpoint. A caller builds that client with explicit credentials and region,
SDK retries disabled (the controller owns retries) and bounded timeouts; the
adapters refuse any other client.

Nothing here has been exercised against an AWS account. Tests drive these
adapters with stubbed SDK responses, injected clients and network denial.
"""
