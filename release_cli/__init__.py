"""Attended operator CLI for the release controller.

The only package that builds AWS SDK sessions and clients for a release. It
composes the SDK-free controller (``release``) with the injected-client adapters
(``release_aws``), an isolated client factory, an explicit session-credentials
file, an operator identity and time preflight, and a monotonic-anchored Clock.
"""
