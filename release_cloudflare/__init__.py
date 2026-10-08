"""Cloudflare adapters for the attended release controller.

Nothing in this package creates SDK sessions, resolves credentials, reads the
process environment or loads dotenv files. Callers inject configured clients;
the adapters validate them and fail closed on anything they cannot prove.
"""
