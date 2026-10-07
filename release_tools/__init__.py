"""Guarded one-shot release jobs for the dedicated Runtime and product databases.

The release-tools image runs exactly one of these fixed programs per ECS task:
``bootstrap``, ``grant``, ``proof`` or ``reconcile``. Every input comes from the
reviewed task definition and its pinned secret versions; nothing is downloaded or
supplied as free-form SQL at runtime. See docs/release-tools.md.
"""
