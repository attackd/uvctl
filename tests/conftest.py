"""Shared pytest configuration.

Safety guard: tests marked ``system`` mutate the host (create users, write to
``/opt`` and ``/etc``, touch sudoers). They are deselected by default via the
``-m 'not system'`` addopt in pyproject.toml. This hook adds a second, louder
belt-and-suspenders check: even if someone selects them explicitly, refuse to
run them unless UVCTL_ALLOW_SYSTEM_TESTS=1 is set in the environment — which
the container/CI sets and a dev host does not.
"""

import os

import pytest


def pytest_collection_modifyitems(config, items):
    """Skip system tests unless explicitly enabled for a disposable host."""
    if os.environ.get("UVCTL_ALLOW_SYSTEM_TESTS") == "1":
        return
    skip = pytest.mark.skip(
        reason="system test: set UVCTL_ALLOW_SYSTEM_TESTS=1 (container/CI only)"
    )
    for item in items:
        if "system" in item.keywords:
            item.add_marker(skip)
