"""Tier-2 system-test smoke check.

These tests run ONLY inside the disposable container (or CI), where the host
can be freely mutated. They are marked ``system`` — deselected by default and
additionally gated behind UVCTL_ALLOW_SYSTEM_TESTS=1 (see tests/conftest.py).

This file proves the tier-2 harness wiring end to end: it confirms the test
process has the prerequisites the real system tests will need (root, a
non-root user to prove the core invariant against, and the ``uv`` binary).
Replace/extend as the escalation, setup, and suffix code lands.
"""

import os
import pwd
import shutil

import pytest

pytestmark = pytest.mark.system


def test_running_as_root():
    """setup and the escalation tests need to start from uid 0."""
    assert os.geteuid() == 0, "system tests must run as root inside the container"


def test_unprivileged_user_exists():
    """The core invariant ('a regular user can run the tool') needs one."""
    pwd.getpwnam("tester")


def test_uv_binary_available():
    """uvctl resolves uv to an absolute path; the image must provide it."""
    assert shutil.which("uv") is not None
