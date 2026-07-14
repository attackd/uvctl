"""Unit tests for uvctl.escalate — planning, env, uv-path check (tier 1).

The actual privilege drops (setuid/sudo) are tier-2; here we verify the pure
decision logic and command construction with an injected fake runner.
"""

import os

import pytest

from uvctl import escalate
from uvctl.escalate import (
    DIRECT,
    ROOT_DROP,
    SUDO,
    EscalationError,
)


class FakeRunner:
    """Captures the arguments a subprocess runner would have been called with."""

    def __init__(self):
        self.argv = None
        self.kwargs = None

    def __call__(self, argv, **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        return "ran"


# --- build_subprocess_env ----------------------------------------------------


def test_build_subprocess_env_is_explicit_and_complete():
    env = escalate.build_subprocess_env(
        tool_dir="/t", bin_dir="/b", python_install_dir="/p", cache_dir="/c"
    )
    assert env == {
        "UV_TOOL_DIR": "/t",
        "UV_TOOL_BIN_DIR": "/b",
        "UV_PYTHON_INSTALL_DIR": "/p",
        "UV_CACHE_DIR": "/c",
        "PATH": escalate.MINIMAL_PATH,
    }
    # nothing inherited from the caller
    assert "HOME" not in env


# --- plan_privilege / child_runs_as ------------------------------------------


@pytest.mark.parametrize(
    ("service_user", "current_user", "euid", "expected"),
    [
        ("uvctl", "uvctl", 1000, DIRECT),  # already the service user
        ("uvctl", "root", 0, ROOT_DROP),  # root drops directly
        ("uvctl", "alice", 1001, SUDO),  # unprivileged admin uses sudo
        ("", "root", 0, DIRECT),  # no service user configured
        (None, "alice", 1001, DIRECT),
    ],
)
def test_plan_privilege(service_user, current_user, euid, expected):
    assert (
        escalate.plan_privilege(service_user, current_user=current_user, euid=euid)
        == expected
    )


@pytest.mark.parametrize("plan", [SUDO, ROOT_DROP])
def test_child_runs_as_service_user_never_root(plan):
    # Core invariant instrumentation: the install child is the service user.
    assert escalate.child_runs_as(plan, "uvctl", "root") == "uvctl"


def test_child_runs_as_direct_is_current_user():
    assert escalate.child_runs_as(DIRECT, "uvctl", "uvctl") == "uvctl"


# --- check_uv_path -----------------------------------------------------------


def test_check_uv_path_rejects_unrecorded():
    with pytest.raises(EscalationError, match="run `uvctl setup`"):
        escalate.check_uv_path(None)


def test_check_uv_path_rejects_missing(tmp_path):
    with pytest.raises(EscalationError, match="no longer exists"):
        escalate.check_uv_path(str(tmp_path / "nope"))


def test_check_uv_path_rejects_group_or_world_writable(tmp_path):
    uv = tmp_path / "uv"
    uv.write_text("#!/bin/sh\n")
    uv.chmod(0o775)  # group-writable
    with pytest.raises(EscalationError, match="writable"):
        escalate.check_uv_path(str(uv))


def test_check_uv_path_rejects_nonroot_owned_and_writable(tmp_path):
    uv = tmp_path / "uv"
    uv.write_text("#!/bin/sh\n")
    uv.chmod(0o755)  # owner-writable, owned by the (non-root) test user
    # default allowed_uids is root only, so our uid is not permitted to own it
    with pytest.raises(EscalationError):
        escalate.check_uv_path(str(uv))


def test_check_uv_path_accepts_when_owner_is_allowed(tmp_path):
    uv = tmp_path / "uv"
    uv.write_text("#!/bin/sh\n")
    uv.chmod(0o755)
    # widen allowed owners to include the current uid
    assert escalate.check_uv_path(str(uv), allowed_uids=(0, os.getuid())) == str(uv)


def test_check_uv_path_accepts_readonly_nonroot(tmp_path):
    uv = tmp_path / "uv"
    uv.write_text("#!/bin/sh\n")
    uv.chmod(0o555)  # no write bit anywhere
    assert escalate.check_uv_path(str(uv)) == str(uv)


# --- run_as_service_user: argv construction per plan -------------------------


def test_run_as_service_user_sudo_builds_env_prefixed_argv():
    fake = FakeRunner()
    escalate.run_as_service_user(
        ["/opt/uv/bin/uv", "tool", "list"],
        service_user="uvctl",
        env={"UV_TOOL_DIR": "/opt/uv/tools"},
        current_user="alice",
        euid=1001,
        runner=fake,
    )
    assert fake.argv[:4] == ["sudo", "-u", "uvctl", "env"]
    assert "UV_TOOL_DIR=/opt/uv/tools" in fake.argv
    assert fake.argv[-3:] == ["/opt/uv/bin/uv", "tool", "list"]


def test_run_as_service_user_direct_passes_argv_unwrapped():
    fake = FakeRunner()
    escalate.run_as_service_user(
        ["/opt/uv/bin/uv", "tool", "list"],
        service_user="uvctl",
        current_user="uvctl",  # already the service user
        euid=1000,
        runner=fake,
    )
    assert fake.argv == ["/opt/uv/bin/uv", "tool", "list"]
    assert fake.kwargs["env"]["PATH"] == escalate.MINIMAL_PATH


def test_run_as_service_user_root_drop_has_preexec():
    fake = FakeRunner()
    escalate.run_as_service_user(
        ["/opt/uv/bin/uv", "tool", "list"],
        service_user="uvctl",
        current_user="root",
        euid=0,
        runner=fake,
    )
    assert fake.argv == ["/opt/uv/bin/uv", "tool", "list"]
    assert callable(fake.kwargs["preexec_fn"])  # drops to the service user


# --- run_uv ------------------------------------------------------------------


def test_run_uv_checks_path_then_runs(tmp_path):
    uv = tmp_path / "uv"
    uv.write_text("#!/bin/sh\n")
    uv.chmod(0o555)
    fake = FakeRunner()
    escalate.run_uv(
        ["tool", "install", "ruff"],
        uv_path=str(uv),
        tool_dir="/opt/uv/tools",
        bin_dir="/opt/uv/bin",
        python_install_dir="/opt/uv/python",
        cache_dir="/opt/uv/cache",
        service_user="uvctl",
        current_user="alice",
        euid=1001,
        runner=fake,
    )
    assert "UV_TOOL_DIR=/opt/uv/tools" in fake.argv
    assert "UV_PYTHON_INSTALL_DIR=/opt/uv/python" in fake.argv
    assert fake.argv[-4:] == [str(uv), "tool", "install", "ruff"]


def test_run_uv_refuses_unsafe_uv(tmp_path):
    uv = tmp_path / "uv"
    uv.write_text("#!/bin/sh\n")
    uv.chmod(0o777)  # world-writable
    with pytest.raises(EscalationError):
        escalate.run_uv(
            ["tool", "list"],
            uv_path=str(uv),
            tool_dir="/t",
            bin_dir="/b",
            python_install_dir="/p",
            cache_dir="/c",
            service_user="uvctl",
            current_user="alice",
            euid=1001,
            runner=FakeRunner(),
        )


# --- run_as_root -------------------------------------------------------------


def test_run_as_root_direct_when_root():
    fake = FakeRunner()
    escalate.run_as_root(["ln", "-s", "a", "b"], euid=0, runner=fake)
    assert fake.argv == ["ln", "-s", "a", "b"]


def test_run_as_root_prefixes_sudo_when_not_root():
    fake = FakeRunner()
    escalate.run_as_root(["ln", "-s", "a", "b"], euid=1001, runner=fake)
    assert fake.argv == ["sudo", "ln", "-s", "a", "b"]


# --- drop_privileges_permanently (guards; happy path is tier-2) --------------


def test_drop_refuses_when_not_root():
    # The host test process is not root; the drop must refuse rather than
    # partially mutate credentials.
    if os.geteuid() == 0:
        pytest.skip("running as root; guard exercised in tier-2")
    with pytest.raises(EscalationError, match="as root"):
        escalate.drop_privileges_permanently("nobody")


def test_drop_refuses_uid_zero_target(monkeypatch):
    # Even if we were root, dropping "to" a uid-0 account is refused. Simulate
    # root so we reach the uid-0 guard without touching real credentials.
    monkeypatch.setattr(escalate.os, "geteuid", lambda: 0)
    with pytest.raises(EscalationError, match="uid-0"):
        escalate.drop_privileges_permanently("root")
